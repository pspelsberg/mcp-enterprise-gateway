from dataclasses import dataclass
import re
import threading
import docker
from docker.errors import DockerException, NotFound
try:
    from requests.exceptions import ReadTimeout
except ImportError:  # pragma: no cover
    ReadTimeout = TimeoutError
from src.core.models import (
    DockerDaemonUnavailableError, SandboxExecutionError, SandboxImageIntegrityError,
    SandboxTimeoutError, UnsupportedLanguageError, SandboxCapacityError,
)

MAX_OUTPUT = 1024 * 1024
MAX_CODE_BYTES = 100 * 1024
TRUNCATION_MARKER = b"\n[output truncated]"
CLEANUP_WAIT_SECONDS = 1
_DIGEST_REF = re.compile(r"^.+@sha256:[0-9a-f]{64}$")


def _decode_with_limit(data: bytes, limit: int) -> tuple[str, bool]:
    text = data.decode(errors="replace")
    encoded = text.encode("utf-8")
    if len(encoded) <= limit:
        return text, False
    # Dropping incomplete trailing code points keeps the encoded result bounded.
    return encoded[:limit].decode("utf-8", errors="ignore"), True


def bounded_output(data: bytes) -> str:
    """Return at most MAX_OUTPUT UTF-8 bytes, including the truncation marker."""
    if len(data) <= MAX_OUTPUT:
        text, truncated = _decode_with_limit(data, MAX_OUTPUT)
        if not truncated:
            return text
        payload_limit = max(0, MAX_OUTPUT - len(TRUNCATION_MARKER))
        text, _ = _decode_with_limit(data, payload_limit)
        return text + TRUNCATION_MARKER.decode()
    payload_limit = max(0, MAX_OUTPUT - len(TRUNCATION_MARKER))
    text, _ = _decode_with_limit(data[:payload_limit], payload_limit)
    return text + TRUNCATION_MARKER.decode()


def _stream_output(container, *, stdout: bool, stderr: bool) -> str:
    payload_limit = MAX_OUTPUT - len(TRUNCATION_MARKER)
    payload = bytearray()
    truncated = False
    stream = None
    try:
        try:
            stream = container.logs(stdout=stdout, stderr=stderr, stream=True, follow=False)
        except TypeError:
            # Only supports older/test-double SDK signatures; still requires streaming.
            stream = container.logs(stdout=stdout, stderr=stderr, stream=True)
        if isinstance(stream, (bytes, bytearray, str)):
            raise SandboxExecutionError("sandbox log stream is not streaming")
        for chunk in stream:
            if isinstance(chunk, tuple):
                chunk = chunk[-1]
            if isinstance(chunk, str):
                chunk = chunk.encode()
            if not isinstance(chunk, (bytes, bytearray)):
                raise SandboxExecutionError("sandbox log stream is invalid")
            if not chunk:
                continue
            remaining = payload_limit - len(payload)
            if remaining <= 0:
                truncated = True
                break
            if len(chunk) > remaining:
                payload.extend(chunk[:remaining])
                truncated = True
                break
            payload.extend(chunk)
        text, decode_truncated = _decode_with_limit(bytes(payload), payload_limit)
        truncated = truncated or decode_truncated
        return text + (TRUNCATION_MARKER.decode() if truncated else "")
    except SandboxExecutionError:
        raise
    except Exception as exc:
        raise SandboxExecutionError("sandbox output could not be read") from exc
    finally:
        close = getattr(stream, "close", None)
        if callable(close):
            try:
                close()
            except Exception:
                pass


def _cleanup_timed_out_container(container) -> None:
    """Best effort termination; cleanup failures never replace the timeout."""
    for action in ("kill", "stop"):
        try:
            method = getattr(container, action, None)
            if callable(method):
                method()
        except Exception:
            pass
    try:
        container.wait(timeout=CLEANUP_WAIT_SECONDS)
    except Exception:
        pass
    try:
        container.remove(force=True)
    except Exception:
        pass


@dataclass
class DockerRunner:
    client: object | None = None
    images: dict | None = None
    expected_image_ids: dict | None = None
    expected_digests: dict | None = None
    require_digests: bool = True
    max_concurrent: int = 4

    def __post_init__(self):
        if not isinstance(self.max_concurrent, int) or self.max_concurrent < 1:
            raise ValueError("max_concurrent must be positive")
        self._capacity = threading.BoundedSemaphore(self.max_concurrent)

        # Tags remain available only for explicitly opted-in local test/development mode.
        self.images = self.images or {"python": "python:3.11-slim@sha256:" + "0" * 64, "javascript": "node:20-alpine@sha256:" + "0" * 64}
        self.expected_image_ids = self.expected_image_ids or {}
        self.expected_digests = self.expected_digests or {}
        if set(self.images) != {"python", "javascript"}:
            raise ValueError("sandbox image policy must define python and javascript")
        if self.require_digests:
            for image in self.images.values():
                if not _DIGEST_REF.fullmatch(image):
                    raise ValueError("sandbox images must be immutable digest references")

    def run(self, code: str, language: str, timeout_seconds: int) -> dict:
        if language not in {"python", "javascript"}:
            raise UnsupportedLanguageError("unsupported language")
        if not isinstance(code, str) or not code or len(code.encode("utf-8")) > MAX_CODE_BYTES:
            raise SandboxExecutionError("sandbox code is invalid or too large")
        if not isinstance(timeout_seconds, int) or isinstance(timeout_seconds, bool) or not 1 <= timeout_seconds <= 30:
            raise SandboxExecutionError("sandbox timeout is invalid")
        images = self.images or {}
        image = images[language]
        try:
            client = self.client or docker.from_env()
            client.ping()
        except DockerException as exc:
            raise DockerDaemonUnavailableError("Docker daemon unavailable") from exc
        command = ["python", "-c", code] if language == "python" else ["node", "-e", code]
        try:
            image_obj = client.images.get(image)
            if self.require_digests:
                configured_digest = image.rsplit("@sha256:", 1)[1]
                expected_digest = self.expected_digests.get(language, configured_digest)
                if expected_digest != configured_digest:
                    raise SandboxImageIntegrityError("sandbox image integrity check failed")
                attrs = getattr(image_obj, "attrs", {}) or {}
                repo_digests = attrs.get("RepoDigests", []) or []
                if not repo_digests or not any(item.endswith("@sha256:" + expected_digest) for item in repo_digests):
                    raise SandboxImageIntegrityError("sandbox image integrity check failed")
            expected_id = self.expected_image_ids.get(language)
            if expected_id:
                attrs = getattr(image_obj, "attrs", {}) or {}
                actual_id = getattr(image_obj, "id", None) or attrs.get("Id")
                if actual_id != expected_id:
                    raise SandboxImageIntegrityError("sandbox image integrity check failed")
        except NotFound as exc:
            raise SandboxExecutionError("sandbox image is not available locally") from exc
        except SandboxImageIntegrityError:
            raise
        except DockerException as exc:
            raise SandboxExecutionError("sandbox image lookup failed") from exc
        if not self._capacity.acquire(blocking=False):
            raise SandboxCapacityError("sandbox capacity exhausted")
        container = None
        timeout_cleaned = False
        try:
            container = client.containers.run(
                image, command, detach=True, network_mode="none", user="1000:1000", read_only=True,
                cap_drop=["ALL"], security_opt=["no-new-privileges:true"],
                tmpfs={"/tmp": "rw,noexec,nosuid,size=64m"}, mem_limit="256m",
                nano_cpus=500_000_000, pids_limit=64,
                # Bound daemon-side retention as well as gateway-side streaming;
                # otherwise Docker can buffer an unbounded completed log first.
                log_config={"type": "local", "config": {"max-size": "3m", "max-file": "1"}},
            )
            try:
                result = container.wait(timeout=timeout_seconds)
            except (ReadTimeout, TimeoutError) as exc:
                _cleanup_timed_out_container(container)
                timeout_cleaned = True
                raise SandboxTimeoutError("sandbox execution timed out") from exc
            stdout = _stream_output(container, stdout=True, stderr=False)
            stderr = _stream_output(container, stdout=False, stderr=True)
            return {"stdout": stdout, "stderr": stderr, "exit_code": int(result.get("StatusCode", 1))}
        except SandboxTimeoutError:
            raise
        except DockerException as exc:
            raise SandboxExecutionError("sandbox execution failed") from exc
        finally:
            if container is not None and not timeout_cleaned:
                try:
                    container.remove(force=True)
                except Exception:
                    pass
            self._capacity.release()
