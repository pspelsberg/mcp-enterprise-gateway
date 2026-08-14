import os
import stat
from pathlib import Path
import re
from src.core.models import ConceptNotFoundError, ResourceTooLargeError

MAX_RESOURCE_BYTES = 1024 * 1024

class OKFResourceProvider:
    def __init__(self, root: str | Path, max_bytes: int = MAX_RESOURCE_BYTES):
        self.root = Path(root).resolve()
        if max_bytes < 0:
            raise ValueError("max_bytes must be non-negative")
        self.max_bytes = max_bytes
        try:
            self._root_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError as exc:
            raise ValueError("OKF root must be a readable directory") from exc

    def __del__(self):
        fd = getattr(self, "_root_fd", None)
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass

    def read(self, concept_id: str) -> str:
        if not re.fullmatch(r"[a-zA-Z0-9_-]+", concept_id):
            raise ConceptNotFoundError("invalid concept id")
        # Open the final component without following symlinks.  Checking
        # is_symlink() before read_text() is TOCTOU-prone when the resource
        # directory is writable by another process.
        path = self.root / (concept_id + ".md")
        try:
            fd = os.open(concept_id + ".md", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=self._root_fd)
        except (FileNotFoundError, IsADirectoryError, NotADirectoryError, PermissionError, OSError) as exc:
            # ELOOP (symlink) and all filesystem details are intentionally
            # indistinguishable from a missing concept at the protocol edge.
            raise ConceptNotFoundError("concept not found") from exc
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode):
                raise ConceptNotFoundError("concept not found")
            if metadata.st_size > self.max_bytes:
                raise ResourceTooLargeError("resource exceeds size limit")
            chunks = []
            remaining = self.max_bytes
            while remaining:
                chunk = os.read(fd, min(64 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            return b"".join(chunks).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ConceptNotFoundError("concept is not valid UTF-8") from exc
        finally:
            os.close(fd)
