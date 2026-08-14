from dataclasses import dataclass
import docker
from docker.errors import DockerException, NotFound
from src.core.models import DockerDaemonUnavailableError, SandboxExecutionError

MAX_OUTPUT=1024*1024

def bounded_output(data: bytes) -> str:
    if len(data) <= MAX_OUTPUT: return data.decode(errors="replace")
    marker=b"\n[output truncated]"
    return (data[:MAX_OUTPUT-len(marker)] + marker).decode(errors="replace")
@dataclass
class DockerRunner:
    client: object|None=None
    images: dict = None
    def __post_init__(self): self.images=self.images or {"python":"python:3.11-slim","javascript":"node:20-alpine"}
    def run(self, code: str, language: str, timeout_seconds: int) -> dict:
        try: client=self.client or docker.from_env(); client.ping()
        except DockerException as exc: raise DockerDaemonUnavailableError("Docker daemon unavailable") from exc
        image=self.images[language]
        command=["python","-c",code] if language=="python" else ["node","-e",code]
        try:
            container=client.containers.run(image,command,detach=True,network_mode="none",user="1000:1000",read_only=True,cap_drop=["ALL"],security_opt=["no-new-privileges:true"],tmpfs={"/tmp":"rw,noexec,nosuid,size=64m"},mem_limit="256m",nano_cpus=500_000_000,pids_limit=64)
            try:
                result=container.wait(timeout=timeout_seconds)
                logs_out=container.logs(stdout=True,stderr=False)[:MAX_OUTPUT]; logs_err=container.logs(stdout=False,stderr=True)[:MAX_OUTPUT]
                return {"stdout":bounded_output(logs_out),"stderr":bounded_output(logs_err),"exit_code":int(result.get("StatusCode",1))}
            finally: container.remove(force=True)
        except DockerException as exc: raise SandboxExecutionError("sandbox execution failed") from exc
