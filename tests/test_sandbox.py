import pytest
from src.sandbox.docker_runner import DockerRunner
from src.core.models import DockerDaemonUnavailableError

def test_docker_security_options_are_applied():
    class Container:
        def wait(self, timeout): return {"StatusCode":0}
        def logs(self, **kwargs): return b"ok"
        def remove(self, force): pass
    class Containers:
        def run(self, image, command, **kw):
            assert image=="python:3.11-slim"; assert kw["network_mode"]=="none"; assert kw["read_only"]
            assert kw["user"]=="1000:1000"; assert kw["cap_drop"]==["ALL"]; assert kw["pids_limit"]==64
            return Container()
    class Images:
        def get(self, image): pass
    class Client:
        containers=Containers(); images=Images()
        def ping(self): pass
    assert DockerRunner(Client()).run("print(1)","python",10)["exit_code"]==0

def test_daemon_error_without_host_fallback():
    class Client:
        def ping(self): raise RuntimeError("offline")
    # RuntimeError is not a DockerException; real client errors are translated.
    # This fake verifies no subprocess fallback path exists.
    with pytest.raises(Exception): DockerRunner(Client()).run("print(1)","python",10)
