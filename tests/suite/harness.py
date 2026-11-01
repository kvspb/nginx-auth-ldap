"""Start throwaway nginx instances with a per-test configuration."""

from __future__ import annotations

import os
import re
import signal
import socket
import subprocess
import tempfile
import textwrap
import time
from dataclasses import dataclass, field
from pathlib import Path

import requests

NGINX_BINARY = os.environ.get("NGINX_BINARY", "nginx")

# Mull enables a mutant through an environment variable named after it,
# e.g. "cxx_eq_to_ne:/src/x.c:12:5:12:7=1". nginx clears the environment of
# its workers, so such variables are passed on with the "env" directive.
MULL_MUTANT_RE = re.compile(r"^cxx_\w+:")

# Written by the master process when a worker dies abnormally.
CRASH_RE = re.compile(r"worker process \d+ exited on signal \d+")
ASAN_RE = re.compile(r"ERROR: AddressSanitizer")


def nginx_version() -> tuple[int, int, int]:
    out = subprocess.run([NGINX_BINARY, "-v"], capture_output=True, text=True, check=False).stderr
    match = re.search(r"nginx/(\d+)\.(\d+)\.(\d+)", out)
    if match is None:
        raise RuntimeError(f"cannot parse nginx version from {out!r}")
    major, minor, patch = (int(part) for part in match.groups())
    return major, minor, patch


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@dataclass
class Nginx:
    """One nginx master process with its own prefix directory.

    The configuration is assembled from an ``http`` block fragment (usually
    ``ldap_server`` blocks and module directives) and a ``server`` block
    fragment (locations). The listen directive is added automatically.
    """

    prefix: Path
    port: int = field(default_factory=_free_port)
    env: dict[str, str] = field(default_factory=dict)
    process: subprocess.Popen | None = None
    # Worker PIDs right after start(); a different set later means a worker
    # died and the master replaced it.
    started_workers: frozenset[int] | None = None

    @property
    def error_log(self) -> Path:
        return self.prefix / "logs" / "error.log"

    @property
    def conf_path(self) -> Path:
        return self.prefix / "conf" / "nginx.conf"

    def url(self, path: str = "/") -> str:
        return f"http://127.0.0.1:{self.port}{path}"

    def write_config(self, http: str = "", server: str = "", main: str = "", events: str = "") -> Path:
        for sub in ("conf", "html", "logs", "temp"):
            (self.prefix / sub).mkdir(parents=True, exist_ok=True)
        # Served by protected_location() once access is granted.
        (self.prefix / "html" / "ok").write_text("ok")

        level = "debug" if "--with-debug" in self._configure_args() else "info"
        passed_env = "".join(
            f'env "{name}";\n' for name in {**os.environ, **self.env} if MULL_MUTANT_RE.match(name)
        )
        conf = textwrap.dedent(
            """\
            {passed_env}daemon off;
            master_process on;
            # The runner container is disposable; running workers as root
            # keeps the private (0700) prefix directory accessible to them.
            user root;
            worker_processes 1;
            error_log {error_log} {level};
            {main}
            pid {prefix}/logs/nginx.pid;

            events {{
                worker_connections 64;
                {events}
            }}

            http {{
                access_log off;
                client_body_temp_path {prefix}/temp/client_body;
                proxy_temp_path {prefix}/temp/proxy;
                fastcgi_temp_path {prefix}/temp/fastcgi;
                uwsgi_temp_path {prefix}/temp/uwsgi;
                scgi_temp_path {prefix}/temp/scgi;

            {http}

                server {{
                    listen 127.0.0.1:{port};

            {server}
                }}
            }}
            """
        ).format(
            passed_env=passed_env,
            main=main,
            events=events,
            error_log=self.error_log,
            level=level,
            prefix=self.prefix,
            port=self.port,
            http=textwrap.indent(textwrap.dedent(http), "    "),
            server=textwrap.indent(textwrap.dedent(server), "        "),
        )
        self.conf_path.write_text(conf)
        return self.conf_path

    def check_config(self, http: str = "", server: str = "") -> subprocess.CompletedProcess:
        """Run ``nginx -t``; a negative return code means it was killed by a signal."""
        self.write_config(http, server)
        return subprocess.run(
            [NGINX_BINARY, "-t", "-p", str(self.prefix), "-c", str(self.conf_path)],
            capture_output=True,
            text=True,
            env={**os.environ, **self.env},
            timeout=30,
            check=False,
        )

    def start(self, http: str = "", server: str = "", main: str = "", events: str = "") -> Nginx:
        """Start nginx; ``main`` goes into the main (top-level) context and
        ``events`` into the events block."""
        # Restarting is allowed, e.g. by a parametrized class-scoped fixture.
        self.stop()
        self.write_config(http, server, main, events)
        self.process = subprocess.Popen(
            [NGINX_BINARY, "-p", str(self.prefix), "-c", str(self.conf_path)],
            env={**os.environ, **self.env},
        )
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError(f"nginx exited with {self.process.returncode}:\n{self.log()}")
            # The master listens before it forks, so also wait for the worker:
            # crash detection compares worker PIDs against this snapshot.
            workers = self.worker_pids()
            if workers != frozenset():
                try:
                    socket.create_connection(("127.0.0.1", self.port), timeout=0.2).close()
                    self.started_workers = workers
                    return self
                except OSError:
                    pass
            time.sleep(0.02)
        raise RuntimeError(f"nginx did not start:\n{self.log()}")

    def reload(self, deadline: float = 10) -> None:
        """Reload the configuration (SIGHUP) and wait for a new worker.

        The old worker shuts down gracefully and may outlive this call.
        """
        assert self.process is not None
        old = self.worker_pids() or frozenset()
        self.process.send_signal(signal.SIGHUP)
        end = time.monotonic() + deadline
        while time.monotonic() < end:
            if (self.worker_pids() or frozenset()) - old:
                return
            time.sleep(0.02)
        raise RuntimeError(f"nginx did not start a new worker:\n{self.log()}")

    def stop(self) -> None:
        if self.process is None or self.process.poll() is not None:
            return
        self.process.send_signal(signal.SIGTERM)
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()

    def get(
        self,
        path: str = "/",
        auth: tuple[str, str] | None = None,
        timeout: float = 15,
        **kwargs,
    ) -> requests.Response:
        return requests.get(self.url(path), auth=auth, timeout=timeout, **kwargs)

    def log(self, since: int = 0) -> str:
        """The error log from byte offset ``since`` (see log_size())."""
        try:
            with self.error_log.open("rb") as log:
                log.seek(since)
                return log.read().decode(errors="replace")
        except FileNotFoundError:
            return ""

    def log_size(self) -> int:
        try:
            return self.error_log.stat().st_size
        except FileNotFoundError:
            return 0

    def worker_pids(self) -> frozenset[int] | None:
        """Live children of the master, or None where /proc is unavailable."""
        if self.process is None or self.process.poll() is not None:
            return frozenset()
        proc = Path("/proc")
        if not proc.is_dir():
            return None
        pids = set()
        for stat in proc.glob("[0-9]*/stat"):
            try:
                # The command name may contain spaces; fields follow the last ")".
                state, ppid = stat.read_text().rsplit(")", 1)[1].split()[:2]
            except (OSError, IndexError, ValueError):
                continue
            if int(ppid) == self.process.pid and state != "Z":
                pids.add(int(stat.parent.name))
        return frozenset(pids)

    def crashes(self, since: int = 0, workers: frozenset[int] | None = None) -> list[str]:
        """Worker crash and sanitizer reports logged after byte offset ``since``.

        ``workers`` is the PID set before the code under test ran (defaults to
        the set seen at start). When it still matches, no worker died and the
        log is read at once; otherwise the master logs the death
        asynchronously, so give it a moment first.
        """
        if workers is None:
            workers = self.started_workers
        current = self.worker_pids()
        if workers is None or current is None or current != workers:
            time.sleep(0.5)
        log = self.log(since)
        return CRASH_RE.findall(log) + ASAN_RE.findall(log)

    @staticmethod
    def _configure_args() -> str:
        return subprocess.run([NGINX_BINARY, "-V"], capture_output=True, text=True, check=False).stderr


def new_prefix() -> Path:
    return Path(tempfile.mkdtemp(prefix="nginx-"))
