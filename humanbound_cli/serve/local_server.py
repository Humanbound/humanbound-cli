"""Launch and manage a local bot server subprocess."""

import atexit
import os
import signal
import socket
import subprocess
import sys
import time
from typing import Optional

import requests

from ..config import SERVE_HEALTH_CHECK_TIMEOUT, SERVE_INSTALL_TIMEOUT, SERVE_PORT_RANGE
from ..exceptions import ServeError
from .runtime_detector import RuntimeInfo


class LocalServer:
    """Context manager for starting/stopping a local bot server.

    Usage::

        with LocalServer(runtime) as server:
            # server.port is the actual port
            # server.base_url is http://localhost:{port}
            ...
        # server is stopped automatically
    """

    def __init__(self, runtime: RuntimeInfo, repo_path: str, verbose: bool = False):
        self.runtime = runtime
        self.repo = repo_path
        self.verbose = verbose
        self.port: int = runtime.port
        self.base_url: str = ""
        self._process: Optional[subprocess.Popen] = None
        self._started = False

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
        return False

    # -----------------------------------------------------------------
    # Lifecycle
    # -----------------------------------------------------------------

    def start(self) -> None:
        """Allocate port, start the server, wait for health check."""
        self.port = self._allocate_port(self.runtime.port)
        self.base_url = f"http://localhost:{self.port}"

        # Build start command with actual port
        cmd = self.runtime.start_cmd.replace("{port}", str(self.port))

        # Prepare environment — pass through user env so their API keys work
        env = os.environ.copy()
        env["PORT"] = str(self.port)

        try:
            self._process = subprocess.Popen(
                cmd,
                shell=True,
                cwd=self.repo,
                env=env,
                stdout=subprocess.PIPE if not self.verbose else None,
                stderr=subprocess.PIPE if not self.verbose else None,
                start_new_session=True,  # own process group for clean kill
            )
        except OSError as e:
            raise ServeError(f"Failed to start server: {e}")

        # Register safety-net cleanup
        atexit.register(self._atexit_cleanup)
        self._started = True

        # Wait for health check
        if not self._wait_for_health():
            stderr_tail = self._read_stderr_tail()
            self.stop()
            msg = "Server did not become healthy"
            if stderr_tail:
                msg += f"\n\nLast output:\n{stderr_tail}"
            raise ServeError(msg)

    def stop(self) -> None:
        """Stop the server process and all children via process group kill."""
        if not self._process:
            return

        try:
            pgid = os.getpgid(self._process.pid)
            os.killpg(pgid, signal.SIGTERM)
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(pgid, signal.SIGKILL)
                self._process.wait(timeout=2)
        except (ProcessLookupError, OSError):
            pass  # already dead
        finally:
            self._process = None
            self._started = False

    def install_deps(self) -> None:
        """Run the dependency install command (blocking)."""
        if not self.runtime.install_cmd:
            return

        try:
            result = subprocess.run(
                self.runtime.install_cmd,
                shell=True,
                cwd=self.repo,
                capture_output=True,
                text=True,
                timeout=SERVE_INSTALL_TIMEOUT,
            )
            if result.returncode != 0:
                raise ServeError(
                    f"Dependency install failed (exit {result.returncode}):\n{result.stderr[:500]}"
                )
        except subprocess.TimeoutExpired:
            raise ServeError(
                f"Dependency install timed out after {SERVE_INSTALL_TIMEOUT}s"
            )

    # -----------------------------------------------------------------
    # Port allocation
    # -----------------------------------------------------------------

    def _allocate_port(self, preferred: int) -> int:
        """Try preferred port, then scan range for a free one."""
        if self._is_port_free(preferred):
            return preferred

        low, high = SERVE_PORT_RANGE
        for port in range(low, high + 1):
            if port != preferred and self._is_port_free(port):
                return port

        raise ServeError(f"No free port found in range {low}-{high}")

    @staticmethod
    def _is_port_free(port: int) -> bool:
        """Check if a port is available."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("localhost", port))
                return True
            except OSError:
                return False

    # -----------------------------------------------------------------
    # Health check
    # -----------------------------------------------------------------

    def _wait_for_health(self) -> bool:
        """Poll the health endpoint until it responds 200 or timeout."""
        health_url = f"{self.base_url}{self.runtime.health_route}"
        deadline = time.time() + SERVE_HEALTH_CHECK_TIMEOUT
        interval = 2

        while time.time() < deadline:
            # Check if process died
            if self._process and self._process.poll() is not None:
                return False

            try:
                resp = requests.get(health_url, timeout=3)
                if resp.status_code < 500:
                    return True
            except requests.ConnectionError:
                pass
            except requests.Timeout:
                pass

            time.sleep(interval)

        return False

    # -----------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------

    def _read_stderr_tail(self, lines: int = 20) -> str:
        """Read the last N lines of stderr from the process."""
        if not self._process or not self._process.stderr:
            return ""
        try:
            raw = self._process.stderr.read()
            if raw:
                decoded = raw.decode("utf-8", errors="replace")
                return "\n".join(decoded.splitlines()[-lines:])
        except Exception:
            pass
        return ""

    def _atexit_cleanup(self) -> None:
        """Safety net: kill server on interpreter exit."""
        if self._started:
            self.stop()
