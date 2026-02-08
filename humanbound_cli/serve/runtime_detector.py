"""Detect how to run a bot repository as a local HTTP server."""

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ..exceptions import RuntimeDetectionError


@dataclass
class RuntimeInfo:
    """Detected runtime configuration for a bot repository."""

    runtime: str        # "python", "node", "docker", "langgraph"
    framework: str      # "fastapi", "flask", "django", "express", "langgraph", "docker"
    entry_point: str    # "app.py", "server.js", "docker-compose.yml"
    install_cmd: str    # "pip install -r requirements.txt"
    start_cmd: str      # "uvicorn app:app --port {port}"
    port: int           # 8000
    chat_route: str     # "/chat"
    health_route: str   # "/health"
    env_file: Optional[str] = None   # ".env.example"
    confidence: float = 0.0          # 0.0-1.0


# Keywords that indicate a chat/message endpoint
_CHAT_KEYWORDS = re.compile(
    r"(chat|message|completion|send|ask|query|converse|invoke|run)",
    re.IGNORECASE,
)

# Default chat route fallbacks (tried in order)
_DEFAULT_CHAT_ROUTES = ["/chat", "/api/chat", "/v1/chat/completions"]


class RuntimeDetector:
    """Detect framework, entrypoint, port, and chat route from a repository."""

    def __init__(self, repo_path: str):
        self.repo = Path(repo_path).resolve()
        if not self.repo.is_dir():
            raise RuntimeDetectionError(f"Not a directory: {self.repo}")

    def detect(self) -> Optional[RuntimeInfo]:
        """Run all detectors in confidence order, return first match or None."""
        detectors = [
            self._detect_docker,
            self._detect_langgraph,
            self._detect_fastapi,
            self._detect_flask,
            self._detect_node_express,
            self._detect_django,
        ]

        for detector in detectors:
            result = detector()
            if result:
                # Detect env file
                result.env_file = self._find_env_file()
                return result

        return None

    # -----------------------------------------------------------------
    # Docker
    # -----------------------------------------------------------------

    def _detect_docker(self) -> Optional[RuntimeInfo]:
        """Detect Docker/docker-compose projects."""
        compose = self._find_file("docker-compose.yml") or self._find_file("docker-compose.yaml")
        dockerfile = self._find_file("Dockerfile")

        if not compose and not dockerfile:
            return None

        entry = str((compose or dockerfile).relative_to(self.repo))
        port = 8000

        # Try to parse EXPOSE from Dockerfile
        if dockerfile:
            port = self._parse_docker_expose(dockerfile) or port

        # Try to parse ports from docker-compose
        if compose:
            port = self._parse_compose_port(compose) or port

        start_cmd = "docker compose up" if compose else f"docker build -t hb-bot . && docker run -p {port}:{port} hb-bot"

        return RuntimeInfo(
            runtime="docker",
            framework="docker",
            entry_point=entry,
            install_cmd="",
            start_cmd=start_cmd,
            port=port,
            chat_route=self._detect_chat_route_generic() or "/chat",
            health_route="/health",
            confidence=0.95,
        )

    def _parse_docker_expose(self, dockerfile: Path) -> Optional[int]:
        """Parse EXPOSE directive from Dockerfile."""
        try:
            for line in dockerfile.read_text().splitlines():
                match = re.match(r"^\s*EXPOSE\s+(\d+)", line)
                if match:
                    return int(match.group(1))
        except OSError:
            pass
        return None

    def _parse_compose_port(self, compose_file: Path) -> Optional[int]:
        """Parse first port mapping from docker-compose.yml."""
        try:
            import yaml
            data = yaml.safe_load(compose_file.read_text())
            services = data.get("services", {})
            for svc in services.values():
                ports = svc.get("ports", [])
                for p in ports:
                    # "8000:8000" or "8000"
                    parts = str(p).split(":")
                    return int(parts[0])
        except Exception:
            pass
        return None

    # -----------------------------------------------------------------
    # LangGraph
    # -----------------------------------------------------------------

    def _detect_langgraph(self) -> Optional[RuntimeInfo]:
        """Detect LangGraph projects via langgraph.json."""
        lg_config = self._find_file("langgraph.json")
        if not lg_config:
            return None

        port = 8123
        chat_route = "/runs/stream"

        try:
            data = json.loads(lg_config.read_text())
            graphs = data.get("graphs", {})
            if graphs:
                # Use first graph's path for the run endpoint
                first_graph = next(iter(graphs))
                chat_route = f"/runs/stream"
        except (json.JSONDecodeError, OSError):
            pass

        # LangGraph CLI uses its own install/start
        return RuntimeInfo(
            runtime="langgraph",
            framework="langgraph",
            entry_point="langgraph.json",
            install_cmd="pip install langgraph-cli",
            start_cmd=f"langgraph dev --port {port}",
            port=port,
            chat_route=chat_route,
            health_route="/ok",
            confidence=0.90,
        )

    # -----------------------------------------------------------------
    # FastAPI
    # -----------------------------------------------------------------

    def _detect_fastapi(self) -> Optional[RuntimeInfo]:
        """Detect FastAPI projects."""
        entry = self._find_python_file_containing("FastAPI(")
        if not entry:
            return None

        rel = str(entry.relative_to(self.repo))
        module = rel.replace("/", ".").removesuffix(".py")
        # Detect the app variable name
        app_var = self._find_app_variable(entry, "FastAPI(")

        chat_route = self._detect_chat_route_python(entry) or "/chat"
        health_route = self._detect_health_route_python(entry) or "/health"
        install_cmd = self._python_install_cmd()

        return RuntimeInfo(
            runtime="python",
            framework="fastapi",
            entry_point=rel,
            install_cmd=install_cmd,
            start_cmd=f"uvicorn {module}:{app_var} --port {{port}}",
            port=8000,
            chat_route=chat_route,
            health_route=health_route,
            confidence=0.85,
        )

    # -----------------------------------------------------------------
    # Flask
    # -----------------------------------------------------------------

    def _detect_flask(self) -> Optional[RuntimeInfo]:
        """Detect Flask projects."""
        entry = self._find_python_file_containing("Flask(__name__)")
        if not entry:
            return None

        rel = str(entry.relative_to(self.repo))
        chat_route = self._detect_chat_route_python(entry) or "/chat"
        health_route = self._detect_health_route_python(entry) or "/health"
        install_cmd = self._python_install_cmd()

        return RuntimeInfo(
            runtime="python",
            framework="flask",
            entry_point=rel,
            install_cmd=install_cmd,
            start_cmd=f"flask --app {rel} run --port {{port}}",
            port=5000,
            chat_route=chat_route,
            health_route=health_route,
            confidence=0.80,
        )

    # -----------------------------------------------------------------
    # Django
    # -----------------------------------------------------------------

    def _detect_django(self) -> Optional[RuntimeInfo]:
        """Detect Django projects."""
        manage = self._find_file("manage.py")
        if not manage:
            return None

        # Confirm it's Django by checking for settings reference
        try:
            content = manage.read_text()
            if "django" not in content.lower():
                return None
        except OSError:
            return None

        install_cmd = self._python_install_cmd()

        return RuntimeInfo(
            runtime="python",
            framework="django",
            entry_point="manage.py",
            install_cmd=install_cmd,
            start_cmd="python manage.py runserver 0.0.0.0:{port}",
            port=8000,
            chat_route=self._detect_chat_route_generic() or "/chat",
            health_route="/health",
            confidence=0.70,
        )

    # -----------------------------------------------------------------
    # Node / Express
    # -----------------------------------------------------------------

    def _detect_node_express(self) -> Optional[RuntimeInfo]:
        """Detect Node.js/Express projects."""
        pkg_json = self._find_file("package.json")
        if not pkg_json:
            return None

        try:
            data = json.loads(pkg_json.read_text())
        except (json.JSONDecodeError, OSError):
            return None

        deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
        if "express" not in deps and "fastify" not in deps and "koa" not in deps:
            return None

        # Parse start script
        scripts = data.get("scripts", {})
        start_cmd = scripts.get("start", "node index.js")
        port = 3000

        # Try to extract port from start script
        port_match = re.search(r"--port[= ](\d+)", start_cmd)
        if port_match:
            port = int(port_match.group(1))

        # Find main entry
        main = data.get("main", "index.js")

        return RuntimeInfo(
            runtime="node",
            framework="express",
            entry_point=main,
            install_cmd="npm install",
            start_cmd=f"npm start",
            port=port,
            chat_route=self._detect_chat_route_generic() or "/chat",
            health_route="/health",
            confidence=0.80,
        )

    # -----------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------

    def _find_file(self, name: str) -> Optional[Path]:
        """Find a file by exact name in repo root."""
        target = self.repo / name
        return target if target.is_file() else None

    def _find_python_file_containing(self, pattern: str) -> Optional[Path]:
        """Find a Python file in the repo containing a pattern string.

        Searches root-level files first, then one level deep.
        """
        # Root-level .py files first (most likely)
        for f in sorted(self.repo.glob("*.py")):
            try:
                if pattern in f.read_text():
                    return f
            except OSError:
                continue

        # One level deep
        for f in sorted(self.repo.glob("*/*.py")):
            if any(skip in str(f) for skip in ("__pycache__", ".venv", "node_modules", "test")):
                continue
            try:
                if pattern in f.read_text():
                    return f
            except OSError:
                continue

        return None

    def _find_app_variable(self, filepath: Path, constructor: str) -> str:
        """Find the variable name assigned to a framework constructor (e.g. 'app = FastAPI()')."""
        try:
            for line in filepath.read_text().splitlines():
                if constructor in line:
                    match = re.match(r"^\s*(\w+)\s*=\s*" + re.escape(constructor.rstrip("(")), line)
                    if match:
                        return match.group(1)
        except OSError:
            pass
        return "app"

    def _detect_chat_route_python(self, filepath: Path) -> Optional[str]:
        """Detect chat route from Python route decorators."""
        try:
            content = filepath.read_text()
        except OSError:
            return None

        # Match @app.post("/chat"), @app.route("/message"), etc.
        route_pattern = re.compile(
            r'@\w+\.(post|route|get|put)\s*\(\s*["\']([^"\']+)["\']',
            re.IGNORECASE,
        )

        for match in route_pattern.finditer(content):
            route = match.group(2)
            if _CHAT_KEYWORDS.search(route):
                return route

        return None

    def _detect_health_route_python(self, filepath: Path) -> Optional[str]:
        """Detect health check route from Python route decorators."""
        try:
            content = filepath.read_text()
        except OSError:
            return None

        route_pattern = re.compile(
            r'@\w+\.(get|route)\s*\(\s*["\']([^"\']+)["\']',
            re.IGNORECASE,
        )

        for match in route_pattern.finditer(content):
            route = match.group(2)
            if re.search(r"(health|healthz|ready|status|ping|ok)", route, re.IGNORECASE):
                return route

        return None

    def _detect_chat_route_generic(self) -> Optional[str]:
        """Try to detect chat route from any source file via grep."""
        patterns = ["*.py", "*.js", "*.ts"]
        for pat in patterns:
            for f in self.repo.glob(pat):
                if any(skip in str(f) for skip in ("__pycache__", "node_modules", ".venv", "test")):
                    continue
                try:
                    content = f.read_text()
                except OSError:
                    continue
                # Look for route-like patterns with chat keywords
                route_match = re.search(
                    r'["\'](/[\w/]*(?:chat|message|completion|ask|query)[\w/]*)["\']',
                    content,
                    re.IGNORECASE,
                )
                if route_match:
                    return route_match.group(1)
        return None

    def _find_env_file(self) -> Optional[str]:
        """Find .env.example or similar env template."""
        for name in (".env.example", ".env.template", ".env.sample"):
            if (self.repo / name).is_file():
                return name
        return None

    def _python_install_cmd(self) -> str:
        """Determine the Python dependency install command."""
        if (self.repo / "requirements.txt").is_file():
            return "pip install -r requirements.txt"
        if (self.repo / "pyproject.toml").is_file():
            return "pip install -e ."
        if (self.repo / "setup.py").is_file():
            return "pip install -e ."
        return ""
