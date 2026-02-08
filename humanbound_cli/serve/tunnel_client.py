"""WebSocket tunnel client for the Humanbound relay service."""

import json
import threading
from typing import Optional

import requests

from ..config import DEFAULT_RELAY_URL
from ..exceptions import TunnelError


def _require_websockets():
    """Import websockets or raise a clear error."""
    try:
        import websockets.sync.client as ws_client
        return ws_client
    except ImportError:
        raise TunnelError(
            "The 'websockets' package is required for --serve tunnelling.\n"
            "Install it with: pip install 'humanbound-cli[serve]'"
        )


class TunnelClient:
    """WebSocket client that tunnels HTTP requests through the Humanbound relay.

    Protocol::

        CLI -> Relay:  {"type": "register", "local_port": 8000}
        Relay -> CLI:  {"type": "registered", "public_url": "https://abc123.relay.humanbound.ai"}

        Relay -> CLI:  {"type": "request", "id": "req-123", "method": "POST", "path": "/chat", ...}
        CLI forwards:  HTTP POST localhost:8000/chat
        CLI -> Relay:  {"type": "response", "id": "req-123", "status": 200, "body": "..."}

        Relay -> CLI:  {"type": "ping"}  /  CLI -> Relay: {"type": "pong"}
    """

    def __init__(self, local_port: int, api_token: str, relay_url: str = None):
        self.local_port = local_port
        self.local_base = f"http://localhost:{local_port}"
        self.api_token = api_token
        self.relay_url = relay_url or DEFAULT_RELAY_URL
        self.public_url: Optional[str] = None
        self._ws = None
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._connected = False

    def connect(self) -> str:
        """Connect to the relay and return the public URL.

        Raises:
            TunnelError: If connection or registration fails.
        """
        ws_client = _require_websockets()

        headers = {"Authorization": f"Bearer {self.api_token}"}

        try:
            self._ws = ws_client.connect(
                self.relay_url,
                additional_headers=headers,
                open_timeout=15,
                close_timeout=5,
            )
        except Exception as e:
            raise TunnelError(f"Could not connect to relay: {e}")

        # Send registration
        try:
            self._ws.send(json.dumps({
                "type": "register",
                "local_port": self.local_port,
            }))

            # Wait for registration response
            raw = self._ws.recv(timeout=15)
            msg = json.loads(raw)

            if msg.get("type") == "registered" and msg.get("public_url"):
                self.public_url = msg["public_url"]
            elif msg.get("type") == "error":
                raise TunnelError(f"Relay error: {msg.get('message', 'unknown')}")
            else:
                raise TunnelError(f"Unexpected relay response: {msg}")

        except TunnelError:
            raise
        except Exception as e:
            self.disconnect()
            raise TunnelError(f"Registration failed: {e}")

        # Start forwarding thread
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._forward_loop, daemon=True)
        self._thread.start()
        self._connected = True

        return self.public_url

    def disconnect(self) -> None:
        """Close the tunnel connection."""
        self._stop_event.set()
        self._connected = False

        if self._ws:
            try:
                self._ws.close()
            except Exception:
                pass
            self._ws = None

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)
        self._thread = None

    @property
    def is_connected(self) -> bool:
        return self._connected and self._ws is not None

    # -----------------------------------------------------------------
    # Forwarding loop
    # -----------------------------------------------------------------

    def _forward_loop(self) -> None:
        """Read relay messages and forward HTTP requests to local server."""
        reconnect_attempted = False

        while not self._stop_event.is_set():
            try:
                raw = self._ws.recv(timeout=5)
            except TimeoutError:
                continue
            except Exception:
                if self._stop_event.is_set():
                    return
                # One reconnect attempt
                if not reconnect_attempted:
                    reconnect_attempted = True
                    if self._try_reconnect():
                        continue
                self._connected = False
                return

            try:
                msg = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                continue

            msg_type = msg.get("type")

            if msg_type == "ping":
                self._send({"type": "pong"})

            elif msg_type == "request":
                self._handle_request(msg)

    def _handle_request(self, msg: dict) -> None:
        """Forward an HTTP request to the local server and send the response back."""
        req_id = msg.get("id")
        method = msg.get("method", "GET").upper()
        path = msg.get("path", "/")
        headers = msg.get("headers", {})
        body = msg.get("body")

        url = f"{self.local_base}{path}"

        try:
            resp = requests.request(
                method=method,
                url=url,
                headers={k: v for k, v in headers.items() if k.lower() != "host"},
                data=body.encode("utf-8") if isinstance(body, str) else body,
                timeout=30,
            )

            self._send({
                "type": "response",
                "id": req_id,
                "status": resp.status_code,
                "headers": dict(resp.headers),
                "body": resp.text,
            })

        except Exception as e:
            self._send({
                "type": "response",
                "id": req_id,
                "status": 502,
                "body": json.dumps({"error": f"Local forwarding failed: {e}"}),
            })

    def _send(self, msg: dict) -> None:
        """Send a JSON message to the relay."""
        if self._ws:
            try:
                self._ws.send(json.dumps(msg))
            except Exception:
                pass

    def _try_reconnect(self) -> bool:
        """Attempt one reconnection."""
        ws_client = _require_websockets()

        try:
            if self._ws:
                try:
                    self._ws.close()
                except Exception:
                    pass

            headers = {"Authorization": f"Bearer {self.api_token}"}
            self._ws = ws_client.connect(
                self.relay_url,
                additional_headers=headers,
                open_timeout=10,
                close_timeout=5,
            )

            self._ws.send(json.dumps({
                "type": "register",
                "local_port": self.local_port,
            }))

            raw = self._ws.recv(timeout=10)
            msg = json.loads(raw)

            if msg.get("type") == "registered":
                self.public_url = msg.get("public_url", self.public_url)
                return True
        except Exception:
            pass

        return False
