"""Authentication commands."""

import click
from rich.console import Console
from rich.panel import Panel

from ..client import HumanboundClient
from ..exceptions import AuthenticationError, APIError

console = Console()


@click.group("auth")
def auth_group():
    """Authentication commands."""
    pass


@auth_group.command("login")
@click.option("--base-url", help="API base URL for on-prem deployments")
@click.option("--port", default=8085, help="Local callback port (default: 8085)")
@click.option("--force", "-f", is_flag=True, help="Force re-authentication even if already logged in")
def login(base_url: str, port: int, force: bool):
    """Authenticate with Humanbound via browser.

    Opens your browser to complete OAuth authentication.
    Credentials are stored locally for future use.
    """
    client = HumanboundClient(base_url=base_url)

    if client.is_authenticated() and not force:
        console.print("[yellow]Already logged in.[/yellow]")
        if not click.confirm("Login again?"):
            return
        # User confirmed re-login, clear existing credentials first
        client.logout()

    try:
        console.print("Starting authentication...")
        client.login(callback_port=port)

        # Auto-select default organisation and resolve name
        org_display = "not set"
        if client.default_organisation_id:
            client.set_organisation(client.default_organisation_id)
            try:
                orgs = client.list_organisations()
                org = next((o for o in orgs if o.get("id", "").lower() == client.default_organisation_id.lower()), None)
                org_display = f"{org.get('name')} ({client.default_organisation_id})" if org else client.default_organisation_id
            except Exception as e:
                org_display = f"{client.default_organisation_id} (could not resolve name: {e})"

        console.print(Panel(
            f"[green]Login successful![/green]\n\n"
            f"User: {client.username or 'unknown'}\n"
            f"Organisation: {org_display}",
            title="Humanbound",
        ))
    except AuthenticationError as e:
        # Clear any partial credentials on failure (silent to avoid confusion)
        client.logout(silent=True)
        console.print(f"[red]Login failed:[/red] {e}")
        raise SystemExit(1)


@auth_group.command("logout")
@click.option("--revoke", is_flag=True, help="Also clear browser SSO session (opens browser)")
@click.option("--port", default=8085, help="Local callback port (default: 8085)")
def logout(revoke: bool, port: int):
    """Clear stored credentials."""
    client = HumanboundClient()
    client.logout()  # This already prints the success message

    if revoke:
        import webbrowser
        import urllib.parse
        import http.server
        import socketserver
        from ..config import get_auth0_domain, get_auth0_client_id
        from ..client import LOGOUT_HTML

        auth0_domain = get_auth0_domain()
        client_id = get_auth0_client_id()
        return_to = f"http://localhost:{port}"

        logout_url = (
            f"https://{auth0_domain}/v2/logout?"
            + urllib.parse.urlencode({"client_id": client_id, "returnTo": return_to})
        )

        class LogoutHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(LOGOUT_HTML.encode())

            def log_message(self, format, *args):
                pass

        socketserver.TCPServer.allow_reuse_address = True
        server = socketserver.TCPServer(("", port), LogoutHandler)
        server.timeout = 30

        try:
            console.print("Opening browser to clear Auth0 session...")
            webbrowser.open(logout_url)
            server.handle_request()
        finally:
            server.server_close()

        console.print("[green]Browser session revoked.[/green]")
    else:
        console.print(
            "[dim]Note: Your browser may still have an active Auth0 session. "
            "Use 'hb logout --revoke' to also clear the browser session.[/dim]"
        )


@auth_group.command("whoami")
def whoami():
    """Show current authentication status."""
    client = HumanboundClient()

    if client.is_authenticated():
        # Resolve org name
        org_display = "[dim]not set[/dim]"
        if client.organisation_id:
            org_display = client.organisation_id
            try:
                orgs = client.list_organisations()
                org = next((o for o in orgs if o.get("id", "").lower() == client.organisation_id.lower()), None)
                if org:
                    org_display = f"{org.get('name')} ({client.organisation_id})"
            except Exception as e:
                org_display = f"{client.organisation_id} [dim](could not resolve name: {e})[/dim]"

        console.print(Panel(
            f"[green]Authenticated[/green]\n\n"
            f"User: {client.username or '[dim]unknown[/dim]'}\n"
            f"Email: {client.email or '[dim]unknown[/dim]'}\n"
            f"Base URL: {client.base_url}\n"
            f"Organisation: {org_display}\n"
            f"Project: {client.project_id or '[dim]not set[/dim]'}",
            title="Humanbound Status",
        ))
    else:
        console.print(Panel(
            "[yellow]Not authenticated[/yellow]\n\n"
            "Run 'hb login' to authenticate.",
            title="Humanbound Status",
        ))
