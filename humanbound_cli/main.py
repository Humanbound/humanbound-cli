"""Humanbound CLI entry point."""

import click
from rich.console import Console

from .client import HumanboundClient
from .config import get_base_url

from .commands import (
    auth,
    orgs,
    projects,
    experiments,
    init,
    test,
    logs,
    posture,
    guardrails,
    docs,
    providers,
    findings,
    api_keys,
    members,
    coverage,
    campaigns,
    upload_logs,
)

console = Console()


def get_client() -> HumanboundClient:
    """Get a configured Humanbound client."""
    return HumanboundClient()


@click.group()
@click.option(
    "--base-url",
    envvar="HUMANBOUND_BASE_URL",
    help="API base URL (default: https://api.humanbound.ai)",
)
@click.pass_context
def cli(ctx, base_url: str):
    """Humanbound CLI - AI agent security testing from the command line.

    Use 'hb login' to authenticate, then create a project and run tests.

    \b
    Quick Start:
      hb login                      # Authenticate
      hb switch <id>              # Select organisation
      hb init --name "Bot" --prompt ./prompt.txt  # Create project
      hb test                       # Run security tests
      hb status                     # Check progress
      hb logs                       # Get results

    \b
    Project Sources:
      hb init --prompt ./prompt.txt   # From system prompt
      hb init --endpoint ./config.json  # From live chatbot
      hb init --repo ./agent-code     # From repository
      hb init --openapi ./spec.yaml   # From OpenAPI spec
    """
    ctx.ensure_object(dict)
    ctx.obj["base_url"] = base_url


# Register command groups
cli.add_command(auth.auth_group)
cli.add_command(orgs.orgs_group)
cli.add_command(projects.projects_group)
cli.add_command(experiments.experiments_group)
cli.add_command(providers.providers_group)
cli.add_command(findings.findings_group)
cli.add_command(api_keys.api_keys_group)
cli.add_command(members.members_group)
cli.add_command(campaigns.campaigns_group)

# Register top-level commands
cli.add_command(init.init_project)
cli.add_command(test.test_command)
cli.add_command(logs.logs_command)
cli.add_command(posture.posture_command)
cli.add_command(guardrails.guardrails_command)
cli.add_command(docs.docs_command)
cli.add_command(coverage.coverage_command)
cli.add_command(upload_logs.upload_logs_command)


# Convenience aliases at top level
@cli.command("login")
@click.pass_context
def login_alias(ctx):
    """Authenticate with Humanbound (alias for 'auth login')."""
    ctx.invoke(auth.login, base_url=ctx.obj.get("base_url"))


@cli.command("logout")
@click.pass_context
def logout_alias(ctx):
    """Clear stored credentials (alias for 'auth logout')."""
    ctx.invoke(auth.logout)


@cli.command("whoami")
@click.pass_context
def whoami_alias(ctx):
    """Show current authentication status (alias for 'auth whoami')."""
    ctx.invoke(auth.whoami)


@cli.command("switch")
@click.argument("org_id")
def switch_org(org_id: str):
    """Switch to a different organisation.

    ORG_ID: Organisation UUID to use.
    """
    from .client import HumanboundClient
    from .exceptions import NotAuthenticatedError, APIError

    client = HumanboundClient()

    try:
        # Verify the org exists by listing and checking
        orgs_list = client.list_organisations()
        org = next((o for o in orgs_list if o.get("id") == org_id), None)

        if not org:
            console.print(f"[red]Organisation not found:[/red] {org_id}")
            console.print("\nAvailable organisations:")
            for o in orgs_list:
                console.print(f"  {o.get('id')} - {o.get('name')}")
            raise SystemExit(1)

        client.set_organisation(org_id)
        console.print(f"[green]Switched to organisation:[/green] {org.get('name')}")

    except NotAuthenticatedError:
        console.print("[red]Not authenticated.[/red] Run 'hb login' first.")
        raise SystemExit(1)
    except APIError as e:
        console.print(f"[red]Error:[/red] {e}")


@cli.command("status")
@click.argument("experiment_id", required=False)
@click.option("--watch", "-w", is_flag=True, help="Watch status until completion")
@click.pass_context
def status_alias(ctx, experiment_id: str, watch: bool):
    """Check experiment status (alias for 'experiments status').

    If no experiment_id is provided, shows the most recent experiment.
    """
    client = HumanboundClient()

    if not experiment_id:
        # Get most recent experiment
        if not client.project_id:
            console.print("[yellow]No project selected.[/yellow]")
            console.print("Use 'hb projects use <id>' to select a project.")
            raise SystemExit(1)

        try:
            response = client.list_experiments(page=1, size=1)
            exps = response.get("data", [])
            if not exps:
                console.print("[yellow]No experiments found.[/yellow]")
                raise SystemExit(1)
            experiment_id = exps[0].get("id")
        except Exception as e:
            console.print(f"[red]Error:[/red] {e}")
            raise SystemExit(1)

    ctx.invoke(
        experiments.experiment_status,
        experiment_id=experiment_id,
        watch=watch,
        interval=10,
    )


if __name__ == "__main__":
    cli()
