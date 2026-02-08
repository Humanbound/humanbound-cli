"""Logs command for retrieving and exporting experiment results."""

import click
from rich.console import Console
from rich.table import Table
import json
import sys
from pathlib import Path

from ..client import HumanboundClient
from ..exceptions import NotAuthenticatedError, APIError
from ..config import LONG_TIMEOUT

console = Console()
console_err = Console(stderr=True)


@click.command("logs")
@click.argument("experiment_id", required=False)
@click.option(
    "--format", "-f", "output_format",
    type=click.Choice(["table", "json", "html"]),
    default="table",
    help="Output format"
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    help="Output file path (prints to stdout if not specified)"
)
@click.option(
    "--verdict", "-v",
    type=click.Choice(["pass", "fail", "all"]),
    default="all",
    help="Filter by verdict"
)
@click.option(
    "--page", default=1, help="Page number (for table format)"
)
@click.option(
    "--size", default=50, help="Items per page (for table format)"
)
@click.option(
    "--all", "fetch_all", is_flag=True, help="Fetch all logs (for json format)"
)
def logs_command(experiment_id: str, output_format: str, output: str, verdict: str, page: int, size: int, fetch_all: bool):
    """Get logs from an experiment.

    If no experiment_id is provided, uses the most recent experiment.

    \b
    Examples:
      hb logs                              # Show recent experiment logs
      hb logs abc123 --format=json         # Export as JSON
      hb logs abc123 --format=html -o report.html
      hb logs abc123 --verdict=fail        # Show only failures
    """
    client = HumanboundClient()

    if not client.is_authenticated():
        console_err.print("[red]Not authenticated.[/red] Run 'hb login' first.")
        raise SystemExit(1)

    if not client.project_id:
        console_err.print("[yellow]No project selected.[/yellow]")
        console_err.print("Use 'hb projects use <id>' to select a project first.")
        raise SystemExit(1)

    try:
        # Get experiment ID if not provided
        if not experiment_id:
            response = client.list_experiments(page=1, size=1)
            exps = response.get("data", [])
            if not exps:
                console_err.print("[yellow]No experiments found.[/yellow]")
                raise SystemExit(1)
            experiment_id = exps[0].get("id")
            console_err.print(f"[dim]Using most recent experiment: {experiment_id}[/dim]")

        # Resolve partial experiment ID
        experiment_id = _resolve_experiment_id(client, experiment_id)

        if output_format == "html":
            _export_html(client, experiment_id, output)
        elif output_format == "json":
            _export_json(client, experiment_id, output, verdict, fetch_all, page, size)
        else:
            _show_table(client, experiment_id, verdict, page, size)

    except NotAuthenticatedError:
        console_err.print("[red]Not authenticated.[/red] Run 'hb login' first.")
        raise SystemExit(1)
    except APIError as e:
        console_err.print(f"[red]Error:[/red] {e}")
        raise SystemExit(1)


def _resolve_experiment_id(client: HumanboundClient, partial_id: str) -> str:
    """Resolve a partial experiment ID to full ID."""
    if len(partial_id) >= 32:
        return partial_id

    # Search recent experiments for match
    response = client.list_experiments(page=1, size=50)
    for exp in response.get("data", []):
        if exp.get("id", "").startswith(partial_id):
            return exp.get("id")

    # Not found, return as-is and let API handle error
    return partial_id


def _show_table(client: HumanboundClient, experiment_id: str, verdict: str, page: int, size: int):
    """Show logs in table format."""
    result_filter = None if verdict == "all" else verdict

    response = client.get_experiment_logs(
        experiment_id,
        page=page,
        size=size,
        result=result_filter,
    )
    logs = response.get("data", [])

    if not logs:
        console.print("[yellow]No logs found.[/yellow]")
        return

    table = Table(title=f"Experiment Logs (page {page})")
    table.add_column("ID", style="dim", width=10)
    table.add_column("Verdict", width=6)
    table.add_column("Severity", width=8)
    table.add_column("Category", width=15)
    table.add_column("Prompt", max_width=50)

    for log in logs:
        result_val = log.get("result", "")
        result_style = "[green]pass[/green]" if result_val == "pass" else "[red]fail[/red]"

        severity = log.get("severity", "")
        severity_style = {
            "critical": "[red bold]critical[/red bold]",
            "high": "[red]high[/red]",
            "medium": "[yellow]medium[/yellow]",
            "low": "[blue]low[/blue]",
        }.get(str(severity).lower(), str(severity))

        table.add_row(
            log.get("id", ""),
            result_style,
            severity_style if result_val == "fail" else "",
            log.get("fail_category") or log.get("gen_category") or "",
            (log.get("prompt", "") or "")[:50],
        )

    console.print(table)

    total = response.get("total", 0)
    if response.get("has_next_page"):
        console.print(f"\n[dim]Showing {len(logs)} of {total}. Use --page to see more.[/dim]")


def _export_json(client: HumanboundClient, experiment_id: str, output: str, verdict: str, fetch_all: bool, page: int, size: int):
    """Export logs as JSON."""
    result_filter = None if verdict == "all" else verdict

    all_logs = []

    if fetch_all:
        # Fetch all pages
        current_page = 1
        while True:
            response = client.get_experiment_logs(
                experiment_id,
                page=current_page,
                size=100,
                result=result_filter,
            )
            logs = response.get("data", [])
            all_logs.extend(logs)

            if not response.get("has_next_page"):
                break
            current_page += 1
    else:
        response = client.get_experiment_logs(
            experiment_id,
            page=page,
            size=size,
            result=result_filter,
        )
        all_logs = response.get("data", [])

    # Get experiment info for context
    experiment = client.get_experiment(experiment_id)

    export_data = {
        "experiment": {
            "id": experiment.get("id"),
            "name": experiment.get("name"),
            "status": experiment.get("status"),
            "test_category": experiment.get("test_category"),
            "testing_level": experiment.get("testing_level"),
            "created_at": experiment.get("created_at"),
        },
        "results": experiment.get("results", {}),
        "logs": all_logs,
        "total_logs": len(all_logs),
    }

    json_output = json.dumps(export_data, indent=2, default=str)

    if output:
        Path(output).write_text(json_output)
        console.print(f"[green]JSON exported to:[/green] {output}")
    else:
        print(json_output)


def _export_html(client: HumanboundClient, experiment_id: str, output: str):
    """Export logs as HTML report."""
    with console.status("Generating HTML report...", spinner="dots"):
        experiment = client.get_experiment(experiment_id)

        # Fetch all logs
        all_logs = []
        page = 1
        while True:
            resp = client.get_experiment_logs(experiment_id, page=page, size=100)
            all_logs.extend(resp.get("data", []))
            if not resp.get("has_next_page"):
                break
            page += 1

        from ..report import generate_html_report
        report_html = generate_html_report(experiment, all_logs)

    filename = output or f"experiment_{experiment_id[:8]}_report.html"
    Path(filename).write_text(report_html)
    console.print(f"[green]HTML report exported to:[/green] {filename}")
