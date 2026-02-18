"""Inventory management commands for Shadow AI Discovery."""

import json

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Confirm

from ..client import HumanboundClient
from ..exceptions import NotAuthenticatedError, APIError

console = Console()

RISK_STYLES = {
    "critical": "[red bold]CRITICAL[/red bold]",
    "high": "[red]HIGH[/red]",
    "medium": "[yellow]MEDIUM[/yellow]",
    "low": "[cyan]LOW[/cyan]",
    "unknown": "[dim]UNKNOWN[/dim]",
}

CATEGORY_STYLES = {
    "AC-1": "[blue]Copilot[/blue]",
    "AC-2": "[cyan]AI Platform[/cyan]",
    "AC-3": "[green]ML/Data[/green]",
    "AC-4": "[magenta]AI Dev Tool[/magenta]",
    "AC-5": "[yellow]AI Assistant[/yellow]",
    "AC-6": "[red]AI Agent[/red]",
    "AC-7": "[blue]AI API[/blue]",
    "AC-8": "[cyan]AI Infra[/cyan]",
    "AC-9": "[dim]Other AI[/dim]",
}


def _require_client() -> HumanboundClient:
    """Return an authenticated client with an org selected, or exit."""
    client = HumanboundClient()
    if not client.is_authenticated():
        console.print("[red]Not authenticated.[/red] Run 'hb login' first.")
        raise SystemExit(1)
    if not client.organisation_id:
        console.print("[yellow]No organisation selected.[/yellow]")
        console.print("Use 'hb switch <org-id>' first.")
        raise SystemExit(1)
    return client


def _score_color(score) -> str:
    """Return a Rich color name based on posture score."""
    if score is None:
        return "dim"
    score = float(score)
    if score >= 80:
        return "green"
    elif score >= 60:
        return "yellow"
    return "red"


def _score_bar(score, width: int = 20) -> str:
    """Create a visual score bar."""
    if score is None:
        return "[dim]" + "░" * width + "[/dim]"
    score = float(score)
    filled = int(score / 100 * width)
    empty = width - filled
    color = _score_color(score)
    return f"[{color}]{'█' * filled}[/{color}][dim]{'░' * empty}[/dim]"


def _score_to_grade(score: float) -> str:
    """Convert numeric score to letter grade."""
    if score >= 90:
        return "A"
    elif score >= 80:
        return "B"
    elif score >= 70:
        return "C"
    elif score >= 60:
        return "D"
    return "F"


def _format_threats(threats) -> str:
    """Format triggered threats as a compact string."""
    if not threats:
        return "[dim]-[/dim]"
    if isinstance(threats, str):
        return threats
    labels = []
    for t in threats[:3]:
        if isinstance(t, dict):
            labels.append(t.get("threat_class", t.get("id", "")))
        else:
            labels.append(str(t))
    result = ", ".join(labels)
    if len(threats) > 3:
        result += f" (+{len(threats) - 3})"
    return result


def _resolve_asset_id(client: HumanboundClient, partial_id: str) -> str:
    """Resolve a partial asset ID to full ID."""
    if len(partial_id) >= 32:
        return partial_id

    response = client.list_inventory(page=1, size=100)
    assets = response.get("data", []) if isinstance(response, dict) else response
    for asset in assets:
        if asset.get("id", "").startswith(partial_id):
            return asset.get("id")

    return partial_id


# =============================================================================
# Command Group
# =============================================================================


@click.group("inventory", invoke_without_command=True)
@click.option("--category", default=None, help="Filter by asset category")
@click.option("--vendor", default=None, help="Filter by vendor")
@click.option("--risk-level", type=click.Choice(["critical", "high", "medium", "low"]), default=None, help="Filter by risk level")
@click.option("--sanctioned/--unsanctioned", default=None, help="Filter by sanctioned status")
@click.option("--page", default=1, help="Page number")
@click.option("--size", default=50, help="Items per page")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@click.option("--report", "report_path", is_flag=False, flag_value="auto", default=None,
              help="Export as branded HTML report (optionally pass a filename)")
@click.pass_context
def inventory_group(ctx, category, vendor, risk_level, sanctioned, page, size, as_json, report_path):
    """View and manage discovered AI inventory.

    \b
    Examples:
      hb inventory                           # List all assets
      hb inventory --report                  # Export HTML report
      hb inventory --risk-level critical     # Filter by risk
      hb inventory --sanctioned              # Show sanctioned only
      hb inventory --json                    # JSON output
      hb inventory view <id>                 # Detailed asset view
      hb inventory posture                   # Shadow AI posture

    Use 'hb discover --save' to discover and persist AI assets.
    """
    if ctx.invoked_subcommand is not None:
        return

    client = _require_client()

    try:
        with console.status("Fetching inventory..."):
            response = client.list_inventory(
                category=category,
                vendor=vendor,
                risk_level=risk_level,
                is_sanctioned=sanctioned,
                page=page,
                size=size,
            )

        if as_json:
            print(json.dumps(response, indent=2, default=str))
            return

        assets = response.get("data", []) if isinstance(response, dict) else response

        if not assets:
            console.print("[yellow]No inventory assets found.[/yellow]")
            console.print("[dim]Run 'hb discover --save' to discover and persist AI assets.[/dim]")
            return

        table = Table(title="AI Inventory")
        table.add_column("ID", style="dim", no_wrap=True)
        table.add_column("Name", max_width=30)
        table.add_column("Category", width=14)
        table.add_column("Vendor", width=12)
        table.add_column("Risk", width=10)
        table.add_column("Sanctioned", width=10, justify="center")
        table.add_column("Posture", width=8, justify="right")

        for asset in assets:
            risk = str(asset.get("risk_level", "unknown")).lower()
            cat = asset.get("category", "")
            cat_display = CATEGORY_STYLES.get(cat, cat)
            sanctioned_val = asset.get("is_sanctioned")
            if sanctioned_val is True:
                sanctioned_str = "[green]yes[/green]"
            elif sanctioned_val is False:
                sanctioned_str = "[red]no[/red]"
            else:
                sanctioned_str = "[dim]-[/dim]"

            posture_score = asset.get("posture_score")
            if posture_score is not None:
                color = _score_color(posture_score)
                posture_str = f"[{color}]{posture_score:.0f}[/{color}]"
            else:
                posture_str = "[dim]-[/dim]"

            table.add_row(
                str(asset.get("id", "")),
                asset.get("name", ""),
                cat_display,
                asset.get("vendor", ""),
                RISK_STYLES.get(risk, risk),
                sanctioned_str,
                posture_str,
            )

        console.print(table)

        total = response.get("total", 0) if isinstance(response, dict) else len(assets)
        has_next = response.get("has_next_page", False) if isinstance(response, dict) else False
        if total:
            console.print(f"\n[dim]{total} total assets. Page {page}.[/dim]")
        if has_next:
            console.print(f"[dim]Use --page {page + 1} to see more.[/dim]")

        # HTML report export
        if report_path is not None:
            _export_inventory_report(assets, total, report_path)

    except NotAuthenticatedError:
        console.print("[red]Not authenticated.[/red] Run 'hb login' first.")
        raise SystemExit(1)
    except APIError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise SystemExit(1)


# =============================================================================
# View
# =============================================================================


@inventory_group.command("view")
@click.argument("asset_id")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@click.option("--report", "report_path", is_flag=False, flag_value="auto", default=None,
              help="Export as branded HTML report (optionally pass a filename)")
def view_asset(asset_id, as_json, report_path):
    """View detailed information about an inventory asset.

    ASSET_ID: Asset UUID (or partial ID).
    """
    client = _require_client()

    try:
        asset_id = _resolve_asset_id(client, asset_id)

        with console.status("Fetching asset..."):
            asset = client.get_inventory_asset(asset_id)

        if as_json:
            print(json.dumps(asset, indent=2, default=str))
            return

        # General info panel
        risk = str(asset.get("risk_level", "unknown")).lower()
        cat = asset.get("category", "")

        info_lines = [
            f"[bold]{asset.get('name', 'Unknown')}[/bold]\n",
            f"  Vendor:     {asset.get('vendor', '-')}",
            f"  Category:   {CATEGORY_STYLES.get(cat, cat)}",
            f"  Risk:       {RISK_STYLES.get(risk, risk)}",
            f"  Resource ID: [dim]{asset.get('resource_id', '-')}[/dim]",
            f"  [dim]ID: {asset.get('id', '')}[/dim]",
        ]

        sanctioned_val = asset.get("is_sanctioned")
        if sanctioned_val is True:
            info_lines.append("  Sanctioned: [green]Yes[/green]")
        elif sanctioned_val is False:
            info_lines.append("  Sanctioned: [red]No[/red]")

        posture_score = asset.get("posture_score")
        if posture_score is not None:
            color = _score_color(posture_score)
            info_lines.append(f"  Posture:    [{color}]{posture_score:.0f}/100[/{color}]")

        console.print(Panel(
            "\n".join(info_lines),
            title="Asset Details",
            border_style="blue",
            padding=(1, 2),
        ))

        # Governance section
        gov_fields = [
            ("Owner", asset.get("business_owner") or asset.get("technical_owner")),
            ("Department", asset.get("organisation_unit")),
            ("Business Purpose", asset.get("business_process") or asset.get("intended_use")),
            ("Has Policy", asset.get("has_policy")),
            ("Has Risk Assessment", asset.get("has_risk_assessment")),
            ("Data Sensitivity", asset.get("data_sensitivity")),
            ("Criticality", asset.get("criticality")),
        ]
        gov_lines = []
        for label, val in gov_fields:
            if val is not None and val != "":
                if isinstance(val, bool):
                    val = "[green]Yes[/green]" if val else "[red]No[/red]"
                gov_lines.append(f"  {label}: {val}")

        if gov_lines:
            console.print("\n[bold]Governance:[/bold]")
            console.print("\n".join(gov_lines))

        # Triggered threats
        threats = asset.get("triggered_threats", [])
        if threats:
            console.print("\n[bold]Triggered Threats:[/bold]\n")
            threat_table = Table(show_header=True, header_style="bold")
            threat_table.add_column("Threat Class", width=12)
            threat_table.add_column("Description", max_width=40)
            threat_table.add_column("Risk", width=10)

            for t in threats:
                if isinstance(t, dict):
                    t_risk = str(t.get("risk_level", t.get("severity", ""))).lower()
                    threat_table.add_row(
                        t.get("threat_class", t.get("id", "")),
                        t.get("description", t.get("title", "")),
                        RISK_STYLES.get(t_risk, t_risk),
                    )

            console.print(threat_table)

        # Evidence signals
        evidence = asset.get("evidence_signals", [])
        if evidence:
            console.print(f"\n[bold]Evidence Signals:[/bold] [dim]{len(evidence)} signal(s)[/dim]")
            for sig in evidence[:10]:
                if isinstance(sig, dict):
                    console.print(f"  [dim]-[/dim] {sig.get('signal', sig.get('name', str(sig)))}")
                else:
                    console.print(f"  [dim]-[/dim] {sig}")

        # Governance gaps
        gaps = asset.get("governance_gaps", [])
        if gaps:
            console.print(f"\n[bold]Governance Gaps:[/bold]")
            for gap in gaps:
                if isinstance(gap, dict):
                    console.print(f"  [yellow]![/yellow] {gap.get('description', gap.get('gap', str(gap)))}")
                else:
                    console.print(f"  [yellow]![/yellow] {gap}")

        # HTML report export
        if report_path is not None:
            _export_asset_report(asset, report_path)

    except NotAuthenticatedError:
        console.print("[red]Not authenticated.[/red] Run 'hb login' first.")
        raise SystemExit(1)
    except APIError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise SystemExit(1)


# =============================================================================
# Update
# =============================================================================


@inventory_group.command("update")
@click.argument("asset_id")
@click.option("--sanctioned/--unsanctioned", default=None, help="Mark as sanctioned or unsanctioned")
@click.option("--owner", default=None, help="Business owner name or email")
@click.option("--department", default=None, help="Organisation unit / department")
@click.option("--business-purpose", default=None, help="Business purpose or intended use")
@click.option("--has-policy/--no-policy", default=None, help="Has usage policy")
@click.option("--has-risk-assessment/--no-risk-assessment", default=None, help="Has risk assessment")
def update_asset(asset_id, sanctioned, owner, department, business_purpose, has_policy, has_risk_assessment):
    """Update governance fields on an inventory asset.

    ASSET_ID: Asset UUID (or partial ID).

    \b
    Examples:
      hb inventory update <id> --sanctioned --owner "security@corp.com"
      hb inventory update <id> --unsanctioned --has-policy
      hb inventory update <id> --department "Engineering" --business-purpose "Customer support"
    """
    client = _require_client()

    data = {}
    if sanctioned is not None:
        data["is_sanctioned"] = sanctioned
    if owner:
        data["business_owner"] = owner
        data["has_owner"] = True
    if department:
        data["organisation_unit"] = department
    if business_purpose:
        data["intended_use"] = business_purpose
    if has_policy is not None:
        data["has_policy"] = has_policy
    if has_risk_assessment is not None:
        data["has_risk_assessment"] = has_risk_assessment

    if not data:
        console.print("[yellow]Nothing to update.[/yellow] Provide at least one option.")
        raise SystemExit(1)

    try:
        asset_id = _resolve_asset_id(client, asset_id)

        with console.status("Updating asset..."):
            client.update_inventory_asset(asset_id, data)

        console.print("[green]Asset updated.[/green]")
        console.print(f"[dim]ID: {asset_id}[/dim]")
        for key, val in data.items():
            display_key = key.replace("_", " ").title()
            if isinstance(val, bool):
                val = "[green]Yes[/green]" if val else "[red]No[/red]"
            console.print(f"  {display_key}: {val}")

    except NotAuthenticatedError:
        console.print("[red]Not authenticated.[/red] Run 'hb login' first.")
        raise SystemExit(1)
    except APIError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise SystemExit(1)


# =============================================================================
# Archive
# =============================================================================


@inventory_group.command("archive")
@click.argument("asset_id")
@click.option("--force", is_flag=True, help="Skip confirmation prompt")
def archive_asset(asset_id, force):
    """Archive an inventory asset.

    ASSET_ID: Asset UUID (or partial ID).
    """
    client = _require_client()

    try:
        asset_id = _resolve_asset_id(client, asset_id)

        if not force:
            if not Confirm.ask(f"Archive asset [bold]{asset_id}[/bold]?"):
                console.print("[dim]Cancelled.[/dim]")
                return

        with console.status("Archiving asset..."):
            client.archive_inventory_asset(asset_id)

        console.print("[green]Asset archived.[/green]")
        console.print(f"[dim]ID: {asset_id}[/dim]")

    except NotAuthenticatedError:
        console.print("[red]Not authenticated.[/red] Run 'hb login' first.")
        raise SystemExit(1)
    except APIError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise SystemExit(1)


# =============================================================================
# Posture
# =============================================================================


@inventory_group.command("posture")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@click.option("--report", "report_path", is_flag=False, flag_value="auto", default=None,
              help="Export posture as branded HTML report")
def shadow_posture(as_json, report_path):
    """View Shadow AI posture for the organisation.

    Displays the overall posture score based on discovered inventory
    assets, their risk levels, and governance status.

    \b
    Examples:
      hb inventory posture
      hb inventory posture --report
      hb inventory posture --json
    """
    client = _require_client()

    try:
        with console.status("Calculating shadow AI posture..."):
            result = client.get_shadow_posture()

        if as_json:
            print(json.dumps(result, indent=2, default=str))
            return

        score = result.get("score", 0)
        grade = result.get("grade", _score_to_grade(score))
        color = _score_color(score)

        # Main score panel
        total_assets = result.get("total_assets", 0)
        shadow_count = result.get("shadow_count", result.get("unsanctioned_count", 0))
        sanctioned_count = result.get("sanctioned_count", 0)

        panel_lines = [
            f"[bold {color}]{score:.0f}/100[/bold {color}]  [dim]Grade: {grade}[/dim]\n",
            f"  {_score_bar(score, 30)}\n",
            f"  Total assets:     [bold]{total_assets}[/bold]",
            f"  Sanctioned:       [green]{sanctioned_count}[/green]",
            f"  Shadow (unvetted): [yellow]{shadow_count}[/yellow]",
        ]

        console.print(Panel(
            "\n".join(panel_lines),
            title="Shadow AI Posture",
            border_style=color,
            padding=(1, 2),
        ))

        # Risk domain breakdown
        domains = result.get("domains", result.get("risk_domains", {}))
        if domains and isinstance(domains, dict):
            console.print("\n[bold]Risk Domain Breakdown:[/bold]\n")

            domain_table = Table(show_header=True, header_style="bold")
            domain_table.add_column("Domain", width=25)
            domain_table.add_column("Score", width=8, justify="right")
            domain_table.add_column("Bar", width=22)

            for domain_name, domain_data in domains.items():
                d_score = domain_data if isinstance(domain_data, (int, float)) else domain_data.get("score", 0)
                d_color = _score_color(d_score)
                domain_table.add_row(
                    domain_name.replace("_", " ").title(),
                    f"[{d_color}]{d_score:.0f}[/{d_color}]",
                    _score_bar(d_score, 18),
                )

            console.print(domain_table)

        # Risk level summary
        by_risk = result.get("by_risk", result.get("risk_summary", {}))
        if by_risk and isinstance(by_risk, dict):
            console.print("\n[bold]Assets by Risk Level:[/bold]")
            for level in ["critical", "high", "medium", "low", "unknown"]:
                count = by_risk.get(level, 0)
                if count:
                    console.print(f"  {RISK_STYLES.get(level, level)}: {count}")

        # HTML report export
        if report_path is not None:
            _export_posture_report(result, report_path)

    except NotAuthenticatedError:
        console.print("[red]Not authenticated.[/red] Run 'hb login' first.")
        raise SystemExit(1)
    except APIError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise SystemExit(1)


# =============================================================================
# Onboard
# =============================================================================


@inventory_group.command("onboard")
@click.argument("asset_id")
@click.option("--name", default=None, help="Project name override")
@click.option("--force", is_flag=True, help="Skip confirmation prompt")
def onboard_asset(asset_id, name, force):
    """Create a security testing project from an inventory asset.

    Onboards a discovered AI asset into the testing pipeline by creating
    a project linked to it.

    ASSET_ID: Asset UUID (or partial ID).

    \b
    Examples:
      hb inventory onboard <id>
      hb inventory onboard <id> --name "My Bot Security Test"
    """
    client = _require_client()

    try:
        asset_id = _resolve_asset_id(client, asset_id)

        # Fetch asset details for confirmation
        with console.status("Fetching asset..."):
            asset = client.get_inventory_asset(asset_id)

        asset_name = asset.get("name", "Unknown")
        project_name = name or f"Security Test — {asset_name}"

        if not force:
            console.print(f"\nOnboard [bold]{asset_name}[/bold] as a testing project.")
            console.print(f"Project name: [cyan]{project_name}[/cyan]")
            if not Confirm.ask("\nProceed?"):
                console.print("[dim]Cancelled.[/dim]")
                return

        with console.status("Creating project from asset..."):
            result = client.onboard_inventory_asset(asset_id, project_name=name)

        project_id = result.get("project_id", "")

        console.print(Panel(
            f"[bold green]Asset onboarded[/bold green]\n\n"
            f"  Asset:    {asset_name}\n"
            f"  Project:  [cyan]{result.get('name', project_name)}[/cyan]\n"
            f"  [dim]Project ID: {project_id}[/dim]\n"
            f"  [dim]Asset ID:   {asset_id}[/dim]",
            border_style="green",
            padding=(1, 2),
        ))

        console.print(f"\nTo start testing: [bold]hb projects use {project_id}[/bold]")

    except NotAuthenticatedError:
        console.print("[red]Not authenticated.[/red] Run 'hb login' first.")
        raise SystemExit(1)
    except APIError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise SystemExit(1)


# =============================================================================
# Report helpers
# =============================================================================

RISK_BADGE_HTML = {
    "critical": '<span class="badge badge-error">CRITICAL</span>',
    "high": '<span class="badge badge-error" style="opacity:.8">HIGH</span>',
    "medium": '<span class="badge badge-warning">MEDIUM</span>',
    "low": '<span class="badge badge-good">LOW</span>',
    "unknown": '<span class="badge badge-neutral">UNKNOWN</span>',
}

CATEGORY_LABELS = {
    "AC-1": "Copilot",
    "AC-2": "AI Platform",
    "AC-3": "ML/Data",
    "AC-4": "AI Dev Tool",
    "AC-5": "AI Assistant",
    "AC-6": "AI Agent",
    "AC-7": "AI API",
    "AC-8": "AI Infra",
    "AC-9": "Other AI",
}


def _posture_html(score) -> str:
    """Return coloured posture score HTML."""
    if score is None:
        return '<span style="color:var(--text-dim)">-</span>'
    score = float(score)
    if score >= 75:
        color = "var(--success)"
    elif score >= 50:
        color = "var(--warning)"
    else:
        color = "var(--error)"
    return f'<span style="color:{color};font-weight:700">{score:.0f}</span>'


def _inv_build_rows(assets: list, _esc) -> list:
    """Build HTML table rows [ID, Name, Category, Vendor, Risk, Posture] for inventory assets."""
    rows = []
    for asset in assets:
        risk = str(asset.get("risk_level", "unknown")).lower()
        cat = asset.get("category", "")
        rows.append([
            _esc(str(asset.get("id", ""))),
            _esc(asset.get("name", "")),
            _esc(CATEGORY_LABELS.get(cat, cat)),
            _esc(asset.get("vendor", "")),
            RISK_BADGE_HTML.get(risk, _esc(risk)),
            _posture_html(asset.get("posture_score")),
        ])
    return rows


def _inv_generate_actions(shadow_list: list, by_risk: dict, gov_incomplete: int, total: int) -> list:
    """Auto-generate prioritised actions from inventory state."""
    actions = []
    critical = by_risk.get("critical", 0)

    if critical > 0:
        actions.append({
            "title": f"Remediate {critical} critical-risk asset{'s' if critical != 1 else ''}",
            "description": (
                "These assets have critical security gaps. Review their triggered threats "
                "and apply security controls immediately."
            ),
            "effort": "quick",
        })

    if shadow_list:
        actions.append({
            "title": f"Govern {len(shadow_list)} unsanctioned AI tool{'s' if len(shadow_list) != 1 else ''}",
            "description": (
                "Shadow AI tools lack formal approval. Assign ownership, evaluate risk, "
                "and either sanction or retire each tool."
            ),
            "effort": "moderate",
        })

    high = by_risk.get("high", 0)
    if high > 0:
        actions.append({
            "title": f"Review {high} high-risk asset{'s' if high != 1 else ''}",
            "description": (
                "Elevated risk from broad capabilities or data access. Investigate "
                "configurations and consider access restrictions."
            ),
            "effort": "moderate",
        })

    if gov_incomplete > 0:
        actions.append({
            "title": f"Complete governance for {gov_incomplete} asset{'s' if gov_incomplete != 1 else ''}",
            "description": (
                "These assets are missing ownership, usage policies, or risk assessments. "
                "Use <code>hb inventory update &lt;id&gt;</code> to fill governance fields."
            ),
            "effort": "moderate",
        })

    actions.append({
        "title": "Maintain continuous discovery",
        "description": (
            "Run discovery scans regularly to detect new shadow AI adoption "
            "and track posture improvements over time."
        ),
        "effort": "quick",
    })

    return actions[:5]


def _export_inventory_report(assets: list, total: int, report_path) -> None:
    from ..report_builder import ReportBuilder, _esc

    rb = ReportBuilder("AI Inventory", f"{total} assets discovered")

    # ── Aggregates ───────────────────────────────────────────────────
    sanctioned_list = [a for a in assets if a.get("is_sanctioned") is True]
    shadow_list = [a for a in assets if a.get("is_sanctioned") is False]
    unclassified = [a for a in assets if a.get("is_sanctioned") is None]

    by_risk = {}
    for a in assets:
        r = str(a.get("risk_level", "")).lower() or "unknown"
        by_risk[r] = by_risk.get(r, 0) + 1
    critical = by_risk.get("critical", 0)
    high = by_risk.get("high", 0)

    scores = [a.get("posture_score") for a in assets if a.get("posture_score") is not None]
    avg_posture = sum(scores) / len(scores) if scores else 0
    grade = _score_to_grade(avg_posture)

    gov_incomplete = sum(
        1 for a in assets
        if not (a.get("business_owner") or a.get("technical_owner"))
        or not a.get("has_policy")
    )

    # ── 1. Hero ──────────────────────────────────────────────────────
    if shadow_list and critical:
        verdict = (
            f"Your inventory contains <strong>{total}</strong> AI assets. "
            f"<strong style='color:var(--error)'>{len(shadow_list)} are unsanctioned shadow AI</strong>, "
            f"with <strong>{critical} critical</strong> risk{'s' if critical != 1 else ''}."
        )
    elif shadow_list:
        verdict = (
            f"Your inventory contains <strong>{total}</strong> AI assets. "
            f"<strong style='color:var(--warning)'>{len(shadow_list)} are unsanctioned</strong> "
            f"and require governance review."
        )
    elif critical:
        verdict = (
            f"Your inventory contains <strong>{total}</strong> AI assets. "
            f"<strong style='color:var(--error)'>{critical} have critical security gaps</strong>."
        )
    else:
        verdict = (
            f"Your inventory contains <strong>{total}</strong> AI assets "
            f"with no critical risks identified."
        )

    rb.add_hero(avg_posture, grade, verdict, metrics={
        "Total Assets": total,
        "Sanctioned": len(sanctioned_list),
        "Shadow AI": len(shadow_list),
        "Critical": critical,
    })

    # ── 2. Executive Summary ─────────────────────────────────────────
    exec_parts = [f"The organisation's AI inventory contains <strong>{total} assets</strong>."]
    if sanctioned_list:
        exec_parts.append(f"<strong>{len(sanctioned_list)}</strong> are formally sanctioned.")
    if shadow_list:
        pct = (len(shadow_list) / total * 100) if total else 0
        exec_parts.append(
            f"<strong>{len(shadow_list)} ({pct:.0f}%)</strong> are unsanctioned shadow AI "
            f"operating without formal governance."
        )
    if critical or high:
        exec_parts.append(
            f"<strong>{critical + high}</strong> asset{'s' if (critical + high) != 1 else ''} "
            f"present elevated risk and should be prioritised for review."
        )
    if gov_incomplete:
        exec_parts.append(
            f"{gov_incomplete} asset{'s' if gov_incomplete != 1 else ''} "
            f"{'are' if gov_incomplete != 1 else 'is'} missing ownership or usage policies."
        )
    rb.add_executive_summary(" ".join(exec_parts))

    # ── 3. Risk Heatmap ──────────────────────────────────────────────
    if total > 0:
        rb.add_heatmap("Risk Distribution", by_risk)

    # ── 4. Segmented tables ──────────────────────────────────────────
    if shadow_list:
        rb.add_table(
            f"Shadow AI — Requires Action ({len(shadow_list)})",
            columns=["ID", "Name", "Category", "Vendor", "Risk", "Posture"],
            rows=_inv_build_rows(shadow_list, _esc),
        )

    if sanctioned_list:
        rb.add_table(
            f"Sanctioned AI — Monitored ({len(sanctioned_list)})",
            columns=["ID", "Name", "Category", "Vendor", "Risk", "Posture"],
            rows=_inv_build_rows(sanctioned_list, _esc),
        )

    if unclassified:
        rb.add_table(
            f"Unclassified ({len(unclassified)})",
            columns=["ID", "Name", "Category", "Vendor", "Risk", "Posture"],
            rows=_inv_build_rows(unclassified, _esc),
        )

    # ── 5. Prioritised Actions ───────────────────────────────────────
    actions = _inv_generate_actions(shadow_list, by_risk, gov_incomplete, total)
    if actions:
        rb.add_actions("Prioritised Actions", actions)

    # ── 6. Appendix ──────────────────────────────────────────────────
    from ..report_builder import STANDARDS_REFERENCE_HTML
    rb.add_appendix("Appendix: Methodology & References",
        "<p>This report was produced by the <code>hb inventory</code> CLI command. "
        "It presents a point-in-time snapshot of the organisation's AI asset inventory. "
        "Assets are populated through discovery scans that enumerate AI services in connected "
        "cloud environments. Each asset is evaluated against a security threat model. "
        "The posture score reflects the proportion and severity of identified risks. "
        "Governance fields are maintained by administrators.</p>"
        + STANDARDS_REFERENCE_HTML)

    saved = rb.save(None if report_path == "auto" else report_path)
    console.print(f"\n[green]Report saved:[/green] {saved}")


def _export_asset_report(asset: dict, report_path) -> None:
    from ..report_builder import ReportBuilder, _esc

    name = asset.get("name", "Unknown")
    risk = str(asset.get("risk_level", "unknown")).lower()
    cat = asset.get("category", "")
    sanctioned_val = asset.get("is_sanctioned")
    posture_score = asset.get("posture_score")
    threats = asset.get("triggered_threats", [])
    evidence = asset.get("evidence_signals", [])
    gaps = asset.get("governance_gaps", [])

    rb = ReportBuilder(f"Asset: {name}", "Detailed security report")

    # ── 1. Hero ──────────────────────────────────────────────────────
    score = float(posture_score) if posture_score is not None else 0
    grade = _score_to_grade(score) if posture_score is not None else "N/A"

    threat_count = len(threats) if isinstance(threats, list) else 0
    critical_threats = sum(
        1 for t in (threats or [])
        if isinstance(t, dict) and str(t.get("risk_level", t.get("severity", ""))).lower() in ("critical", "high")
    )

    if sanctioned_val is False and critical_threats:
        verdict = (
            f"<strong style='color:var(--error)'>Unsanctioned</strong> asset with "
            f"<strong>{critical_threats} critical/high threat{'s' if critical_threats != 1 else ''}</strong>. "
            f"Immediate governance and remediation required."
        )
    elif sanctioned_val is False:
        verdict = (
            f"<strong style='color:var(--warning)'>Unsanctioned</strong> asset — "
            f"no formal approval or governance in place. "
            f"{threat_count} threat{'s' if threat_count != 1 else ''} identified."
        )
    elif critical_threats:
        verdict = (
            f"Sanctioned asset with <strong style='color:var(--error)'>{critical_threats} "
            f"critical/high threat{'s' if critical_threats != 1 else ''}</strong> requiring remediation."
        )
    elif posture_score is not None and score >= 80:
        verdict = f"Asset is in good standing with a posture score of <strong>{score:.0f}</strong>."
    else:
        verdict = (
            f"{threat_count} threat{'s' if threat_count != 1 else ''} identified. "
            f"Review triggered threats and governance status below."
        )

    sanc_str = "Yes" if sanctioned_val is True else ("No" if sanctioned_val is False else "-")
    rb.add_hero(score, grade, verdict, metrics={
        "Risk Level": risk.upper(),
        "Threats": threat_count,
        "Sanctioned": sanc_str,
        "Category": CATEGORY_LABELS.get(cat, cat),
    })

    # ── 2. Executive Summary ─────────────────────────────────────────
    exec_parts = [f"<strong>{_esc(name)}</strong> is a {_esc(CATEGORY_LABELS.get(cat, cat))} asset"]
    vendor = asset.get("vendor", "")
    if vendor:
        exec_parts[-1] += f" from {_esc(vendor)}"
    exec_parts[-1] += "."

    if threat_count:
        exec_parts.append(
            f"Security evaluation identified <strong>{threat_count} threat{'s' if threat_count != 1 else ''}</strong>"
            + (f", of which <strong>{critical_threats}</strong> are critical or high severity." if critical_threats else ".")
        )
    if gaps:
        exec_parts.append(f"{len(gaps)} governance gap{'s' if len(gaps) != 1 else ''} need to be addressed.")
    if evidence:
        exec_parts.append(f"Assessment is based on {len(evidence)} evidence signal{'s' if len(evidence) != 1 else ''}.")
    rb.add_executive_summary(" ".join(exec_parts))

    # ── 3. Asset Overview ────────────────────────────────────────────
    rb.add_kv("Asset Overview", {
        "Name": name,
        "Vendor": vendor or "-",
        "Category": CATEGORY_LABELS.get(cat, cat),
        "Risk Level": risk.upper(),
        "Sanctioned": sanc_str,
        "Resource ID": asset.get("resource_id", "-"),
    })

    # ── 4. Governance ────────────────────────────────────────────────
    gov_fields = [
        ("Owner", asset.get("business_owner") or asset.get("technical_owner")),
        ("Department", asset.get("organisation_unit")),
        ("Business Purpose", asset.get("business_process") or asset.get("intended_use")),
        ("Has Policy", asset.get("has_policy")),
        ("Has Risk Assessment", asset.get("has_risk_assessment")),
        ("Data Sensitivity", asset.get("data_sensitivity")),
        ("Criticality", asset.get("criticality")),
    ]
    gov_items = []
    for label, val in gov_fields:
        if val is not None and val != "":
            if isinstance(val, bool):
                val_html = '<span class="badge badge-success">Yes</span>' if val else '<span class="badge badge-error">No</span>'
            else:
                val_html = _esc(str(val))
            gov_items.append(f"<strong>{_esc(label)}:</strong> {val_html}")
    if gov_items:
        rb.add_panel("Governance Status", "<br>".join(gov_items))

    # ── 5. Triggered Threats ─────────────────────────────────────────
    if threats:
        rows = []
        for t in threats:
            if isinstance(t, dict):
                t_risk = str(t.get("risk_level", t.get("severity", ""))).lower()
                # Include framework mapping if available
                mappings = t.get("external_mappings", {})
                mapping_parts = []
                for framework in ("owasp_llm", "mitre_atlas", "eu_ai_act", "nist_ai_rmf"):
                    refs = mappings.get(framework)
                    if refs:
                        if isinstance(refs, list):
                            if isinstance(refs[0], dict):
                                mapping_parts.append(f"{framework.replace('_', ' ').upper()}: {refs[0].get('id', '')}")
                            else:
                                mapping_parts.append(f"{framework.replace('_', ' ').upper()}: {refs[0]}")
                mapping_str = f'<br><span style="font-size:.75rem;color:var(--text-dim)">{" | ".join(mapping_parts)}</span>' if mapping_parts else ""

                rows.append([
                    _esc(t.get("threat_class", t.get("id", ""))),
                    _esc(t.get("description", t.get("title", ""))) + mapping_str,
                    RISK_BADGE_HTML.get(t_risk, _esc(t_risk)),
                ])
        if rows:
            rb.add_table("Triggered Threats", columns=["Threat Class", "Description", "Risk"], rows=rows)

    # ── 6. Evidence Signals ──────────────────────────────────────────
    if evidence:
        items = []
        for sig in evidence:
            if isinstance(sig, dict):
                items.append(_esc(sig.get("signal", sig.get("name", str(sig)))))
            else:
                items.append(_esc(str(sig)))
        rb.add_panel("Evidence Signals", "<br>".join(f"&bull; {i}" for i in items))

    # ── 7. Governance Gaps → Actions ─────────────────────────────────
    if gaps:
        actions = []
        for gap in gaps[:5]:
            desc = gap.get("description", gap.get("gap", str(gap))) if isinstance(gap, dict) else str(gap)
            actions.append({
                "title": _esc(desc[:80]),
                "description": _esc(desc) if len(desc) > 80 else "",
                "effort": "moderate",
            })
        rb.add_actions("Governance Actions Required", actions)

    # ── 8. Appendix ──────────────────────────────────────────────────
    from ..report_builder import STANDARDS_REFERENCE_HTML
    rb.add_appendix("Appendix: Methodology & References",
        "<p>This report was produced by the <code>hb inventory view</code> CLI command. "
        "The asset was discovered through a cloud environment scan and evaluated against "
        "a security threat model. 38 evidence signals across 7 categories (ownership, "
        "data handling, access control, safety controls, supply chain, observability, "
        "proliferation) inform the evaluation. Governance fields are maintained by administrators.</p>"
        + STANDARDS_REFERENCE_HTML)

    saved = rb.save(None if report_path == "auto" else report_path)
    console.print(f"\n[green]Report saved:[/green] {saved}")


def _export_posture_report(result: dict, report_path) -> None:
    from ..report_builder import ReportBuilder, _esc

    score = result.get("score", 0)
    grade = result.get("grade", _score_to_grade(score))

    total_assets = result.get("total_assets", 0)
    shadow_count = result.get("shadow_count", result.get("unsanctioned_count", 0))
    sanctioned_count = result.get("sanctioned_count", 0)

    domains = result.get("domains", result.get("risk_domains", {}))
    by_risk = result.get("by_risk", result.get("risk_summary", {}))
    previous = result.get("previous_score")
    previous_date = result.get("previous_date", "")

    rb = ReportBuilder("Shadow AI Posture", "Organisation posture assessment")

    # ── 1. Hero ──────────────────────────────────────────────────────
    if score >= 80:
        verdict = (
            f"Your organisation's shadow AI posture is <strong style='color:var(--success)'>healthy</strong>. "
            f"Score: <strong>{score:.0f}/100</strong> (Grade {grade})."
        )
    elif score >= 60:
        verdict = (
            f"Your shadow AI posture <strong style='color:var(--warning)'>needs attention</strong>. "
            f"Score: <strong>{score:.0f}/100</strong> (Grade {grade}). "
            f"Address critical findings to improve."
        )
    else:
        verdict = (
            f"Your shadow AI posture is <strong style='color:var(--error)'>at risk</strong>. "
            f"Score: <strong>{score:.0f}/100</strong> (Grade {grade}). "
            f"Immediate remediation required."
        )

    rb.add_hero(score, grade, verdict, metrics={
        "Total Assets": total_assets,
        "Sanctioned": sanctioned_count,
        "Shadow AI": shadow_count,
        "Grade": grade,
    })

    # ── 2. Executive Summary ─────────────────────────────────────────
    exec_parts = [
        f"The organisation manages <strong>{total_assets} AI assets</strong> — "
        f"{sanctioned_count} sanctioned, {shadow_count} unsanctioned shadow AI."
    ]
    if by_risk:
        critical = by_risk.get("critical", 0)
        high = by_risk.get("high", 0)
        if critical or high:
            exec_parts.append(
                f"<strong>{critical + high} asset{'s' if (critical + high) != 1 else ''}</strong> "
                f"are at elevated risk."
            )
    if domains and isinstance(domains, dict):
        worst = min(
            domains.items(),
            key=lambda x: x[1] if isinstance(x[1], (int, float)) else x[1].get("score", 100),
        )
        w_name = worst[0].replace("_", " ").title()
        w_score = worst[1] if isinstance(worst[1], (int, float)) else worst[1].get("score", 0)
        if w_score < 70:
            exec_parts.append(
                f"The weakest domain is <strong>{w_name}</strong> (score {w_score:.0f}), "
                f"which should be prioritised for improvement."
            )
    if previous is not None:
        delta = score - previous
        if delta > 0:
            exec_parts.append(f"Posture improved by {delta:.0f} points since the previous assessment.")
        elif delta < 0:
            exec_parts.append(
                f"Posture <strong style='color:var(--error)'>degraded by {abs(delta):.0f} points</strong> "
                f"since the previous assessment."
            )
    rb.add_executive_summary(" ".join(exec_parts))

    # ── 3. Trend ─────────────────────────────────────────────────────
    if previous is not None:
        rb.add_trend(score, previous, previous_date)

    # ── 4. Risk Domain Breakdown ─────────────────────────────────────
    if domains and isinstance(domains, dict):
        rows = []
        for domain_name, domain_data in domains.items():
            d_score = domain_data if isinstance(domain_data, (int, float)) else domain_data.get("score", 0)
            d_score = float(d_score)
            if d_score >= 75:
                score_color = "var(--success)"
            elif d_score >= 50:
                score_color = "var(--warning)"
            else:
                score_color = "var(--error)"

            # Visual bar in HTML
            filled_pct = min(d_score, 100)
            bar_html = (
                f'<div style="display:flex;align-items:center;gap:.5rem">'
                f'<span style="color:{score_color};font-weight:700;min-width:2rem">{d_score:.0f}</span>'
                f'<div style="flex:1;height:8px;background:var(--border);border-radius:4px;overflow:hidden">'
                f'<div style="width:{filled_pct:.0f}%;height:100%;background:{score_color};border-radius:4px"></div>'
                f'</div></div>'
            )
            rows.append([_esc(domain_name.replace("_", " ").title()), bar_html])
        rb.add_table("Risk Domain Breakdown", columns=["Domain", "Score"], rows=rows)

    # ── 5. Risk Heatmap ──────────────────────────────────────────────
    if by_risk and isinstance(by_risk, dict):
        rb.add_heatmap("Assets by Risk Level", by_risk)

    # ── 6. Prioritised Actions ───────────────────────────────────────
    actions = []
    if domains and isinstance(domains, dict):
        worst_domain = min(
            domains.items(),
            key=lambda x: x[1] if isinstance(x[1], (int, float)) else x[1].get("score", 100),
        )
        w_name = worst_domain[0].replace("_", " ").title()
        w_score = worst_domain[1] if isinstance(worst_domain[1], (int, float)) else worst_domain[1].get("score", 0)
        if w_score < 70:
            actions.append({
                "title": f"Strengthen {w_name}",
                "description": (
                    f"This domain scores {w_score:.0f}/100 — the lowest across your inventory. "
                    f"Review associated findings and apply recommended controls to improve posture."
                ),
                "effort": "moderate",
            })

    if by_risk and by_risk.get("critical", 0) > 0:
        actions.append({
            "title": f"Remediate {by_risk['critical']} critical-risk asset{'s' if by_risk['critical'] != 1 else ''}",
            "description": (
                "Critical-risk assets have the highest impact on posture score. "
                "Addressing these first yields the greatest improvement."
            ),
            "effort": "quick",
        })

    if shadow_count > 0:
        actions.append({
            "title": f"Govern {shadow_count} unsanctioned tool{'s' if shadow_count != 1 else ''}",
            "description": (
                "Assign ownership, apply usage policies, and formally sanction or retire each "
                "unsanctioned AI tool to reduce governance risk."
            ),
            "effort": "moderate",
        })

    actions.append({
        "title": "Track posture over time",
        "description": (
            "Run <code>hb inventory posture</code> regularly and compare trend data "
            "to verify that remediation efforts are improving the overall score."
        ),
        "effort": "quick",
    })

    rb.add_actions("Prioritised Actions", actions[:5])

    # ── 7. Appendix ──────────────────────────────────────────────────
    from ..report_builder import STANDARDS_REFERENCE_HTML
    rb.add_appendix("Appendix: Methodology & References",
        "<p>This report was produced by the <code>hb inventory posture</code> CLI command. "
        "The posture score is calculated as <code>100 &times; (1 &minus; severity_impact)</code> "
        "where severity_impact is derived from all security findings across discovered AI assets. "
        "Domain scores reflect the subset of findings in each risk category. "
        "Grades: A (&ge;90), B (&ge;80), C (&ge;70), D (&ge;60), F (&lt;60).</p>"
        + STANDARDS_REFERENCE_HTML)

    saved = rb.save(None if report_path == "auto" else report_path)
    console.print(f"\n[green]Report saved:[/green] {saved}")
