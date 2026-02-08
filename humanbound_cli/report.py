"""Humanbound-branded HTML experiment report generator."""

from html import escape
from datetime import datetime


def generate_html_report(experiment: dict, logs: list[dict]) -> str:
    """Generate a self-contained Humanbound-branded HTML report from experiment data.

    Args:
        experiment: Experiment object from GET /experiments/{id}.
        logs: List of log objects from GET /experiments/{id}/logs.

    Returns:
        Complete HTML document as a string.
    """
    results = experiment.get("results") or {}
    stats = results.get("stats") or {}
    exec_t = results.get("exec_t") or {}
    tests_data = (results.get("tests") or {}).get("data") or {}
    tests_evals = (results.get("tests") or {}).get("evals") or {}
    insights = results.get("insights") or []

    status = experiment.get("status", "unknown")
    name = experiment.get("name", "Untitled Experiment")
    test_category = experiment.get("test_category", "")
    testing_level = experiment.get("testing_level", "")
    lang = experiment.get("lang", "")
    created_at = experiment.get("created_at", "")

    total = stats.get("total", 0)
    passed = stats.get("pass", 0)
    failed = stats.get("fail", 0)
    tpi = stats.get("total_perfomance_index", 0)
    reliability = stats.get("reliability", 0)
    fail_impact = stats.get("fail_impact", 0)

    pass_rate = (passed / total * 100) if total > 0 else 0
    fail_rate = (failed / total * 100) if total > 0 else 0

    pass_rating = _get_pass_rating(pass_rate)
    is_finished = status.lower() in ("finished", "completed")

    generated_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    html_parts = [
        _html_head(name),
        '<body>',
        _header_section(name, status, test_category, testing_level, lang, created_at, generated_at),
    ]

    if is_finished and total > 0:
        html_parts.append(_health_overview(tpi, reliability, fail_impact))
        html_parts.append(_metric_cards(pass_rate, fail_rate, total, passed, failed, exec_t, pass_rating))
        if tests_evals or tests_data:
            html_parts.append(_threats_table(tests_evals, tests_data))
        if insights:
            html_parts.append(_insights_section(insights))
    elif not is_finished:
        html_parts.append(_status_banner(status))

    html_parts.append(_logs_section(logs))
    html_parts.append(_footer(generated_at))
    html_parts.append('</body></html>')

    return '\n'.join(html_parts)


def _get_pass_rating(pass_rate: float) -> tuple[str, str]:
    """Return (label, css_class) for pass rate badge."""
    if pass_rate >= 90:
        return ("Excellent", "badge-success")
    elif pass_rate >= 75:
        return ("Good", "badge-good")
    elif pass_rate >= 60:
        return ("Fair", "badge-warning")
    else:
        return ("Poor", "badge-error")


def _risk_level(fail_count: int) -> tuple[str, str]:
    """Return (label, css_class) for risk level based on fail count."""
    if fail_count >= 5:
        return ("Critical", "severity-critical")
    elif fail_count >= 3:
        return ("High", "severity-high")
    elif fail_count >= 1:
        return ("Medium", "severity-medium")
    else:
        return ("Low", "severity-low")


def _fmt(val, decimals=1) -> str:
    """Format a numeric value safely."""
    try:
        return f"{float(val):.{decimals}f}"
    except (TypeError, ValueError):
        return "0"


def _esc(val) -> str:
    """HTML-escape a value."""
    return escape(str(val)) if val is not None else ""


def _html_head(title: str) -> str:
    return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{_esc(title)} — Humanbound Report</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
:root{{
  --bg:#1E2323;--bg-card:#161b22;--bg-surface:#0d1117;
  --text:#E6EDF3;--text-secondary:#8B949E;--text-dim:#6e7681;
  --border:#30363D;--accent:#FD9506;
  --success:#3FB950;--warning:#F0C000;--error:#F85149;
  --good:#58a6ff;
  --font-sans:'Inter',ui-sans-serif,system-ui,-apple-system,sans-serif;
  --font-mono:'JetBrains Mono','SF Mono','Fira Code',monospace;
}}
body{{
  font-family:var(--font-sans);background:var(--bg);color:var(--text);
  line-height:1.6;min-height:100vh;
}}
.container{{max-width:1100px;margin:0 auto;padding:2rem 1.5rem}}
a{{color:var(--accent);text-decoration:none}}
a:hover{{text-decoration:underline}}

/* Header */
.report-header{{
  display:flex;align-items:center;gap:1.5rem;
  padding:1.5rem 2rem;background:var(--bg-card);
  border:1px solid var(--border);border-radius:12px;margin-bottom:1.5rem;
}}
.report-header img{{height:36px}}
.report-header h1{{font-size:1.25rem;font-weight:600;flex:1}}
.meta-row{{display:flex;gap:1.5rem;flex-wrap:wrap;margin-top:.5rem;font-size:.8rem;color:var(--text-secondary)}}
.meta-row span{{display:flex;align-items:center;gap:.35rem}}

/* Badges */
.badge{{
  display:inline-block;padding:.2rem .65rem;border-radius:20px;
  font-size:.75rem;font-weight:600;text-transform:uppercase;letter-spacing:.03em;
}}
.badge-success{{background:rgba(63,185,80,.15);color:var(--success);border:1px solid rgba(63,185,80,.3)}}
.badge-good{{background:rgba(88,166,255,.15);color:var(--good);border:1px solid rgba(88,166,255,.3)}}
.badge-warning{{background:rgba(240,192,0,.15);color:var(--warning);border:1px solid rgba(240,192,0,.3)}}
.badge-error{{background:rgba(248,81,73,.15);color:var(--error);border:1px solid rgba(248,81,73,.3)}}
.badge-neutral{{background:rgba(139,148,158,.15);color:var(--text-secondary);border:1px solid rgba(139,148,158,.3)}}
.badge-accent{{background:rgba(253,149,6,.15);color:var(--accent);border:1px solid rgba(253,149,6,.3)}}

/* Section */
.section{{margin-bottom:1.5rem}}
.section-title{{
  font-size:1rem;font-weight:600;margin-bottom:1rem;
  padding-bottom:.5rem;border-bottom:1px solid var(--border);
  display:flex;align-items:center;gap:.5rem;
}}

/* Health overview - donut + metrics */
.health-grid{{display:grid;grid-template-columns:200px 1fr;gap:1.5rem;align-items:center}}
.donut-container{{position:relative;width:160px;height:160px;margin:0 auto}}
.donut-container svg{{width:160px;height:160px;transform:rotate(-90deg)}}
.donut-container circle{{fill:none;stroke-width:14;stroke-linecap:round}}
.donut-bg{{stroke:var(--border)}}
.donut-fill{{transition:stroke-dashoffset .6s ease}}
.donut-label{{
  position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);
  text-align:center;
}}
.donut-label .value{{font-size:2rem;font-weight:700;line-height:1}}
.donut-label .label{{font-size:.7rem;color:var(--text-secondary);margin-top:.15rem}}
.health-metrics{{display:flex;flex-direction:column;gap:1rem}}
.health-metric{{
  display:flex;justify-content:space-between;align-items:center;
  padding:.75rem 1rem;background:var(--bg-card);
  border:1px solid var(--border);border-radius:8px;
}}
.health-metric .name{{font-size:.85rem;color:var(--text-secondary)}}
.health-metric .val{{font-size:1.1rem;font-weight:600}}

/* Metric cards */
.cards-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:1rem}}
.card{{
  padding:1.25rem;background:var(--bg-card);
  border:1px solid var(--border);border-radius:10px;
}}
.card .card-label{{font-size:.8rem;color:var(--text-secondary);margin-bottom:.35rem;display:flex;align-items:center;gap:.5rem}}
.card .card-value{{font-size:1.5rem;font-weight:700}}
.card .card-sub{{font-size:.8rem;color:var(--text-secondary);margin-top:.25rem}}

/* Tables */
table{{width:100%;border-collapse:collapse;font-size:.85rem}}
thead th{{
  text-align:left;padding:.6rem .75rem;
  background:var(--bg-surface);color:var(--text-secondary);
  font-weight:600;border-bottom:1px solid var(--border);
  font-size:.75rem;text-transform:uppercase;letter-spacing:.04em;
}}
tbody td{{padding:.6rem .75rem;border-bottom:1px solid var(--border)}}
tbody tr:hover{{background:rgba(255,255,255,.02)}}

/* Severity circles */
.severity-circle{{
  display:inline-flex;align-items:center;justify-content:center;
  width:42px;height:42px;border-radius:50%;font-size:.8rem;font-weight:700;
  flex-shrink:0;
}}
.severity-critical{{background:rgba(248,81,73,.15);color:var(--error);border:2px solid var(--error)}}
.severity-high{{background:rgba(248,81,73,.1);color:#ff7b72;border:2px solid #ff7b72}}
.severity-medium{{background:rgba(240,192,0,.12);color:var(--warning);border:2px solid var(--warning)}}
.severity-low{{background:rgba(63,185,80,.12);color:var(--success);border:2px solid var(--success)}}

/* Insights */
.insight-card{{
  padding:1.25rem;background:var(--bg-card);
  border:1px solid var(--border);border-radius:10px;margin-bottom:1rem;
}}
.insight-header{{display:flex;align-items:center;gap:1rem;margin-bottom:.75rem}}
.insight-header .title{{font-weight:600;flex:1}}
.insight-explanation{{color:var(--text-secondary);font-size:.85rem;line-height:1.7}}
.insight-examples{{margin-top:.75rem}}
.insight-examples summary{{
  cursor:pointer;font-size:.8rem;color:var(--accent);font-weight:500;
  list-style:none;
}}
.insight-examples summary::before{{content:"▸ ";transition:transform .2s}}
.insight-examples[open] summary::before{{content:"▾ "}}
.example-block{{
  margin-top:.5rem;padding:.75rem;background:var(--bg-surface);
  border:1px solid var(--border);border-radius:6px;
  font-family:var(--font-mono);font-size:.78rem;
  white-space:pre-wrap;word-break:break-word;
  color:var(--text-secondary);max-height:200px;overflow-y:auto;
}}

/* Logs */
.log-filters{{display:flex;gap:.5rem;margin-bottom:1rem;flex-wrap:wrap}}
.filter-btn{{
  padding:.3rem .75rem;border-radius:16px;border:1px solid var(--border);
  background:var(--bg-card);color:var(--text-secondary);
  cursor:pointer;font-size:.78rem;font-family:var(--font-sans);
}}
.filter-btn:hover,.filter-btn.active{{border-color:var(--accent);color:var(--accent)}}
.log-detail{{
  padding:.75rem;margin-top:.5rem;background:var(--bg-surface);
  border:1px solid var(--border);border-radius:6px;
}}
.log-detail .field-label{{font-size:.7rem;color:var(--text-dim);text-transform:uppercase;margin-bottom:.15rem}}
.log-detail .field-value{{font-size:.82rem;margin-bottom:.75rem;white-space:pre-wrap;word-break:break-word}}
.log-detail .field-value:last-child{{margin-bottom:0}}
details>summary{{cursor:pointer;list-style:none}}
details>summary::-webkit-details-marker{{display:none}}
.prompt-preview{{max-width:350px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}

/* Verdict cell */
.verdict-cell{{display:flex;flex-direction:column;gap:.2rem}}
.verdict-pill{{
  display:flex;align-items:center;gap:.4rem;
  padding:.3rem .7rem;border-radius:8px;font-size:.78rem;
}}
.verdict-pill.pill-pass{{background:rgba(63,185,80,.1);border:1px solid rgba(63,185,80,.25)}}
.verdict-pill.pill-fail{{background:rgba(248,81,73,.1);border:1px solid rgba(248,81,73,.25)}}
.verdict-dot{{width:8px;height:8px;border-radius:50%;flex-shrink:0}}
.verdict-dot.dot-pass{{background:var(--success)}}
.verdict-dot.dot-fail{{background:var(--error)}}
.verdict-label{{font-weight:600;text-transform:uppercase;letter-spacing:.03em}}
.verdict-pill.pill-pass .verdict-label{{color:var(--success)}}
.verdict-pill.pill-fail .verdict-label{{color:var(--error)}}
.verdict-meta{{font-size:.72rem;color:var(--text-dim);display:flex;align-items:center;gap:.6rem;margin-top:.3rem}}
.verdict-meta-item{{display:flex;align-items:center;gap:.25rem}}
.meta-label{{color:var(--text-dim);font-size:.65rem;text-transform:uppercase;letter-spacing:.04em}}
.verdict-meta .sev-tag{{
  padding:.1rem .4rem;border-radius:4px;font-weight:600;
  text-transform:uppercase;font-size:.65rem;letter-spacing:.03em;
}}
.sev-tag.tag-critical{{background:rgba(248,81,73,.15);color:var(--error)}}
.sev-tag.tag-high{{background:rgba(255,123,114,.12);color:#ff7b72}}
.sev-tag.tag-medium{{background:rgba(240,192,0,.12);color:var(--warning)}}
.sev-tag.tag-low{{background:rgba(63,185,80,.1);color:var(--success)}}

/* Threat list */
.threat-list{{display:flex;flex-wrap:wrap;gap:.5rem}}
.threat-item{{
  display:inline-flex;align-items:center;gap:.5rem;
  padding:.4rem .75rem;background:var(--bg-card);
  border:1px solid var(--border);border-radius:8px;font-size:.82rem;
}}
.threat-name{{color:var(--text-secondary)}}

/* Status banner */
.status-banner{{
  padding:2rem;text-align:center;
  background:var(--bg-card);border:1px solid var(--border);border-radius:10px;
  margin-bottom:1.5rem;
}}
.status-banner h2{{font-size:1.1rem;margin-bottom:.5rem}}
.status-banner p{{color:var(--text-secondary);font-size:.9rem}}

/* Footer */
.report-footer{{
  text-align:center;padding:1.5rem 0;margin-top:2rem;
  border-top:1px solid var(--border);color:var(--text-dim);font-size:.75rem;
}}

/* Empty state */
.empty-state{{
  padding:3rem;text-align:center;color:var(--text-secondary);
  background:var(--bg-card);border:1px solid var(--border);border-radius:10px;
}}

/* Print styles */
@media print{{
  body{{background:#fff;color:#1a1a1a;font-size:11pt}}
  .container{{max-width:100%;padding:0}}
  .report-header,.card,.insight-card,.health-metric{{
    background:#f8f9fa;border-color:#dee2e6;color:#1a1a1a;
  }}
  .badge{{border-width:1px}}
  .donut-bg{{stroke:#dee2e6}}
  thead th{{background:#f1f3f5;color:#495057}}
  tbody td{{border-color:#dee2e6}}
  details{{open:true}}
  .log-filters{{display:none}}
}}

/* Responsive */
@media(max-width:700px){{
  .health-grid{{grid-template-columns:1fr}}
  .report-header{{flex-direction:column;align-items:flex-start}}
  .cards-grid{{grid-template-columns:1fr}}
}}
</style>
</head>'''


def _header_section(name, status, test_category, testing_level, lang, created_at, generated_at):
    status_lower = status.lower()
    if status_lower in ("finished", "completed"):
        status_badge = f'<span class="badge badge-success">{_esc(status)}</span>'
    elif status_lower in ("failed", "error"):
        status_badge = f'<span class="badge badge-error">{_esc(status)}</span>'
    elif status_lower == "running":
        status_badge = f'<span class="badge badge-warning">{_esc(status)}</span>'
    else:
        status_badge = f'<span class="badge badge-neutral">{_esc(status)}</span>'

    meta_items = []
    if test_category:
        meta_items.append(f'<span>{_esc(test_category)}</span>')
    if testing_level:
        meta_items.append(f'<span>Level: {_esc(testing_level)}</span>')
    if lang:
        meta_items.append(f'<span>Lang: {_esc(lang)}</span>')
    if created_at:
        meta_items.append(f'<span>{_esc(created_at)}</span>')

    meta_html = f'<div class="meta-row">{"".join(meta_items)}</div>' if meta_items else ''

    return f'''<div class="container">
<div class="report-header">
  <img src="https://cdneunorth.blob.core.windows.net/data/humanbound_logo.png" alt="Humanbound">
  <div style="flex:1">
    <div style="display:flex;align-items:center;gap:.75rem">
      <h1>{_esc(name)}</h1>
      {status_badge}
    </div>
    {meta_html}
  </div>
</div>'''


def _health_overview(tpi, reliability, fail_impact):
    tpi_val = float(tpi or 0)
    circumference = 2 * 3.14159 * 66
    offset = circumference - (tpi_val / 100) * circumference

    if tpi_val >= 75:
        stroke_color = "var(--success)"
    elif tpi_val >= 50:
        stroke_color = "var(--warning)"
    else:
        stroke_color = "var(--error)"

    return f'''<div class="section">
  <div class="section-title">Health Overview</div>
  <div class="health-grid">
    <div class="donut-container">
      <svg viewBox="0 0 160 160">
        <circle class="donut-bg" cx="80" cy="80" r="66"/>
        <circle class="donut-fill" cx="80" cy="80" r="66"
          stroke="{stroke_color}"
          stroke-dasharray="{_fmt(circumference, 2)}"
          stroke-dashoffset="{_fmt(offset, 2)}"/>
      </svg>
      <div class="donut-label">
        <div class="value">{_fmt(tpi_val, 1)}</div>
        <div class="label">TPI Score</div>
      </div>
    </div>
    <div class="health-metrics">
      <div class="health-metric">
        <span class="name">Reliability</span>
        <span class="val">{_fmt(reliability, 1)}%</span>
      </div>
      <div class="health-metric">
        <span class="name">Fail Impact</span>
        <span class="val">{_fmt(fail_impact, 1)}%</span>
      </div>
    </div>
  </div>
</div>'''


def _metric_cards(pass_rate, fail_rate, total, passed, failed, exec_t, pass_rating):
    rating_label, rating_class = pass_rating
    min_t = _fmt(exec_t.get("min_t", 0))
    avg_t = _fmt(exec_t.get("avg_t", 0))
    max_t = _fmt(exec_t.get("max_t", 0))

    return f'''<div class="section">
  <div class="cards-grid">
    <div class="card">
      <div class="card-label">Pass Rate <span class="badge {rating_class}">{rating_label}</span></div>
      <div class="card-value">{_fmt(pass_rate, 1)}%</div>
      <div class="card-sub">{passed} of {total} tests passed</div>
    </div>
    <div class="card">
      <div class="card-label">Error Rate</div>
      <div class="card-value" style="color:var(--error)">{_fmt(fail_rate, 1)}%</div>
      <div class="card-sub">{failed} tests failed</div>
    </div>
    <div class="card">
      <div class="card-label">Total Tests</div>
      <div class="card-value">{total}</div>
      <div class="card-sub">
        <span style="color:var(--success)">{passed} pass</span> /
        <span style="color:var(--error)">{failed} fail</span>
      </div>
    </div>
    <div class="card">
      <div class="card-label">Execution Time</div>
      <div class="card-value">{avg_t}s</div>
      <div class="card-sub">min {min_t}s / max {max_t}s</div>
    </div>
  </div>
</div>'''


def _threats_table(tests_evals, tests_data):
    # Collect all threats with fail > 0, sorted by fail count descending
    threats = []

    for category, data in tests_evals.items():
        fail_count = data.get("fail", 0) if isinstance(data, dict) else 0
        if fail_count > 0:
            threats.append((category, fail_count))

    for category, data in tests_data.items():
        if not isinstance(data, dict):
            continue
        f = data.get("fail", 0)
        if f > 0:
            threats.append((category, f))

    if not threats:
        return ''

    threats.sort(key=lambda t: t[1], reverse=True)

    items = []
    for category, fail_count in threats:
        risk_label, risk_class = _risk_level(fail_count)
        tag_cls = {"severity-critical": "tag-critical", "severity-high": "tag-high", "severity-medium": "tag-medium", "severity-low": "tag-low"}.get(risk_class, "tag-low")
        items.append(f'''<div class="threat-item">
  <span class="threat-name">{_esc(category)}</span>
  <span class="threat-count"><span class="sev-tag {tag_cls}">{fail_count} {risk_label}</span></span>
</div>''')

    return f'''<div class="section">
  <div class="section-title">Threats Found ({len(threats)})</div>
  <div class="threat-list">
    {''.join(items)}
  </div>
</div>'''


def _insights_section(insights):
    cards = []
    for insight in insights:
        result = insight.get("result", "")
        category = insight.get("category", "")
        severity = insight.get("severity", 0)
        explanation = insight.get("explanation", "")
        examples = insight.get("examples") or []

        try:
            sev_val = int(severity)
        except (TypeError, ValueError):
            sev_val = 0

        if sev_val >= 75:
            sev_class = "severity-critical"
        elif sev_val >= 50:
            sev_class = "severity-high"
        elif sev_val >= 25:
            sev_class = "severity-medium"
        else:
            sev_class = "severity-low"

        result_badge = ''
        if result:
            r_class = "badge-error" if result.lower() == "fail" else "badge-success"
            result_badge = f'<span class="badge {r_class}">{_esc(result)}</span>'

        examples_html = ''
        if examples:
            example_blocks = []
            for ex in examples[:3]:
                if isinstance(ex, dict):
                    text = ex.get("prompt", "") or ex.get("text", "") or str(ex)
                else:
                    text = str(ex)
                example_blocks.append(f'<div class="example-block">{_esc(text)}</div>')
            examples_html = f'''<details class="insight-examples">
  <summary>View {len(examples)} example{"s" if len(examples) != 1 else ""}</summary>
  {''.join(example_blocks)}
</details>'''

        cards.append(f'''<div class="insight-card">
  <div class="insight-header">
    <div class="severity-circle {sev_class}">{sev_val}</div>
    <div class="title">{_esc(category)} {result_badge}</div>
  </div>
  <div class="insight-explanation">{_esc(explanation)}</div>
  {examples_html}
</div>''')

    return f'''<div class="section">
  <div class="section-title">Insights</div>
  {''.join(cards)}
</div>'''


def _logs_section(logs):
    if not logs:
        return '''<div class="section">
  <div class="section-title">Logs</div>
  <div class="empty-state">No logs available for this experiment.</div>
</div>'''

    total_pass = sum(1 for l in logs if l.get("result") == "pass")
    total_fail = sum(1 for l in logs if l.get("result") == "fail")

    rows = []
    for i, log in enumerate(logs):
        result = log.get("result", "")
        severity = log.get("severity", "")
        gen_cat = log.get("gen_category", "")
        fail_cat = log.get("fail_category", "")
        explanation = log.get("explanation", "") or ""
        conversation = log.get("conversation") or []
        exec_time = log.get("exec_t", "")
        confidence = log.get("confidence", "")
        log_id = log.get("id", "")

        result_class = "badge-success" if result == "pass" else "badge-error"
        category = fail_cat or gen_cat or ""

        # Consolidated verdict cell
        pill_cls = "pill-pass" if result == "pass" else "pill-fail"
        dot_cls = "dot-pass" if result == "pass" else "dot-fail"

        meta_parts = []
        if severity:
            try:
                sev_val = int(severity)
                if sev_val >= 75:
                    tag_cls = "tag-critical"
                elif sev_val >= 50:
                    tag_cls = "tag-high"
                elif sev_val >= 25:
                    tag_cls = "tag-medium"
                else:
                    tag_cls = "tag-low"
                meta_parts.append(f'<span class="verdict-meta-item"><span class="meta-label">Sev</span> <span class="sev-tag {tag_cls}">{sev_val}</span></span>')
            except (TypeError, ValueError):
                sev_lower = str(severity).lower()
                tag_cls = {"critical": "tag-critical", "high": "tag-high", "medium": "tag-medium", "low": "tag-low"}.get(sev_lower, "tag-low")
                meta_parts.append(f'<span class="verdict-meta-item"><span class="meta-label">Sev</span> <span class="sev-tag {tag_cls}">{_esc(severity)}</span></span>')
        if confidence:
            try:
                conf_val = float(confidence)
                if conf_val >= 90:
                    conf_color = "var(--success)"
                elif conf_val >= 70:
                    conf_color = "var(--warning)"
                else:
                    conf_color = "var(--error)"
                meta_parts.append(f'<span class="verdict-meta-item"><span class="meta-label">Conf</span> <span style="color:{conf_color};font-weight:600">{conf_val:.0f}%</span></span>')
            except (TypeError, ValueError):
                pass
        meta_html = f'<div class="verdict-meta">{"".join(meta_parts)}</div>' if meta_parts else ''

        verdict_html = f'''<div class="verdict-cell">
  <div class="verdict-pill {pill_cls}">
    <span class="verdict-dot {dot_cls}"></span>
    <span class="verdict-label">{_esc(result)}</span>
  </div>
  {meta_html}
</div>'''

        # Build detail fields from conversation
        detail_parts = []
        if conversation:
            conv_text = _format_conversation(conversation)
            detail_parts.append(f'<div class="field-label">Conversation</div><div class="field-value">{conv_text}</div>')
        if exec_time:
            detail_parts.append(f'<div class="field-label">Execution Time</div><div class="field-value">{_esc(str(exec_time))}s</div>')

        detail_html = f'<div class="log-detail">{"".join(detail_parts)}</div>' if detail_parts else ''

        # Preview: first user message from conversation, or fallback to prompt
        preview = ""
        if conversation:
            for msg in (conversation if isinstance(conversation, list) else []):
                if isinstance(msg, dict):
                    if msg.get("u"):
                        preview = msg["u"][:80]
                        break
                    if msg.get("role", "").lower() in ("user", "attacker"):
                        preview = msg.get("content", "")[:80]
                        break
        if not preview:
            preview = (log.get("prompt", "") or "")[:80]

        rows.append(f'''<tr data-result="{_esc(result)}">
  <td>{verdict_html}</td>
  <td style="font-size:.82rem;color:var(--text-secondary);max-width:300px">{_esc(explanation[:120])}{"…" if len(explanation) > 120 else ""}</td>
  <td>
    <details>
      <summary class="prompt-preview">{_esc(preview)}{"…" if len(preview) >= 80 else ""}</summary>
      {detail_html}
    </details>
  </td>
</tr>''')

    return f'''<div class="section">
  <div class="section-title">Logs ({len(logs)} total — <span style="color:var(--success)">{total_pass} pass</span>, <span style="color:var(--error)">{total_fail} fail</span>)</div>
  <div class="log-filters">
    <button class="filter-btn active" onclick="filterLogs('all')">All ({len(logs)})</button>
    <button class="filter-btn" onclick="filterLogs('pass')">Pass ({total_pass})</button>
    <button class="filter-btn" onclick="filterLogs('fail')">Fail ({total_fail})</button>
  </div>
  <table id="logs-table">
    <thead>
      <tr><th>Verdict</th><th>Explanation</th><th>Conversation</th></tr>
    </thead>
    <tbody>
      {''.join(rows)}
    </tbody>
  </table>
</div>
<script>
function filterLogs(v){{
  document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));
  event.target.classList.add('active');
  document.querySelectorAll('#logs-table tbody tr').forEach(r=>{{
    r.style.display=(v==='all'||r.dataset.result===v)?'':'none';
  }});
}}
</script>'''


def _format_conversation(conversation):
    """Format a conversation list into HTML.

    Supports both formats:
      - [{"role": "user", "content": "..."}, ...]
      - [{"u": "...", "a": "..."}, ...]  (compact turn format)
    """
    if isinstance(conversation, str):
        return _esc(conversation)
    parts = []
    for msg in conversation:
        if isinstance(msg, dict):
            # Compact turn format: {"u": "...", "a": "..."}
            if "u" in msg or "a" in msg:
                if msg.get("u"):
                    parts.append(f'<strong style="color:var(--accent)">User:</strong> {_esc(msg["u"])}')
                if msg.get("a"):
                    parts.append(f'<strong style="color:var(--good)">Assistant:</strong> {_esc(msg["a"])}')
            # Standard format: {"role": "...", "content": "..."}
            elif msg.get("role"):
                parts.append(f'<strong>{_esc(msg["role"])}:</strong> {_esc(msg.get("content", ""))}')
        else:
            parts.append(_esc(str(msg)))
    return '<br><br>'.join(parts)


def _status_banner(status):
    return f'''<div class="status-banner">
  <h2>Experiment {_esc(status)}</h2>
  <p>Results are not yet available. The experiment is currently <strong>{_esc(status.lower())}</strong>.</p>
</div>'''


def _footer(generated_at):
    return f'''<div class="report-footer">
  Generated by <strong>Humanbound CLI</strong> on {generated_at}<br>
  <a href="https://humanbound.ai">humanbound.ai</a>
</div>
</div>'''
