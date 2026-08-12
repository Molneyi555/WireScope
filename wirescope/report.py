from __future__ import annotations

import html
import json
from copy import deepcopy
from typing import Any, Dict, List, Optional

from .artifacts import atomic_write_text
from .redact import RedactionRules, redact_structure, redact_text, strict_share_safe_rules


SHARING_SAFETY_SCHEMA_VERSION = 1


def report_sharing_metadata(
    share_safe: bool,
    rules: Optional[RedactionRules] = None,
) -> Dict[str, Any]:
    """Describe whether and how a report was prepared for external sharing."""

    if not share_safe:
        return {
            "schema_version": SHARING_SAFETY_SCHEMA_VERSION,
            "mode": "private",
            "share_safe": False,
            "review_recommended": True,
            "message": "This report was not prepared for external sharing.",
        }
    policy = strict_share_safe_rules(rules)
    return {
        "schema_version": SHARING_SAFETY_SCHEMA_VERSION,
        "mode": "share-safe",
        "share_safe": True,
        "review_recommended": True,
        "redactions": {
            "all_header_values": policy.redact_all_headers,
            "all_query_values": policy.redact_all_query_values,
            "url_paths": policy.redact_url_paths,
            "url_fragments_removed": policy.remove_url_fragments,
            "known_secret_formats": policy.detect_value_secrets,
            "high_entropy_candidates": policy.detect_high_entropy,
            "ip_addresses": policy.redact_ip_addresses,
            "email_addresses": policy.redact_email_addresses,
            "hardware_addresses": policy.redact_hardware_addresses,
            "local_paths": policy.redact_local_paths,
            "custom_key_rules": [redact_text(value, policy) for value in policy.key_patterns],
            "custom_header_rules": [redact_text(value, policy) for value in policy.header_patterns],
            "custom_path_rules": [redact_text(value, policy) for value in policy.path_patterns],
        },
        "remaining_visible": [
            "domain names",
            "HTTP methods and statuses",
            "resource types and protocols",
            "timings, byte counts, findings, and aggregate metrics",
        ],
        "limitations": [
            "Share-safe mode minimizes common secrets and identifiers but cannot prove that arbitrary free-form text is non-sensitive.",
            "Domain names and findings remain visible because they are needed to interpret the network analysis.",
            "Review the generated artifact before publishing it outside your trust boundary.",
        ],
    }


def prepare_share_safe_report(
    report: Dict[str, Any],
    rules: Optional[RedactionRules] = None,
) -> Dict[str, Any]:
    """Return a strict, non-mutating share-safe representation of a report."""

    policy = strict_share_safe_rules(rules)
    sanitized = redact_structure(report, policy)
    if not isinstance(sanitized, dict):
        raise TypeError("report must sanitize to a JSON object")
    sanitized["sharing_safety"] = report_sharing_metadata(True, policy)
    return sanitized


def prepare_share_safe_comparison(
    comparison: Dict[str, Any],
    rules: Optional[RedactionRules] = None,
) -> Dict[str, Any]:
    """Return a comparison safe for sharing without local source paths."""

    policy = strict_share_safe_rules(rules)
    sanitized = redact_structure(comparison, policy)
    if not isinstance(sanitized, dict):
        raise TypeError("comparison must sanitize to a JSON object")
    for key in ("before", "after"):
        if key in sanitized:
            sanitized[key] = "[REDACTED SOURCE]"
    sanitized["sharing_safety"] = report_sharing_metadata(True, policy)
    return sanitized


def _prepare_private_report(report: Dict[str, Any]) -> Dict[str, Any]:
    value = deepcopy(report)
    value["sharing_safety"] = report_sharing_metadata(False)
    return value


def esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def human_bytes(value: Any) -> str:
    try:
        amount = float(value or 0)
    except (TypeError, ValueError):
        return "0 B"
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(amount) < 1024 or unit == "TiB":
            return f"{amount:.0f} {unit}" if unit == "B" else f"{amount:.1f} {unit}"
        amount /= 1024
    return f"{amount:.1f} TiB"


def human_ms(value: Any) -> str:
    try:
        amount = float(value or 0)
    except (TypeError, ValueError):
        return "—"
    return f"{amount / 1000:.2f}s" if amount >= 1000 else f"{amount:.1f}ms"


def score_class(value: int) -> str:
    if value >= 85:
        return "good"
    if value >= 60:
        return "warn"
    return "bad"


def render_score_cards(scores: Dict[str, Any]) -> str:
    if not scores:
        return ""
    cards = []
    for key in ("overall", "performance", "reliability", "privacy", "security"):
        if key not in scores:
            continue
        value = int(scores[key])
        cards.append(
            f'<div class="score {score_class(value)}"><div class="ring" style="--score:{value}"><span>{value}</span></div><small>{esc(key.title())}</small></div>'
        )
    return '<div class="scores">' + "".join(cards) + "</div>"


def render_findings(findings: List[Dict[str, Any]]) -> str:
    if not findings:
        return '<div class="empty">No automated findings.</div>'
    values = []
    icons = {"critical": "×", "warning": "!", "info": "i", "ok": "✓"}
    for item in findings:
        severity = str(item.get("severity", "info"))
        evidence = item.get("evidence") or []
        evidence_html = ""
        if evidence:
            evidence_html = '<details><summary>Evidence</summary><ul>' + "".join(f"<li>{esc(value)}</li>" for value in evidence) + "</ul></details>"
        recommendation = f'<p class="recommendation">{esc(item.get("recommendation"))}</p>' if item.get("recommendation") else ""
        values.append(
            f'<article class="finding {esc(severity)}" data-severity="{esc(severity)}">'
            f'<span class="finding-icon">{icons.get(severity, "·")}</span><div>'
            f'<div class="finding-meta">{esc(severity)} · {esc(item.get("category", "overview"))}</div>'
            f'<h3>{esc(item.get("title"))}</h3>{recommendation}{evidence_html}</div></article>'
        )
    return "".join(values)


def render_domain_bars(domains: Dict[str, Dict[str, Any]], limit: int = 25) -> str:
    items = list(domains.items())[:limit]
    peak = max((row.get("bytes", 0) for _domain, row in items), default=1) or 1
    rows = []
    for domain, row in items:
        width = max(1, round((row.get("bytes", 0) / peak) * 100))
        tags = []
        if row.get("third_party"):
            tags.append('<span class="tag">3rd party</span>')
        if row.get("tracker"):
            tags.append('<span class="tag danger">tracker</span>')
        rows.append(
            f'<div class="bar-row"><div class="bar-label"><strong>{esc(domain)}</strong><span>{row.get("requests", 0)} req · {human_bytes(row.get("bytes", 0))} {"".join(tags)}</span></div>'
            f'<div class="bar-track"><div class="bar-fill" style="width:{width}%"></div></div></div>'
        )
    return "".join(rows) or '<div class="empty">No domain data.</div>'


def render_aggregate_bars(values: Dict[str, int]) -> str:
    peak = max(values.values(), default=1) or 1
    return "".join(
        f'<div class="mini-bar"><span>{esc(key)}</span><div><i style="width:{max(1, round(value / peak * 100))}%"></i></div><b>{value}</b></div>'
        for key, value in list(values.items())[:15]
    )


def request_row(item: Dict[str, Any], index: int) -> str:
    status = int(item.get("status", 0) or 0)
    status_class = "status-ok" if 200 <= status < 400 else ("status-warn" if status else "status-muted")
    if item.get("failed") or status >= 400:
        status_class = "status-bad"
    flags = []
    if item.get("from_cache"):
        flags.append('<span class="tag">cache</span>')
    if item.get("third_party"):
        flags.append('<span class="tag">3rd</span>')
    if item.get("tracker"):
        flags.append('<span class="tag danger">tracker</span>')
    if item.get("failed"):
        flags.append('<span class="tag danger">failed</span>')
    timing = item.get("timing") or {}
    detail = {
        "remote": f"{item.get('remote_ip') or '—'}:{item.get('remote_port') or '—'}",
        "connection": item.get("connection_id"),
        "reused": item.get("connection_reused"),
        "priority": item.get("initial_priority"),
        "initiator": item.get("initiator_type"),
        "timing": timing,
        "security": item.get("security_details"),
        "failure": item.get("failure"),
        "query_keys": item.get("query_keys"),
    }
    search = " ".join(
        str(value)
        for value in (
            item.get("method"),
            status,
            item.get("domain"),
            item.get("url"),
            item.get("resource_type"),
            item.get("mime_type"),
            item.get("protocol"),
        )
    ).lower()
    return (
        f'<tr data-search="{esc(search)}" data-status="{status}" data-type="{esc(item.get("resource_type", "Other"))}" '
        f'data-domain="{esc(item.get("domain", ""))}" data-duration="{float(item.get("duration_ms", 0) or 0)}" '
        f'data-size="{int(item.get("transfer_bytes", 0) or 0)}">'
        f'<td class="mono muted">{index + 1}</td><td class="mono">{human_ms(item.get("offset_ms"))}</td>'
        f'<td><strong>{esc(item.get("method"))}</strong></td><td class="{status_class}">{status or "—"}</td>'
        f'<td>{esc(item.get("resource_type"))}</td><td class="url"><span title="{esc(item.get("url"))}">{esc(item.get("url"))}</span>{"".join(flags)}</td>'
        f'<td>{esc(item.get("protocol"))}</td><td data-sort="{float(item.get("duration_ms", 0) or 0)}">{human_ms(item.get("duration_ms"))}</td>'
        f'<td data-sort="{int(item.get("transfer_bytes", 0) or 0)}">{human_bytes(item.get("transfer_bytes"))}</td>'
        f'<td><details><summary>view</summary><pre>{esc(json.dumps(detail, ensure_ascii=False, indent=2))}</pre></details></td></tr>'
    )


def render_waterfall(requests: List[Dict[str, Any]], limit: int = 80) -> str:
    values = sorted(requests, key=lambda item: float(item.get("offset_ms", 0) or 0))[:limit]
    span = max((float(item.get("offset_ms", 0) or 0) + float(item.get("duration_ms", 0) or 0) for item in values), default=1) or 1
    rows = []
    for item in values:
        left = max(0, min(99, float(item.get("offset_ms", 0) or 0) / span * 100))
        width = max(0.4, min(100 - left, float(item.get("duration_ms", 0) or 0) / span * 100))
        bad = " bad" if item.get("failed") or (item.get("status", 0) or 0) >= 400 else ""
        rows.append(
            f'<div class="water-row"><div class="water-label" title="{esc(item.get("url"))}">{esc(item.get("method"))} {esc(item.get("domain"))}{esc(item.get("path"))}</div>'
            f'<div class="water-track"><i class="water-bar{bad}" style="left:{left:.2f}%;width:{width:.2f}%" title="{human_ms(item.get("duration_ms"))}"></i></div>'
            f'<span>{human_ms(item.get("duration_ms"))}</span></div>'
        )
    return "".join(rows) or '<div class="empty">No request timing data.</div>'


def render_browser_details(browser: Dict[str, Any]) -> str:
    if not browser:
        return '<div class="empty">No browser-specific data.</div>'
    metrics = browser.get("performance_metrics", {})
    websocket = browser.get("websocket", {})
    lifecycle = browser.get("lifecycle", [])
    metric_rows = "".join(
        f"<tr><td>{esc(key)}</td><td class='mono'>{esc(round(value, 4) if isinstance(value, float) else value)}</td></tr>"
        for key, value in sorted(metrics.items())
    )
    lifecycle_rows = "".join(
        f"<tr><td>{esc(item.get('method'))}</td><td>{esc(item.get('name', ''))}</td><td class='mono'>{esc(item.get('timestamp', ''))}</td></tr>"
        for item in lifecycle
    )
    return (
        '<div class="grid two"><section class="panel"><h2>Performance metrics</h2><div class="table-wrap"><table><tbody>'
        + metric_rows
        + '</tbody></table></div></section><section class="panel"><h2>WebSocket</h2><pre>'
        + esc(json.dumps(websocket, ensure_ascii=False, indent=2))
        + '</pre><h2>Lifecycle</h2><div class="table-wrap"><table><tbody>'
        + lifecycle_rows
        + "</tbody></table></div></section></div>"
    )


CSS = r"""
:root{color-scheme:dark;--bg:#090d14;--panel:#111823;--panel2:#151f2d;--line:#263246;--text:#e9f1fb;--muted:#91a1b7;--cyan:#45d7ff;--green:#52e39b;--yellow:#ffd166;--red:#ff6577;--blue:#6f8cff}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 20% -10%,#18334b 0,transparent 32%),var(--bg);color:var(--text);font:14px/1.5 ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}header{position:sticky;top:0;z-index:10;background:rgba(9,13,20,.9);backdrop-filter:blur(16px);border-bottom:1px solid var(--line)}.header-inner,main{max-width:1500px;margin:auto;padding:18px 24px}.brand{display:flex;align-items:center;gap:12px}.logo{display:grid;place-items:center;width:36px;height:36px;border-radius:9px;background:linear-gradient(135deg,var(--cyan),var(--blue));color:#071018;font-weight:900}.brand h1{font-size:19px;margin:0}.brand p{color:var(--muted);margin:0;font-size:12px}.tabs{display:flex;gap:4px;margin-top:14px;overflow:auto}.tabs button{background:transparent;color:var(--muted);border:0;border-bottom:2px solid transparent;padding:8px 12px;cursor:pointer}.tabs button.active{color:var(--cyan);border-color:var(--cyan)}main{padding-top:22px}.view{display:none}.view.active{display:block}.hero{display:flex;justify-content:space-between;gap:20px;align-items:center;margin-bottom:18px}.hero h2{font-size:25px;margin:0 0 4px}.hero p{margin:0;color:var(--muted)}.scores{display:flex;gap:12px;flex-wrap:wrap}.score{text-align:center}.ring{--score:0;width:68px;height:68px;border-radius:50%;display:grid;place-items:center;background:conic-gradient(var(--accent) calc(var(--score)*1%),#243043 0);position:relative}.ring:after{content:"";position:absolute;inset:6px;background:var(--panel);border-radius:50%}.ring span{z-index:1;font-weight:800;font-size:20px}.score small{display:block;color:var(--muted);margin-top:4px}.good{--accent:var(--green)}.warn{--accent:var(--yellow)}.bad{--accent:var(--red)}.cards{display:grid;grid-template-columns:repeat(6,minmax(130px,1fr));gap:10px;margin:18px 0}.card,.panel{background:linear-gradient(180deg,rgba(21,31,45,.95),rgba(15,23,34,.95));border:1px solid var(--line);border-radius:12px;padding:16px;box-shadow:0 10px 25px rgba(0,0,0,.16)}.card span{display:block;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.08em}.card strong{display:block;font-size:22px;margin-top:5px}.grid{display:grid;gap:14px}.grid.two{grid-template-columns:repeat(2,minmax(0,1fr))}.panel h2{font-size:15px;margin:0 0 14px}.finding{display:grid;grid-template-columns:34px 1fr;gap:10px;padding:14px;margin-bottom:9px;border:1px solid var(--line);border-left:3px solid var(--muted);border-radius:9px;background:rgba(17,24,35,.7)}.finding.critical{border-left-color:var(--red)}.finding.warning{border-left-color:var(--yellow)}.finding.ok{border-left-color:var(--green)}.finding-icon{display:grid;place-items:center;width:28px;height:28px;border-radius:50%;background:var(--panel2);font-weight:900}.finding h3{font-size:14px;margin:1px 0}.finding-meta{color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.1em}.recommendation{color:#c8d4e5;margin:5px 0}.finding details{margin-top:6px}.finding li{word-break:break-all;color:var(--muted)}.bar-row{display:grid;grid-template-columns:minmax(220px,35%) 1fr;align-items:center;gap:12px;margin:10px 0}.bar-label{display:flex;justify-content:space-between;gap:8px}.bar-label span{color:var(--muted);font-size:11px}.bar-track{height:9px;border-radius:9px;background:#222e40;overflow:hidden}.bar-fill{height:100%;border-radius:inherit;background:linear-gradient(90deg,var(--cyan),var(--blue))}.tag{display:inline-block;border:1px solid #42516a;border-radius:10px;padding:1px 5px;margin-left:4px;font-size:9px;color:#aebdd0}.tag.danger{color:var(--red);border-color:#703846}.mini-bar{display:grid;grid-template-columns:130px 1fr 45px;gap:8px;align-items:center;margin:8px 0}.mini-bar>div{height:6px;background:#222e40;border-radius:5px;overflow:hidden}.mini-bar i{display:block;height:100%;background:var(--cyan)}.toolbar{display:flex;gap:8px;flex-wrap:wrap;margin:0 0 12px}.toolbar input,.toolbar select{background:var(--panel);border:1px solid var(--line);border-radius:7px;color:var(--text);padding:8px 10px}.toolbar input{min-width:320px;flex:1}.toolbar .count{color:var(--muted);padding:8px}.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:10px}table{width:100%;border-collapse:collapse;background:rgba(12,18,27,.75)}th,td{padding:9px 10px;border-bottom:1px solid #202b3b;text-align:left;white-space:nowrap}th{position:sticky;top:0;background:#151e2b;color:#9eb0c7;font-size:10px;text-transform:uppercase;letter-spacing:.07em;cursor:pointer}tbody tr:hover{background:#172231}.url{max-width:520px}.url>span{display:inline-block;max-width:430px;overflow:hidden;text-overflow:ellipsis;vertical-align:middle}.mono,pre{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}.muted{color:var(--muted)}.status-ok{color:var(--green)}.status-warn{color:var(--yellow)}.status-bad{color:var(--red);font-weight:700}.status-muted{color:var(--muted)}details summary{cursor:pointer;color:var(--cyan)}pre{white-space:pre-wrap;word-break:break-word;background:#080c12;padding:10px;border-radius:7px;max-width:700px;max-height:380px;overflow:auto}.water-row{display:grid;grid-template-columns:minmax(220px,32%) 1fr 70px;gap:8px;align-items:center;height:24px}.water-label{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#b9c8da}.water-track{position:relative;height:11px;background:#1a2433;border-radius:3px}.water-bar{position:absolute;height:100%;background:linear-gradient(90deg,var(--cyan),var(--blue));border-radius:3px;min-width:2px}.water-bar.bad{background:var(--red)}.empty{color:var(--muted);padding:20px;text-align:center}footer{max-width:1500px;margin:20px auto;padding:20px 24px;color:var(--muted);border-top:1px solid var(--line)}@media(max-width:900px){.cards{grid-template-columns:repeat(2,1fr)}.grid.two{grid-template-columns:1fr}.hero{display:block}.scores{margin-top:16px}.bar-row{grid-template-columns:1fr}.toolbar input{min-width:100%}}
"""


JS = r"""
const buttons=[...document.querySelectorAll('.tabs button')];const views=[...document.querySelectorAll('.view')];buttons.forEach(b=>b.onclick=()=>{buttons.forEach(x=>x.classList.toggle('active',x===b));views.forEach(v=>v.classList.toggle('active',v.id===b.dataset.view));history.replaceState(null,'','#'+b.dataset.view)});const initial=location.hash.slice(1);if(initial){document.querySelector(`[data-view="${initial}"]`)?.click()}const search=document.querySelector('#request-search');const statusFilter=document.querySelector('#status-filter');const typeFilter=document.querySelector('#type-filter');const rows=[...document.querySelectorAll('#requests-body tr')];const count=document.querySelector('#visible-count');function filter(){const q=(search?.value||'').toLowerCase();const s=statusFilter?.value||'all';const t=typeFilter?.value||'all';let n=0;rows.forEach(r=>{const status=Number(r.dataset.status);const sm=s==='all'||(s==='error'&&(status===0||status>=400))||(s==='success'&&status>=200&&status<400)||(s==='redirect'&&status>=300&&status<400);const show=(!q||r.dataset.search.includes(q))&&sm&&(t==='all'||r.dataset.type===t);r.hidden=!show;if(show)n++});if(count)count.textContent=`${n} shown`}[search,statusFilter,typeFilter].forEach(x=>x?.addEventListener('input',filter));filter();document.querySelectorAll('th[data-key]').forEach(th=>th.onclick=()=>{const key=th.dataset.key;const body=document.querySelector('#requests-body');const asc=th.dataset.asc!=='true';th.dataset.asc=String(asc);rows.sort((a,b)=>{const av=a.dataset[key]??a.children[Number(key)]?.textContent??'';const bv=b.dataset[key]??b.children[Number(key)]?.textContent??'';const an=Number(av),bn=Number(bv);const result=!Number.isNaN(an)&&!Number.isNaN(bn)?an-bn:String(av).localeCompare(String(bv));return asc?result:-result});rows.forEach(r=>body.appendChild(r))});
"""


def generate_html_report(
    report: Dict[str, Any],
    output: str,
    title: str = "WireScope Network Report",
    share_safe: bool = False,
    redaction_rules: Optional[RedactionRules] = None,
) -> None:
    share_policy = strict_share_safe_rules(redaction_rules) if share_safe else None
    report = prepare_share_safe_report(report, redaction_rules) if share_safe else _prepare_private_report(report)
    if share_policy is not None:
        title = redact_text(title, share_policy)
    summary = report.get("summary", {})
    requests = report.get("requests", [])
    aggregates = report.get("aggregates", {})
    types = sorted({str(item.get("resource_type", "Other")) for item in requests})
    type_options = "".join(f'<option value="{esc(value)}">{esc(value)}</option>' for value in types)
    request_rows = "".join(request_row(item, index) for index, item in enumerate(requests))
    cards = [
        ("Requests", summary.get("requests", summary.get("events", 0))),
        ("Domains", summary.get("domains", summary.get("processes", 0))),
        ("Transfer", human_bytes(summary.get("transfer_bytes", 0))),
        ("Page span", human_ms(summary.get("page_span_ms", 0))),
        ("Errors", (summary.get("failed", 0) or 0) + (summary.get("http_errors", 0) or 0)),
        ("Third-party", f"{summary.get('third_party_percent', 0)}%"),
    ]
    card_html = "".join(f'<div class="card"><span>{esc(label)}</span><strong>{esc(value)}</strong></div>' for label, value in cards)
    raw_json = json.dumps(report, ensure_ascii=False, separators=(",", ":")).replace("<", "\\u003c")
    sharing_label = "share-safe export · review before publishing" if share_safe else "private report · not prepared for sharing"
    footer = (
        "Share-safe redaction enabled. Domain names and analysis evidence remain visible; review before publishing."
        if share_safe
        else "Private report. Secrets are redacted by default, but this artifact was not prepared for external sharing."
    )
    document = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{esc(title)}</title><style>{CSS}</style></head><body>
<header><div class="header-inner"><div class="brand"><div class="logo">W</div><div><h1>{esc(title)}</h1><p>{esc(report.get('source_type','recording'))} · generated {esc(report.get('generated_at',''))} · {esc(sharing_label)}</p></div></div><nav class="tabs"><button class="active" data-view="overview">Overview</button><button data-view="requests">Requests</button><button data-view="waterfall">Waterfall</button><button data-view="domains">Domains</button><button data-view="browser">Browser</button></nav></div></header>
<main><section class="view active" id="overview"><div class="hero"><div><h2>Network session analysis</h2><p>{summary.get('requests',0)} requests across {summary.get('domains',0)} domains</p></div>{render_score_cards(report.get('scores',{}))}</div><div class="cards">{card_html}</div><div class="grid two"><section class="panel"><h2>Automated findings</h2>{render_findings(report.get('findings',[]))}</section><section class="panel"><h2>Resource types</h2>{render_aggregate_bars(aggregates.get('resource_types',{}))}<h2 style="margin-top:24px">Protocols</h2>{render_aggregate_bars(aggregates.get('protocols',{}))}</section></div></section>
<section class="view" id="requests"><div class="toolbar"><input id="request-search" type="search" placeholder="Search URL, domain, method, MIME or protocol…"><select id="status-filter"><option value="all">All statuses</option><option value="success">Success</option><option value="redirect">Redirects</option><option value="error">Errors</option></select><select id="type-filter"><option value="all">All types</option>{type_options}</select><span class="count" id="visible-count"></span></div><div class="table-wrap"><table><thead><tr><th>#</th><th data-key="offset_ms">Start</th><th>Method</th><th data-key="status">Status</th><th>Type</th><th>URL</th><th>Protocol</th><th data-key="duration">Time</th><th data-key="size">Transfer</th><th>Details</th></tr></thead><tbody id="requests-body">{request_rows}</tbody></table></div></section>
<section class="view" id="waterfall"><section class="panel"><h2>Request waterfall · first 80 by start time</h2>{render_waterfall(requests)}</section></section>
<section class="view" id="domains"><section class="panel"><h2>Domains by transferred bytes</h2>{render_domain_bars(aggregates.get('domains',{}))}</section></section>
<section class="view" id="browser">{render_browser_details(report.get('browser',{}))}</section></main>
<footer>Generated locally by WireScope. {esc(footer)} The report has no external assets and does not send telemetry.</footer><script id="wirescope-data" type="application/json">{raw_json}</script><script>{JS}</script></body></html>"""
    atomic_write_text(output, document)


def generate_comparison_html(
    comparison: Dict[str, Any],
    output: str,
    share_safe: bool = False,
    redaction_rules: Optional[RedactionRules] = None,
) -> None:
    comparison = (
        prepare_share_safe_comparison(comparison, redaction_rules)
        if share_safe
        else deepcopy(comparison)
    )
    comparison.setdefault("sharing_safety", report_sharing_metadata(False))
    rows = []
    for key, value in comparison.get("deltas", {}).items():
        delta = value.get("delta", 0)
        cls = "status-bad" if delta > 0 and key not in ("cache_percent",) else ("status-ok" if delta < 0 else "")
        rows.append(
            f"<tr><td>{esc(key.replace('_',' ').title())}</td><td>{esc(value.get('before'))}</td><td>{esc(value.get('after'))}</td><td class='{cls}'>{delta:+g}</td><td>{esc(str(value.get('percent'))+'%' if value.get('percent') is not None else '—')}</td></tr>"
        )
    score_rows = []
    for key, value in comparison.get("score_deltas", {}).items():
        delta = value.get("delta", 0)
        cls = "status-ok" if delta > 0 else ("status-bad" if delta < 0 else "")
        score_rows.append(f"<tr><td>{esc(key.title())}</td><td>{value.get('before')}</td><td>{value.get('after')}</td><td class='{cls}'>{delta:+g}</td></tr>")
    sharing_json = json.dumps(
        comparison.get("sharing_safety", {}), ensure_ascii=False, separators=(",", ":")
    ).replace("<", "\\u003c")
    sharing_label = "share-safe · review before publishing" if share_safe else "private · not prepared for sharing"
    document = f"""<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>WireScope Comparison</title><style>{CSS}</style></head><body><header><div class='header-inner'><div class='brand'><div class='logo'>W</div><div><h1>WireScope comparison</h1><p>{esc(comparison.get('before'))} → {esc(comparison.get('after'))} · {esc(sharing_label)}</p></div></div></div></header><main><div class='grid two'><section class='panel'><h2>Network metric deltas</h2><div class='table-wrap'><table><thead><tr><th>Metric</th><th>Before</th><th>After</th><th>Delta</th><th>Change</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div></section><section class='panel'><h2>Score deltas</h2><div class='table-wrap'><table><thead><tr><th>Score</th><th>Before</th><th>After</th><th>Delta</th></tr></thead><tbody>{''.join(score_rows)}</tbody></table></div></section></div></main><footer>Generated locally by WireScope. {esc(sharing_label)}.</footer><script id='wirescope-sharing-safety' type='application/json'>{sharing_json}</script></body></html>"""
    atomic_write_text(output, document)
