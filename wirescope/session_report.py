from __future__ import annotations

import json
import os
from fnmatch import fnmatchcase
from html import escape
from pathlib import Path
from typing import Any, Dict, Optional

from .artifacts import atomic_write_text
from .redact import RedactionRules, is_sensitive_path, redact_structure, redact_text, strict_share_safe_rules
from .session import SessionError, SessionStore


SESSION_REPORT_SCHEMA_VERSION = 1
SESSION_REPORT_LIMITS = {
    "timeline": 10_000,
    "entities": 10_000,
    "relations": 20_000,
    "findings": 5_000,
}
MAX_SESSION_REPORT_TEXT_CHARS = 256 * 1024 * 1024


def _bounded_report_text_size(store: SessionStore) -> int:
    finding_query = (
        """SELECT COALESCE(SUM(
               length(title) + length(explanation) + length(recommendation) +
               length(evidence_json) + COALESCE(length(limitations_json), 0)
           ), 0) FROM (
               SELECT title, explanation, recommendation, evidence_json, limitations_json
               FROM findings ORDER BY timestamp DESC LIMIT ?
           )"""
        if store.schema_version >= 2
        else
        """SELECT COALESCE(SUM(
               length(title) + length(explanation) + length(recommendation) + length(evidence_json)
           ), 0) FROM (
               SELECT title, explanation, recommendation, evidence_json
               FROM findings ORDER BY timestamp DESC LIMIT ?
           )"""
    )
    queries = (
        (
            """SELECT COALESCE(SUM(
                   length(timestamp) + length(source) + length(event_type) + length(severity) +
                   COALESCE(length(entity_id), 0) + COALESCE(length(correlation_id), 0) +
                   length(payload_json)
               ), 0) FROM (
                   SELECT timestamp, source, event_type, severity, entity_id, correlation_id, payload_json
                   FROM events ORDER BY sequence LIMIT ?
               )""",
            SESSION_REPORT_LIMITS["timeline"],
        ),
        (
            """SELECT COALESCE(SUM(
                   length(entity_type) + length(entity_key) + length(label) + length(attributes_json)
               ), 0) FROM (
                   SELECT entity_type, entity_key, label, attributes_json
                   FROM entities ORDER BY last_seen DESC LIMIT ?
               )""",
            SESSION_REPORT_LIMITS["entities"],
        ),
        (
            """SELECT COALESCE(SUM(
                   length(source_id) + length(relation_type) + length(target_id) + length(evidence_json)
               ), 0) FROM (
                   SELECT source_id, relation_type, target_id, evidence_json
                   FROM relations ORDER BY last_seen DESC LIMIT ?
               )""",
            SESSION_REPORT_LIMITS["relations"],
        ),
        (finding_query, SESSION_REPORT_LIMITS["findings"]),
    )
    total = 0
    for query, limit in queries:
        total += int(store.connection.execute(query, (limit,)).fetchone()[0])
        if total > MAX_SESSION_REPORT_TEXT_CHARS:
            raise SessionError(
                f"session report content exceeds {MAX_SESSION_REPORT_TEXT_CHARS} characters"
            )
    return total


def _share_safe_session_data(data: Dict[str, Any], rules: RedactionRules) -> Dict[str, Any]:
    """Sanitize report data without collapsing containers required by the UI."""

    result = redact_structure(data, rules)
    summary = result.get("summary")
    original_summary = data.get("summary")
    if not isinstance(original_summary, dict):
        raise SessionError("session report summary has an invalid structure")

    def explicit_key_match(key: str) -> bool:
        folded = key.casefold()
        return any(fnmatchcase(folded, pattern.casefold()) for pattern in rules.key_patterns)

    summary_redacted = explicit_key_match("summary") or is_sensitive_path(("summary",), rules)
    if not isinstance(summary, dict):
        if not summary_redacted:
            raise SessionError("session report summary has an invalid structure")
        summary = {
            "schema_version": original_summary.get("schema_version"),
            "path": "[REDACTED]",
            "sessions": [],
            "counts": {"events": 0, "entities": 0, "relations": 0, "findings": 0},
            "events_by_type": {},
            "events_by_source": {},
            "entities_by_type": {},
        }
        result["summary"] = summary

    # The database location is operational metadata, never report evidence.
    # Redact it explicitly even for portable paths such as /tmp/capture.wsdb
    # that do not contain a recognizable user-home component.
    summary["path"] = "[REDACTED]"

    original_sessions = original_summary.get("sessions", [])
    if not isinstance(original_sessions, list):
        raise SessionError("session report sessions must be an array")
    sessions_redacted = (
        summary_redacted
        or explicit_key_match("sessions")
        or is_sensitive_path(("summary", "sessions"), rules)
    )
    summary["sessions"] = (
        []
        if sessions_redacted
        else [
            redact_structure(item, rules, path=("summary", "sessions", str(index)))
            for index, item in enumerate(original_sessions)
        ]
    )

    # Aggregation maps are structural data. Event names such as
    # ``session.started`` must not be mistaken for credential-bearing keys.
    for field in ("counts", "events_by_type", "events_by_source", "entities_by_type"):
        original = original_summary.get(field, {})
        if isinstance(original, dict):
            field_redacted = summary_redacted or explicit_key_match(field) or is_sensitive_path(("summary", field), rules)
            if field_redacted:
                summary[field] = {} if field != "counts" else {
                    "events": 0,
                    "entities": 0,
                    "relations": 0,
                    "findings": 0,
                }
            else:
                summary[field] = {
                    redact_text(str(key), rules): value
                    for key, value in original.items()
                }

    for field in ("timeline", "entities", "relations", "findings"):
        if not isinstance(result.get(field), list):
            result[field] = []
    if not isinstance(summary.get("sessions"), list):
        raise SessionError("share-safe report sessions must remain an array")
    return result


def _reject_source_output_collision(session_path: str, output: str) -> None:
    source = Path(session_path).expanduser().absolute()
    destination = Path(output).expanduser().absolute()
    try:
        if destination.exists() and os.path.samefile(source, destination):
            raise SessionError("session report output must not replace its source database")
    except FileNotFoundError:
        pass
    if os.path.normcase(os.path.realpath(str(source))) == os.path.normcase(os.path.realpath(str(destination))):
        raise SessionError("session report output must not replace its source database")


def build_session_report_data(
    session_path: str,
    *,
    share_safe: bool = False,
    redaction_rules: Optional[RedactionRules] = None,
) -> Dict[str, Any]:
    with SessionStore(session_path, read_only=True) as store:
        summary = store.summary()
        _bounded_report_text_size(store)
        data = {
            "schema_version": SESSION_REPORT_SCHEMA_VERSION,
            "summary": summary,
            "timeline": store.timeline(limit=SESSION_REPORT_LIMITS["timeline"]),
            "entities": store.entities(limit=SESSION_REPORT_LIMITS["entities"]),
            "relations": store.relations(limit=SESSION_REPORT_LIMITS["relations"]),
            "findings": store.findings(limit=SESSION_REPORT_LIMITS["findings"]),
            "limits": dict(SESSION_REPORT_LIMITS),
            "sharing_safety": {
                "mode": "share-safe" if share_safe else "private",
                "safe_to_publish_without_review": False,
                "warnings": (
                    ["Strict redaction was applied.", "Domain names and event categories can still reveal activity; review before publishing."]
                    if share_safe
                    else ["This private report was not prepared for sharing."]
                ),
            },
        }
    if share_safe:
        data = _share_safe_session_data(data, strict_share_safe_rules(redaction_rules))
    return data


def generate_session_html(
    session_path: str,
    output: str,
    *,
    title: str = "WireScope Session",
    share_safe: bool = False,
    redaction_rules: Optional[RedactionRules] = None,
) -> Dict[str, Any]:
    _reject_source_output_collision(session_path, output)
    data = build_session_report_data(session_path, share_safe=share_safe, redaction_rules=redaction_rules)
    if share_safe:
        title = redact_text(title, strict_share_safe_rules(redaction_rules))
    raw = json.dumps(data, ensure_ascii=False, separators=(",", ":")).replace("<", "\\u003c")
    mode = "share-safe · review before publishing" if share_safe else "private · not prepared for sharing"
    document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{escape(title)}</title><style>
:root{{color-scheme:dark;--bg:#090d14;--panel:#121a26;--line:#263246;--text:#eaf2fc;--muted:#91a1b7;--cyan:#47d8ff;--green:#52e39b;--yellow:#ffd166;--red:#ff6577}}
*{{box-sizing:border-box}}body{{margin:0;background:radial-gradient(circle at 10% -15%,#1b3b55,transparent 35%),var(--bg);color:var(--text);font:14px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}}header{{position:sticky;top:0;z-index:5;background:#090d14e8;backdrop-filter:blur(14px);border-bottom:1px solid var(--line)}}header>div,main,footer{{max-width:1500px;margin:auto;padding:18px 24px}}h1{{font-size:20px;margin:0}}.subtitle,.muted{{color:var(--muted)}}nav{{display:flex;gap:5px;margin-top:14px;overflow:auto}}button,input,select{{background:var(--panel);color:var(--text);border:1px solid var(--line);border-radius:8px;padding:8px 11px}}nav button{{border-color:transparent;background:transparent;cursor:pointer}}nav button.active{{color:var(--cyan);border-bottom-color:var(--cyan)}}.view{{display:none}}.view.active{{display:block}}.cards{{display:grid;grid-template-columns:repeat(5,minmax(130px,1fr));gap:10px;margin-bottom:18px}}.card,.panel{{background:#121a26e8;border:1px solid var(--line);border-radius:12px;padding:15px}}.card span{{display:block;color:var(--muted);font-size:11px;text-transform:uppercase}}.card strong{{display:block;font-size:24px;margin-top:4px}}.toolbar{{display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap}}.toolbar input{{min-width:300px;flex:1}}.table{{overflow:auto;border:1px solid var(--line);border-radius:10px}}table{{border-collapse:collapse;width:100%;background:#0c121b}}th,td{{padding:9px 10px;border-bottom:1px solid #202b3b;text-align:left;white-space:nowrap}}th{{position:sticky;top:0;background:#151e2b;color:#9eb0c7;font-size:10px;text-transform:uppercase}}tr:hover{{background:#172231}}.type{{color:var(--cyan)}}.warning{{color:var(--yellow)}}.critical{{color:var(--red)}}.ok{{color:var(--green)}}pre{{white-space:pre-wrap;word-break:break-word;background:#080c12;border-radius:8px;padding:10px;max-height:480px;overflow:auto}}footer{{color:var(--muted);border-top:1px solid var(--line);margin-top:24px}}@media(max-width:800px){{.cards{{grid-template-columns:repeat(2,1fr)}}}}
</style></head><body><header><div><h1>{escape(title)}</h1><div class="subtitle">Record → Correlate → Explain · {escape(mode)}</div><nav>
<button class="active" data-view="overview">Overview</button><button data-view="timeline">Timeline</button><button data-view="entities">Entities</button><button data-view="relations">Relations</button><button data-view="findings">Findings</button><button data-view="raw">Raw</button>
</nav></div></header><main>
<section id="overview" class="view active"><div id="cards" class="cards"></div><div class="panel"><h2>Sessions</h2><div id="sessions"></div></div></section>
<section id="timeline" class="view"><div class="toolbar"><input id="event-q" placeholder="Filter type, source, severity or details"><select id="event-type"><option value="">All event types</option></select><span id="event-count" class="muted"></span></div><div class="table"><table><thead><tr><th>#</th><th>Time</th><th>Source</th><th>Type</th><th>Level</th><th>Entity</th><th>Details</th></tr></thead><tbody id="events"></tbody></table></div></section>
<section id="entities" class="view"><div class="toolbar"><input id="entity-q" placeholder="Filter ID, type or label"><select id="entity-type"><option value="">All entity types</option></select><span id="entity-count" class="muted"></span></div><div class="table"><table><thead><tr><th>Type</th><th>Label</th><th>ID</th><th>First seen</th><th>Last seen</th><th>Attributes</th></tr></thead><tbody id="entity-rows"></tbody></table></div></section>
<section id="relations" class="view"><div class="table"><table><thead><tr><th>Source</th><th>Relation</th><th>Target</th><th>Confidence</th><th>Last seen</th><th>Evidence</th></tr></thead><tbody id="relation-rows"></tbody></table></div></section>
<section id="findings" class="view"><div id="finding-rows"></div></section>
<section id="raw" class="view"><pre id="raw-data"></pre></section>
</main><footer>Generated locally by WireScope. This report contains no external assets and sends no telemetry. {escape(mode)}.</footer>
<script id="wirescope-session-data" type="application/json">{raw}</script><script>
const data=JSON.parse(document.getElementById('wirescope-session-data').textContent);const text=(v)=>v==null?'':typeof v==='string'?v:JSON.stringify(v);const el=(tag,value,cls)=>{{const n=document.createElement(tag);n.textContent=text(value);if(cls)n.className=cls;return n}};document.querySelectorAll('nav button').forEach(b=>b.onclick=()=>{{document.querySelectorAll('nav button').forEach(x=>x.classList.toggle('active',x===b));document.querySelectorAll('.view').forEach(v=>v.classList.toggle('active',v.id===b.dataset.view))}});
const counts=data.summary.counts||{{}};[['Events',counts.events],['Entities',counts.entities],['Relations',counts.relations],['Findings',counts.findings],['Schema',data.summary.schema_version]].forEach(([k,v])=>{{const c=el('div','', 'card');c.append(el('span',k),el('strong',v??0));document.getElementById('cards').append(c)}});(data.summary.sessions||[]).forEach(s=>{{const p=el('p',`${{s.title}} · ${{s.status}} · ${{s.started_at}} → ${{s.ended_at||'interrupted/recording'}}`);document.getElementById('sessions').append(p)}});
const eventBody=document.getElementById('events'),eventQ=document.getElementById('event-q'),eventType=document.getElementById('event-type');[...new Set(data.timeline.map(e=>e.event_type))].sort().forEach(v=>eventType.append(el('option',v)));function renderEvents(){{eventBody.textContent='';const q=eventQ.value.toLowerCase(),type=eventType.value;let n=0;data.timeline.forEach(e=>{{const details=text(e.payload);if((type&&e.event_type!==type)||q&&!text([e.source,e.event_type,e.severity,details]).toLowerCase().includes(q))return;const tr=document.createElement('tr');[e.sequence,e.timestamp,e.source,e.event_type,e.severity,e.entity_id||'',details].forEach((v,i)=>tr.append(el('td',v,i===3?'type':i===4?e.severity:'')));eventBody.append(tr);n++}});document.getElementById('event-count').textContent=`${{n}} shown`}}eventQ.oninput=eventType.oninput=renderEvents;renderEvents();
const entityBody=document.getElementById('entity-rows'),entityQ=document.getElementById('entity-q'),entityType=document.getElementById('entity-type');[...new Set(data.entities.map(e=>e.entity_type))].sort().forEach(v=>entityType.append(el('option',v)));function renderEntities(){{entityBody.textContent='';const q=entityQ.value.toLowerCase(),type=entityType.value;let n=0;data.entities.forEach(e=>{{if((type&&e.entity_type!==type)||q&&!text([e.id,e.entity_type,e.label,e.attributes]).toLowerCase().includes(q))return;const tr=document.createElement('tr');[e.entity_type,e.label,e.id,e.first_seen,e.last_seen,e.attributes].forEach((v,i)=>tr.append(el('td',v,i===0?'type':'')));entityBody.append(tr);n++}});document.getElementById('entity-count').textContent=`${{n}} shown`}}entityQ.oninput=entityType.oninput=renderEntities;renderEntities();
const relBody=document.getElementById('relation-rows');data.relations.forEach(r=>{{const tr=document.createElement('tr');[r.source.label,r.relation,r.target.label,r.confidence==null?'':Math.round(r.confidence*100)+'%',r.last_seen,r.evidence].forEach((v,i)=>tr.append(el('td',v,i===1?'type':'')));relBody.append(tr)}});const findingRows=document.getElementById('finding-rows');if(!data.findings.length)findingRows.append(el('p','No stored findings.','muted'));data.findings.forEach(f=>{{const d=el('div','', 'panel');d.append(el('h3',`[${{f.severity}}] ${{f.title}}`,f.severity),el('p',f.explanation),el('p',f.recommendation,'muted'),el('pre',f.evidence));findingRows.append(d)}});document.getElementById('raw-data').textContent=JSON.stringify(data,null,2);
</script></body></html>"""
    atomic_write_text(output, document)
    return data
