"""Export scan results to JSON, CSV, Markdown and a standalone HTML report."""

from __future__ import annotations

import csv
import html
import json
import os
import time
from dataclasses import asdict

SEVERITY_COLORS = {
    "critical": "#b91c1c", "high": "#ea580c", "medium": "#ca8a04",
    "low": "#2563eb", "info": "#64748b", "unknown": "#64748b",
}


def export_json(results, path):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(asdict(results), fh, indent=2, default=str)
    return path


def export_csv(results, path):
    """Write the findings table as CSV (the part most people want in a sheet)."""
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["severity", "host", "finding", "detail", "source"])
        for f in results.findings:
            writer.writerow([f.get("severity", ""), f.get("host", ""), f.get("name", ""),
                             f.get("detail", ""), f.get("source", "")])
    return path


def export_markdown(results, path):
    lines = [
        f"# SmartHunt report — {results.target}",
        "",
        f"- **Mode:** {results.mode}",
        f"- **Started:** {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(results.started))}",
        f"- **Duration:** {results.duration:.1f}s",
        f"- **Tools used:** {', '.join(results.tools_used) or 'built-in only'}",
        "",
        "## Summary",
        "",
        "| Metric | Count |",
        "| --- | ---: |",
    ]
    for key, value in results.stats().items():
        lines.append(f"| {key} | {value} |")

    if results.findings:
        lines += ["", "## Findings", "", "| Severity | Host | Finding | Detail |", "| --- | --- | --- | --- |"]
        for f in results.findings:
            detail = str(f.get("detail", "")).replace("|", "\\|")[:160]
            lines.append(f"| {f.get('severity','')} | {f.get('host','')} | {f.get('name','')} | {detail} |")

    if results.secrets:
        lines += ["", "## Potential secrets in JavaScript", "",
                  "| Severity | Type | Value | Source |", "| --- | --- | --- | --- |"]
        for s in results.secrets:
            lines.append(f"| {s.get('severity','')} | {s.get('type','')} | `{s.get('value','')}` | {s.get('source','')} |")

    if results.hosts:
        lines += ["", "## Live hosts", "", "| Host | Status | Title | Tech |", "| --- | --- | --- | --- |"]
        for h in results.hosts:
            lines.append(f"| {h.get('host','')} | {h.get('status','')} | "
                         f"{str(h.get('title',''))[:60]} | {', '.join(h.get('tech', []))} |")

    if results.subdomains:
        lines += ["", "## Subdomains", "", "```"] + results.subdomains + ["```"]

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return path


def export_finding_report(results, path):
    """Write the one triaged finding — the file you actually submit."""
    markdown = (results.report or {}).get("markdown", "")
    if not markdown:
        return None
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(markdown.rstrip() + "\n")
    return path


def export_txt_lists(results, outdir):
    """Write the raw lists hunters usually pipe into other tools."""
    os.makedirs(outdir, exist_ok=True)
    written = []
    datasets = {
        "subdomains.txt": results.subdomains,
        "live-hosts.txt": [h.get("url") or h.get("host") for h in results.hosts],
        "urls.txt": results.urls,
        "js-files.txt": results.js_files,
        "endpoints.txt": results.js_endpoints,
        "parameters.txt": results.params.get("names", []),
    }
    for name, rows in datasets.items():
        if not rows:
            continue
        path = os.path.join(outdir, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(str(r) for r in rows) + "\n")
        written.append(path)
    return written


def export_html(results, path):
    """A self-contained HTML report — no external assets, opens anywhere."""
    stats = results.stats()
    started = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(results.started))

    def esc(value):
        return html.escape(str(value if value is not None else ""))

    cards = "".join(
        f'<div class="card"><div class="num">{esc(v)}</div><div class="lbl">{esc(k)}</div></div>'
        for k, v in stats.items()
    )

    def table(headers, rows):
        if not rows:
            return '<p class="empty">Nothing found.</p>'
        head = "".join(f"<th>{esc(h)}</th>" for h in headers)
        body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in row) + "</tr>" for row in rows)
        return f'<div class="tw"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'

    def sev(value):
        color = SEVERITY_COLORS.get(str(value).lower(), "#64748b")
        return f'<span class="sev" style="background:{color}">{esc(value).upper()}</span>'

    findings_rows = [
        [sev(f.get("severity")), esc(f.get("host")), esc(f.get("name")),
         f'<code>{esc(f.get("detail"))[:220]}</code>', esc(f.get("source"))]
        for f in results.findings
    ]
    secret_rows = [
        [sev(s.get("severity")), esc(s.get("type")), f'<code>{esc(s.get("value"))}</code>',
         f'<a href="{esc(s.get("source"))}">{esc(s.get("source"))[:70]}</a>']
        for s in results.secrets
    ]
    host_rows = [
        [f'<a href="{esc(h.get("url"))}">{esc(h.get("host"))}</a>', esc(h.get("status")),
         esc(h.get("title"))[:70], ", ".join(esc(t) for t in h.get("tech", [])),
         ", ".join(str(p) for p in h.get("ports", [])), ", ".join(esc(i) for i in h.get("ips", []))]
        for h in results.hosts
    ]
    content_rows = [
        [f'<a href="{esc(c.get("url"))}">{esc(c.get("url"))}</a>', esc(c.get("status")),
         esc(c.get("length")), esc(c.get("type"))]
        for c in results.content
    ]

    def listing(title, items, limit=1500):
        if not items:
            return ""
        shown = [esc(i) for i in items[:limit]]
        more = f'<p class="empty">… and {len(items) - limit} more</p>' if len(items) > limit else ""
        return (f'<h2>{esc(title)} <span class="count">{len(items)}</span></h2>'
                f'<pre class="list">{chr(10).join(shown)}</pre>{more}')

    doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SmartHunt — {esc(results.target)}</title>
<style>
:root {{ color-scheme: light dark; --bg:#0f172a; --panel:#1e293b; --fg:#e2e8f0;
        --muted:#94a3b8; --line:#334155; --accent:#38bdf8; }}
@media (prefers-color-scheme: light) {{
  :root {{ --bg:#f8fafc; --panel:#fff; --fg:#0f172a; --muted:#475569; --line:#e2e8f0; --accent:#0284c7; }}
}}
* {{ box-sizing:border-box; }}
body {{ margin:0; padding:28px; background:var(--bg); color:var(--fg);
       font:15px/1.55 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif; }}
header {{ border-bottom:2px solid var(--accent); padding-bottom:14px; margin-bottom:22px; }}
h1 {{ margin:0 0 6px; font-size:26px; }}
h2 {{ margin:32px 0 12px; font-size:19px; border-left:3px solid var(--accent); padding-left:10px; }}
.count {{ font-size:13px; color:var(--muted); font-weight:400; }}
.meta {{ color:var(--muted); font-size:13px; }}
.cards {{ display:flex; flex-wrap:wrap; gap:12px; margin:18px 0; }}
.card {{ background:var(--panel); border:1px solid var(--line); border-radius:10px;
         padding:14px 18px; min-width:110px; }}
.num {{ font-size:24px; font-weight:700; color:var(--accent); }}
.lbl {{ font-size:12px; color:var(--muted); text-transform:uppercase; letter-spacing:.04em; }}
.tw {{ overflow-x:auto; border:1px solid var(--line); border-radius:10px; }}
table {{ border-collapse:collapse; width:100%; font-size:13.5px; }}
th {{ background:var(--panel); text-align:left; padding:9px 11px; border-bottom:1px solid var(--line);
      position:sticky; top:0; }}
td {{ padding:8px 11px; border-bottom:1px solid var(--line); vertical-align:top; }}
tr:last-child td {{ border-bottom:none; }}
code {{ font:12.5px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace; color:var(--muted);
        word-break:break-all; }}
.sev {{ display:inline-block; padding:2px 8px; border-radius:20px; color:#fff;
        font-size:11px; font-weight:700; letter-spacing:.03em; }}
.list {{ background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:12px;
         max-height:420px; overflow:auto; font:12.5px/1.6 ui-monospace,Menlo,monospace; }}
.empty {{ color:var(--muted); font-style:italic; }}
a {{ color:var(--accent); text-decoration:none; }} a:hover {{ text-decoration:underline; }}
footer {{ margin-top:36px; padding-top:14px; border-top:1px solid var(--line);
          color:var(--muted); font-size:12px; }}
</style></head><body>
<header>
  <h1>SmartHunt — {esc(results.target)}</h1>
  <div class="meta">Mode: <strong>{esc(results.mode)}</strong> &middot; Started {esc(started)}
    &middot; Duration {results.duration:.1f}s
    &middot; Tools: {esc(', '.join(results.tools_used) or 'built-in only')}</div>
</header>

<div class="cards">{cards}</div>

<h2>Findings <span class="count">{len(results.findings)}</span></h2>
{table(["Severity", "Host", "Finding", "Detail", "Source"], findings_rows)}

<h2>Potential secrets in JavaScript <span class="count">{len(results.secrets)}</span></h2>
{table(["Severity", "Type", "Value", "Source file"], secret_rows)}

<h2>Live hosts <span class="count">{len(results.hosts)}</span></h2>
{table(["Host", "Status", "Title", "Tech", "Ports", "IPs"], host_rows)}

<h2>Content discovery <span class="count">{len(results.content)}</span></h2>
{table(["URL", "Status", "Length", "Type"], content_rows)}

{listing("Subdomains", results.subdomains)}
{listing("JavaScript files", results.js_files)}
{listing("Endpoints from JS", results.js_endpoints)}
{listing("Parameters", results.params.get("names", []))}
{listing("URLs", results.urls, limit=3000)}

<footer>Generated by SmartHunt &middot; only test targets you are authorized to test.</footer>
</body></html>"""

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)
    return path


def export_all(results, outdir):
    """Write every format into ``outdir``; returns the list of files written."""
    os.makedirs(outdir, exist_ok=True)
    safe = results.target.replace("*", "wildcard").replace(".", "_") or "scan"
    written = [
        export_json(results, os.path.join(outdir, f"{safe}.json")),
        export_html(results, os.path.join(outdir, f"{safe}.html")),
        export_markdown(results, os.path.join(outdir, f"{safe}.md")),
        export_csv(results, os.path.join(outdir, f"{safe}-findings.csv")),
    ]
    submission = export_finding_report(
        results, os.path.join(outdir, f"{safe}-REPORT.md"))
    if submission:
        written.append(submission)
    written += export_txt_lists(results, os.path.join(outdir, "lists"))
    return written
