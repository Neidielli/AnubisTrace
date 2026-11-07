"""
Interactive Standalone HTML Dashboard Generator for AnubisTrace.
Produces a 100% self-contained, air-gapped forensic report with zero CDN dependencies.
"""

from __future__ import annotations

import html
import json
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Dict, List

from anubistrace import __app_name__, __version__
from anubistrace.core.event import ForensicEvent, Severity

if TYPE_CHECKING:
    from anubistrace.engine.correlation import CorrelatedFinding


def generate_html_report(
    events: List[ForensicEvent],
    stats: Dict[str, object],
    findings: List[CorrelatedFinding],
    output_path: Path,
) -> Path:
    """
    Renders an interactive forensic dashboard as a single standalone HTML file.
    All CSS styles, SVG icons, and JavaScript interactivity are fully inlined.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)

    sev_counts = stats.get("severity_counts", {})
    total_events = stats.get("total_events", len(events))
    crit_count = sev_counts.get("CRITICAL", 0)
    high_count = sev_counts.get("HIGH", 0)
    med_count = sev_counts.get("MEDIUM", 0)
    low_count = sev_counts.get("LOW", 0)
    info_count = sev_counts.get("INFO", 0)

    first_seen = stats.get("first_event", "-")
    last_seen = stats.get("last_event", "-")
    unique_iocs = stats.get("unique_iocs", [])
    top_tactics = stats.get("top_tactics", {})
    top_techniques = stats.get("top_techniques", {})

    # Build Attack Chains HTML
    chains_html = ""
    if findings:
        for i, f in enumerate(findings, 1):
            tactics_badges = "".join(f'<span class="badge badge-tactic">{html.escape(t)}</span>' for t in f.mitre_tactics)
            tech_badges = "".join(f'<span class="badge badge-tech">{html.escape(t)}</span>' for t in f.mitre_techniques)
            chains_html += f"""
            <div class="chain-card">
                <div class="chain-header">
                    <span class="chain-num">Chain #{i}</span>
                    <span class="chain-title">{html.escape(f.title)}</span>
                    <span class="badge badge-crit">{html.escape(f.severity.value)}</span>
                </div>
                <div class="chain-desc">{html.escape(f.description)}</div>
                <div class="chain-meta">
                    <div class="chain-tags">
                        <strong>MITRE Tactics:</strong> {tactics_badges or 'None'}
                    </div>
                    <div class="chain-tags">
                        <strong>Techniques:</strong> {tech_badges or 'None'}
                    </div>
                    <div class="chain-count">
                        <strong>Artifacts:</strong> {len(f.contributing_events)} event(s)
                    </div>
                </div>
            </div>
            """
    else:
        chains_html = '<div class="empty-state">No multi-stage attack chains detected.</div>'

    # Build Tactics breakdown HTML
    tactics_html = ""
    if top_tactics:
        for tactic, count in top_tactics.items():
            pct = min(100, int((count / max(1, total_events)) * 100 * 3))
            tactics_html += f"""
            <div class="stat-bar-container">
                <div class="stat-bar-label">
                    <span>{html.escape(tactic)}</span>
                    <span class="count-val">{count} hit(s)</span>
                </div>
                <div class="stat-bar-track">
                    <div class="stat-bar-fill" style="width: {max(8, pct)}%;"></div>
                </div>
            </div>
            """
    else:
        tactics_html = '<div class="empty-state">No MITRE tactics observed.</div>'

    # Build Techniques table HTML
    techniques_html = ""
    if top_techniques:
        for tech, count in top_techniques.items():
            techniques_html += f"""
            <div class="tech-item">
                <span class="tech-name">{html.escape(tech)}</span>
                <span class="badge badge-tech">{count}</span>
            </div>
            """
    else:
        techniques_html = '<div class="empty-state">No techniques observed.</div>'

    # Build Timeline Rows JSON for fast client-side rendering/filtering
    timeline_rows_json = []
    for e in events:
        timeline_rows_json.append({
            "ts": e.timestamp_iso[:19].replace("T", " "),
            "sev": e.severity.value,
            "src": e.source_type.value,
            "act": html.escape(e.actor or "-"),
            "action": html.escape(e.action),
            "target": html.escape(e.command_line or e.target or "-"),
            "mitre": html.escape("; ".join(e.mitre_techniques) if e.mitre_techniques else "-"),
            "file": html.escape(e.source_file),
        })

    rows_data_str = json.dumps(timeline_rows_json, ensure_ascii=False)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AnubisTrace - Incident Triage & Forensic Timeline</title>
    <style>
        :root {{
            --bg-primary: #0b0f17;
            --bg-secondary: #131b26;
            --bg-card: #182232;
            --bg-hover: #1f2c40;
            --border: #233146;
            --text-primary: #e6edf3;
            --text-muted: #8b949e;
            --accent-green: #00ff66;
            --accent-cyan: #00e5ff;
            --accent-pink: #ff007f;
            --accent-yellow: #ffb800;
            --sev-crit: #ff3366;
            --sev-high: #ff5533;
            --sev-med: #ffb800;
            --sev-low: #00e5ff;
            --sev-info: #8b949e;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background: var(--bg-primary);
            color: var(--text-primary);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            font-size: 14px;
            line-height: 1.5;
            padding: 24px;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        
        /* Header */
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 20px;
            border-bottom: 1px solid var(--border);
            margin-bottom: 24px;
        }}
        .brand {{ display: flex; align-items: center; gap: 12px; }}
        .brand-icon {{
            font-size: 28px;
            background: linear-gradient(135deg, var(--accent-green), var(--accent-cyan));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .brand-title {{ font-size: 22px; font-weight: 700; color: #fff; letter-spacing: 0.5px; }}
        .brand-sub {{ font-size: 12px; color: var(--text-muted); }}
        .header-meta {{ text-align: right; font-size: 12px; color: var(--text-muted); }}

        /* KPI Cards */
        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .kpi-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 16px;
            position: relative;
            overflow: hidden;
        }}
        .kpi-card::before {{
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0; height: 3px;
        }}
        .kpi-total::before {{ background: var(--accent-cyan); }}
        .kpi-crit::before {{ background: var(--sev-crit); }}
        .kpi-high::before {{ background: var(--sev-high); }}
        .kpi-chains::before {{ background: var(--accent-pink); }}
        .kpi-iocs::before {{ background: var(--accent-green); }}

        .kpi-title {{ font-size: 11px; text-transform: uppercase; color: var(--text-muted); font-weight: 600; letter-spacing: 0.5px; }}
        .kpi-value {{ font-size: 28px; font-weight: 800; color: #fff; margin-top: 4px; }}
        .kpi-sub {{ font-size: 12px; color: var(--text-muted); margin-top: 4px; }}

        /* Section Layout */
        .section-title {{
            font-size: 16px;
            font-weight: 700;
            margin-bottom: 14px;
            display: flex;
            align-items: center;
            gap: 8px;
            color: #fff;
        }}
        .layout-two-col {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 24px;
        }}
        @media (max-width: 900px) {{
            .layout-two-col {{ grid-template-columns: 1fr; }}
        }}

        .panel {{
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
        }}

        /* Attack Chains */
        .chain-card {{
            background: var(--bg-card);
            border: 1px solid #ff336644;
            border-left: 4px solid var(--sev-crit);
            border-radius: 6px;
            padding: 14px;
            margin-bottom: 12px;
        }}
        .chain-header {{
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 8px;
        }}
        .chain-num {{ font-size: 11px; background: rgba(255, 51, 102, 0.2); color: var(--sev-crit); padding: 2px 6px; border-radius: 4px; font-weight: 700; }}
        .chain-title {{ font-size: 14px; font-weight: 700; color: #fff; flex: 1; }}
        .chain-desc {{ font-size: 13px; color: var(--text-muted); margin-bottom: 10px; }}
        .chain-meta {{ display: flex; flex-wrap: wrap; gap: 14px; font-size: 11px; color: var(--text-muted); }}

        /* Badges */
        .badge {{
            display: inline-block;
            font-size: 11px;
            font-weight: 700;
            padding: 2px 8px;
            border-radius: 4px;
            text-transform: uppercase;
        }}
        .badge-crit {{ background: rgba(255, 51, 102, 0.2); color: var(--sev-crit); border: 1px solid rgba(255, 51, 102, 0.4); }}
        .badge-high {{ background: rgba(255, 85, 51, 0.2); color: var(--sev-high); border: 1px solid rgba(255, 85, 51, 0.4); }}
        .badge-med {{ background: rgba(255, 184, 0, 0.2); color: var(--sev-med); border: 1px solid rgba(255, 184, 0, 0.4); }}
        .badge-low {{ background: rgba(0, 229, 255, 0.2); color: var(--sev-low); border: 1px solid rgba(0, 229, 255, 0.4); }}
        .badge-info {{ background: rgba(139, 148, 158, 0.2); color: var(--sev-info); border: 1px solid rgba(139, 148, 158, 0.4); }}
        .badge-tactic {{ background: rgba(255, 0, 127, 0.15); color: var(--accent-pink); border: 1px solid rgba(255, 0, 127, 0.3); }}
        .badge-tech {{ background: rgba(0, 255, 102, 0.15); color: var(--accent-green); border: 1px solid rgba(0, 255, 102, 0.3); }}

        /* Stat Bars */
        .stat-bar-container {{ margin-bottom: 12px; }}
        .stat-bar-label {{ display: flex; justify-content: space-between; font-size: 12px; margin-bottom: 4px; }}
        .stat-bar-track {{ background: var(--bg-card); height: 8px; border-radius: 4px; overflow: hidden; }}
        .stat-bar-fill {{ background: linear-gradient(90deg, var(--accent-cyan), var(--accent-green)); height: 100%; border-radius: 4px; }}
        .tech-item {{ display: flex; justify-content: space-between; align-items: center; padding: 6px 0; border-bottom: 1px solid var(--border); font-size: 12px; }}
        .empty-state {{ color: var(--text-muted); font-style: italic; padding: 12px 0; }}

        /* Super Timeline Table */
        .timeline-section {{
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
            margin-top: 24px;
        }}
        .controls-bar {{
            display: flex;
            flex-wrap: wrap;
            gap: 12px;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
        }}
        .search-box {{
            flex: 1;
            min-width: 240px;
            max-width: 400px;
            background: var(--bg-card);
            border: 1px solid var(--border);
            color: var(--text-primary);
            padding: 8px 12px;
            border-radius: 6px;
            font-size: 13px;
            outline: none;
        }}
        .search-box:focus {{ border-color: var(--accent-cyan); }}
        .filter-buttons {{ display: flex; gap: 6px; flex-wrap: wrap; }}
        .filter-btn {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            color: var(--text-muted);
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
        }}
        .filter-btn:hover, .filter-btn.active {{
            color: #fff;
            border-color: var(--accent-cyan);
            background: var(--bg-hover);
        }}

        .table-responsive {{ overflow-x: auto; max-height: 600px; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            text-align: left;
            font-size: 12px;
        }}
        thead {{
            position: sticky;
            top: 0;
            background: var(--bg-card);
            border-bottom: 2px solid var(--border);
            z-index: 10;
        }}
        th {{
            padding: 10px 12px;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-muted);
        }}
        td {{
            padding: 8px 12px;
            border-bottom: 1px solid var(--border);
            vertical-align: top;
        }}
        tbody tr:hover {{ background: var(--bg-hover); }}
        .col-target {{
            max-width: 380px;
            word-break: break-all;
            font-family: monospace;
            color: #a5d6ff;
            font-size: 11px;
        }}
        .col-ts {{ font-family: monospace; white-space: nowrap; color: var(--text-muted); }}

        /* Footer */
        .footer {{
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid var(--border);
            font-size: 12px;
            color: var(--text-muted);
        }}
        .footer a {{ color: var(--accent-green); text-decoration: none; }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <header class="header">
            <div class="brand">
                <span class="brand-icon">⚖️</span>
                <div>
                    <div class="brand-title">{__app_name__} Forensic Triage Dashboard</div>
                    <div class="brand-sub">Incident Investigation & Super Timeline Report • Generated by Neidielli Rosado</div>
                </div>
            </div>
            <div class="header-meta">
                <div><strong>Analysis Window:</strong> {html.escape(first_seen[:19])} &rarr; {html.escape(last_seen[:19])} UTC</div>
                <div><strong>Engine Version:</strong> v{__version__} | <strong>Offline Mode:</strong> Active</div>
            </div>
        </header>

        <!-- KPI Grid -->
        <div class="kpi-grid">
            <div class="kpi-card kpi-total">
                <div class="kpi-title">Total Ingested Events</div>
                <div class="kpi-value">{total_events}</div>
                <div class="kpi-sub">{len(stats.get("source_counts", {}))} Distinct Artifact Source(s)</div>
            </div>
            <div class="kpi-card kpi-crit">
                <div class="kpi-title">Critical Severity</div>
                <div class="kpi-value">{crit_count}</div>
                <div class="kpi-sub">High: {high_count} | Medium: {med_count}</div>
            </div>
            <div class="kpi-card kpi-chains">
                <div class="kpi-title">Attack Chains Correlated</div>
                <div class="kpi-value">{len(findings)}</div>
                <div class="kpi-sub">Multi-stage incident sequences</div>
            </div>
            <div class="kpi-card kpi-iocs">
                <div class="kpi-title">Unique IoCs Detected</div>
                <div class="kpi-value">{len(unique_iocs)}</div>
                <div class="kpi-sub">LOLBins, suspicious IPs, tools</div>
            </div>
        </div>

        <!-- Correlated Attack Sequences -->
        <div class="section-title">🚨 Correlated Cyber Attack Sequences (Temporal Analysis)</div>
        <div class="panel" style="margin-bottom: 24px;">
            {chains_html}
        </div>

        <!-- Two Column Metrics -->
        <div class="layout-two-col">
            <div class="panel">
                <div class="section-title">🎯 Observed MITRE ATT&CK Tactics</div>
                {tactics_html}
            </div>
            <div class="panel">
                <div class="section-title">🛡️ Top Detected Techniques</div>
                {techniques_html}
            </div>
        </div>

        <!-- Super Timeline Table -->
        <div class="timeline-section">
            <div class="section-title">📜 Chronological Forensic Super Timeline</div>
            <div class="controls-bar">
                <input type="text" id="searchInput" class="search-box" placeholder="Search actor, process, command, IP, or action..." onkeyup="filterTable()">
                <div class="filter-buttons">
                    <button class="filter-btn active" onclick="setSeverityFilter('ALL', this)">All ({total_events})</button>
                    <button class="filter-btn" onclick="setSeverityFilter('CRITICAL', this)">Critical ({crit_count})</button>
                    <button class="filter-btn" onclick="setSeverityFilter('HIGH', this)">High ({high_count})</button>
                    <button class="filter-btn" onclick="setSeverityFilter('MEDIUM', this)">Medium ({med_count})</button>
                    <button class="filter-btn" onclick="setSeverityFilter('LOW', this)">Low ({low_count})</button>
                    <button class="filter-btn" onclick="setSeverityFilter('INFO', this)">Info ({info_count})</button>
                </div>
            </div>

            <div class="table-responsive">
                <table>
                    <thead>
                        <tr>
                            <th>Timestamp (UTC)</th>
                            <th>Severity</th>
                            <th>Source</th>
                            <th>Actor</th>
                            <th>Action</th>
                            <th>Target / Command Line</th>
                            <th>MITRE Techniques</th>
                        </tr>
                    </thead>
                    <tbody id="timelineBody">
                        <!-- Populated by JavaScript -->
                    </tbody>
                </table>
            </div>
            <div id="tableStatus" style="margin-top: 10px; font-size: 12px; color: var(--text-muted);"></div>
        </div>

        <!-- Footer -->
        <footer class="footer">
            Generated autonomously by <strong>AnubisTrace</strong> • Created by <a href="https://github.com/Neidielli" target="_blank">Neidielli Rosado</a> • Forensic Incident Triage Engine
        </footer>
    </div>

    <!-- Interactive Vanilla JavaScript -->
    <script>
        const rawEvents = {rows_data_str};
        let currentFilter = 'ALL';

        function renderRows(eventsToRender) {{
            const tbody = document.getElementById('timelineBody');
            tbody.innerHTML = '';

            const badgeClass = {{
                'CRITICAL': 'badge-crit',
                'HIGH': 'badge-high',
                'MEDIUM': 'badge-med',
                'LOW': 'badge-low',
                'INFO': 'badge-info'
            }};

            eventsToRender.forEach(ev => {{
                const tr = document.createElement('tr');
                const bClass = badgeClass[ev.sev] || 'badge-info';
                tr.innerHTML = `
                    <td class="col-ts">${{ev.ts}}</td>
                    <td><span class="badge ${{bClass}}">${{ev.sev}}</span></td>
                    <td style="color: var(--accent-cyan); font-weight: 600;">${{ev.src}}</td>
                    <td style="color: var(--accent-yellow); font-weight: 600;">${{ev.act}}</td>
                    <td><strong>${{ev.action}}</strong></td>
                    <td class="col-target">${{ev.target}}</td>
                    <td style="color: var(--accent-green); font-size: 11px;">${{ev.mitre}}</td>
                `;
                tbody.appendChild(tr);
            }});

            document.getElementById('tableStatus').innerText = `Showing ${{eventsToRender.length}} of ${{rawEvents.length}} forensic records`;
        }}

        function filterTable() {{
            const query = document.getElementById('searchInput').value.toLowerCase();
            const filtered = rawEvents.filter(ev => {{
                const matchSeverity = (currentFilter === 'ALL' || ev.sev === currentFilter);
                if (!matchSeverity) return false;

                if (!query) return true;
                const searchStr = `${{ev.act}} ${{ev.action}} ${{ev.target}} ${{ev.mitre}} ${{ev.src}}`.toLowerCase();
                return searchStr.includes(query);
            }});

            renderRows(filtered);
        }}

        function setSeverityFilter(sev, btnElement) {{
            currentFilter = sev;
            document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
            btnElement.classList.add('active');
            filterTable();
        }}

        // Initial render
        renderRows(rawEvents);
    </script>
</body>
</html>
"""
    output_path.write_text(html_content, encoding="utf-8")
    return output_path
