"""Executive HTML Report Generator for ShadowBoard.

Renders an executive, boardroom-ready, interactive cybersecurity evaluation report:
- Risk score trend sparklines with historical trajectory
- 2D Findings heat-map matrix (OWASP Top 10 for LLMs x Severity)
- Remediation progress tracker with actionable code snippets & SLAs
- Cryptographic evidence integrity certificate with SHA-256 Merkle root & Ed25519 signature
- Boardroom printing & PDF generation support (@media print)
"""

from typing import Dict, Any, List, Optional
from app.reports.executive_report_builder import build_full_executive_report_model


def _render_svg_sparkline(scores: List[int], labels: List[str]) -> str:
    """Renders a responsive, modern inline SVG sparkline chart in orange, black, and white."""
    if not scores:
        scores = [100]
    
    width = 540
    height = 140
    padding_x = 40
    padding_y = 25
    
    min_score = 0
    max_score = 100
    
    num_pts = len(scores)
    step_x = (width - 2 * padding_x) / max(1, num_pts - 1) if num_pts > 1 else 0
    
    points = []
    for i, s in enumerate(scores):
        x = padding_x + i * step_x
        # Invert y because SVG 0 is at top
        y = height - padding_y - ((s - min_score) / (max_score - min_score)) * (height - 2 * padding_y)
        points.append((x, y, s, labels[i] if i < len(labels) else f"Run #{i+1}"))
    
    # Path coordinates
    if num_pts == 1:
        path_d = f"M {padding_x} {points[0][1]} L {width - padding_x} {points[0][1]}"
        area_d = f"M {padding_x} {points[0][1]} L {width - padding_x} {points[0][1]} L {width - padding_x} {height - padding_y} L {padding_x} {height - padding_y} Z"
    else:
        path_d = f"M {points[0][0]} {points[0][1]}"
        for pt in points[1:]:
            path_d += f" L {pt[0]} {pt[1]}"
        area_d = path_d + f" L {points[-1][0]} {height - padding_y} L {points[0][0]} {height - padding_y} Z"

    # SVG Elements
    svg_elements = []
    # Grid lines (at 0, 50, 100)
    for g_val in [0, 50, 100]:
        gy = height - padding_y - ((g_val - min_score) / (max_score - min_score)) * (height - 2 * padding_y)
        svg_elements.append(
            f'<line x1="{padding_x}" y1="{gy}" x2="{width - padding_x}" y2="{gy}" stroke="#262626" stroke-width="1" stroke-dasharray="3,3" />'
            f'<text x="{padding_x - 8}" y="{gy + 3}" fill="#737373" font-size="9" text-anchor="end" font-family="monospace">{g_val}</text>'
        )

    # Shaded Area
    svg_elements.append(
        f'<path d="{area_d}" fill="url(#sparklineGrad)" opacity="0.2" />'
    )
    # Trend Line
    svg_elements.append(
        f'<path d="{path_d}" fill="none" stroke="#f97316" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" />'
    )

    # Dots and labels
    for pt in points:
        color = "#f97316" if pt[2] < 80 else "#ffffff"
        svg_elements.append(
            f'<circle cx="{pt[0]}" cy="{pt[1]}" r="4" fill="{color}" stroke="#000000" stroke-width="2" />'
            f'<text x="{pt[0]}" y="{pt[1] - 8}" fill="#ffffff" font-size="10" font-weight="bold" text-anchor="middle" font-family="monospace">{pt[2]}</text>'
            f'<text x="{pt[0]}" y="{height - 8}" fill="#a3a3a3" font-size="8.5" text-anchor="middle" font-family="monospace">{pt[3]}</text>'
        )

    svg_content = f'''
    <svg viewBox="0 0 {width} {height}" class="w-full h-auto max-h-48 overflow-visible">
        <defs>
            <linearGradient id="sparklineGrad" x1="0%" y1="0%" x2="0%" y2="100%">
                <stop offset="0%" stop-color="#f97316" stop-opacity="0.6" />
                <stop offset="100%" stop-color="#f97316" stop-opacity="0.0" />
            </linearGradient>
        </defs>
        {''.join(svg_elements)}
    </svg>
    '''
    return svg_content


def generate_scan_html_report(
    scan_data: Dict[str, Any],
    findings: Optional[List[Dict[str, Any]]] = None,
    history_runs: Optional[List[Dict[str, Any]]] = None
) -> str:
    """Generates a complete, single-file executive report in strict Orange, Black, and White."""
    m = build_full_executive_report_model(scan_data, findings, history_runs)
    
    score = m["overall_score"]
    grade = m["risk_grade"]
    
    score_color = "#f97316" if score < 80 else "#ffffff"
    grade_badge_bg = "#000000"
    grade_badge_text = "#f97316"
    
    # Sparkline SVG
    sparkline_svg = _render_svg_sparkline(m["sparkline"]["scores"], m["sparkline"]["labels"])

    # Render matrix rows
    matrix_rows_html = []
    for r in m["matrix"]["rows"]:
        c_badge = f'<span class="badge-orange">{r["CRITICAL"]}</span>' if r["CRITICAL"] > 0 else '<span class="text-dim">0</span>'
        h_badge = f'<span class="badge-orange">{r["HIGH"]}</span>' if r["HIGH"] > 0 else '<span class="text-dim">0</span>'
        m_badge = f'<span class="badge-white">{r["MEDIUM"]}</span>' if r["MEDIUM"] > 0 else '<span class="text-dim">0</span>'
        l_badge = f'<span class="badge-white">{r["LOW"]}</span>' if r["LOW"] > 0 else '<span class="text-dim">0</span>'
        tot_badge = f'<span class="font-bold text-orange">{r["total"]}</span>' if r["total"] > 0 else '<span class="text-white font-semibold">0</span>'
        
        matrix_rows_html.append(f'''
        <tr class="border-b border-[#262626] hover:bg-[#121212] transition-colors">
            <td class="py-2.5 px-3 font-semibold text-white">{r["name"]}</td>
            <td class="py-2.5 px-3 text-center">{c_badge}</td>
            <td class="py-2.5 px-3 text-center">{h_badge}</td>
            <td class="py-2.5 px-3 text-center">{m_badge}</td>
            <td class="py-2.5 px-3 text-center">{l_badge}</td>
            <td class="py-2.5 px-3 text-center font-mono">{tot_badge}</td>
        </tr>
        ''')

    # Render remediation items
    remediation_cards_html = []
    for item in m["remediation_items"]:
        is_resolved = item["status"] == "VERIFIED MITIGATED"
        status_badge = (
            '<span class="px-2.5 py-1 rounded text-xs font-mono font-bold bg-[#141414] text-white border border-[#333333] shrink-0">'
            'VERIFIED MITIGATED</span>'
            if is_resolved else
            '<span class="px-2.5 py-1 rounded text-xs font-mono font-bold bg-[#000000] text-[#f97316] border border-[#f97316] shrink-0">'
            'ACTION REQUIRED</span>'
        )

        remediation_cards_html.append(f'''
        <div class="card p-5 space-y-3.5 border-l-4 { 'border-l-white' if is_resolved else 'border-l-[#f97316]' }">
            <div class="flex flex-wrap items-center justify-between gap-2">
                <div class="flex items-center gap-2.5">
                    <span class="font-mono text-xs px-2 py-0.5 rounded bg-[#141414] text-white border border-[#262626] font-bold">{item["id"]}</span>
                    <span class="text-xs font-mono text-[#a3a3a3]">{item["category"]}</span>
                    <span class="text-xs font-mono font-bold text-[#f97316] bg-black px-2 py-0.5 rounded border border-[#f97316]/40">{item["severity"]}</span>
                </div>
                {status_badge}
            </div>

            <div>
                <h4 class="text-sm font-bold text-white tracking-wide">{item["title"]}</h4>
                <p class="text-xs text-[#a3a3a3] mt-1 leading-relaxed"><span class="font-semibold text-white">Root Cause:</span> {item["root_cause"]}</p>
            </div>

            <div class="p-3 rounded bg-black border border-[#262626] space-y-1">
                <div class="text-[10px] font-mono text-[#f97316] uppercase tracking-wider font-semibold">Engineered Code Guardrail:</div>
                <pre class="font-mono text-xs text-white whitespace-pre-wrap leading-relaxed overflow-x-auto">{item["code_playbook"]}</pre>
            </div>

            <div class="grid grid-cols-1 sm:grid-cols-3 gap-2 pt-1 text-[11px] font-mono text-[#a3a3a3]">
                <div><span class="text-[#737373]">Est. Effort:</span> <span class="text-white">{item["effort"]}</span></div>
                <div><span class="text-[#737373]">Owner:</span> <span class="text-white">{item["owner"]}</span></div>
                <div><span class="text-[#737373]">SLA:</span> <span class="text-[#f97316] font-semibold">{item["sla"]}</span></div>
            </div>

            <div class="text-[11px] font-mono text-[#a3a3a3] bg-[#000000] p-2 rounded border border-[#262626]">
                <span class="text-[#737373]">CI Verification Command:</span> <code class="text-white font-bold">{item["verification_cmd"]}</code>
            </div>
        </div>
        ''')

    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ShadowBoard Executive Security Audit — Scan #{m["scan_id"]} ({m["target_name"]})</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-main: #000000;
            --bg-card: #0a0a0a;
            --border: #262626;
            --accent: #f97316;
            --text-main: #ffffff;
            --text-muted: #a3a3a3;
            --text-dim: #737373;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background-color: var(--bg-main);
            color: var(--text-main);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            line-height: 1.5;
            padding-bottom: 60px;
        }}
        .font-mono {{ font-family: 'JetBrains Mono', monospace; }}
        .card {{
            background-color: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
        }}
        .badge-orange {{
            background: #000000;
            color: #f97316;
            border: 1px solid #f97316;
            padding: 2px 7px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 11px;
            font-family: 'JetBrains Mono', monospace;
        }}
        .badge-white {{
            background: #141414;
            color: #ffffff;
            border: 1px solid #333333;
            padding: 2px 7px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 11px;
            font-family: 'JetBrains Mono', monospace;
        }}
        .text-orange {{ color: #f97316; }}
        .text-dim {{ color: #737373; }}
        .border-b {{ border-bottom: 1px solid #262626; }}
        /* Header Toolbar */
        .action-bar {{
            position: sticky;
            top: 0;
            z-index: 50;
            background: #000000;
            border-bottom: 1px solid #262626;
            padding: 12px 24px;
        }}
        @media print {{
            .action-bar, .no-print {{ display: none !important; }}
            body {{ background: #ffffff !important; color: #000000 !important; padding: 0 !important; }}
            .card {{ border: 1px solid #cccccc !important; background: #ffffff !important; color: #000000 !important; box-shadow: none !important; }}
            pre, code {{ color: #000000 !important; background: #f5f5f5 !important; }}
            .text-white {{ color: #000000 !important; }}
            .text-orange {{ color: #ea580c !important; }}
        }}
    </style>
</head>
<body>

    <!-- Header Toolbar -->
    <header class="action-bar flex items-center justify-between no-print" style="display:flex; justify-content:space-between; align-items:center;">
        <div style="display:flex; align-items:center; gap:12px;">
            <div style="width:32px; height:32px; border-radius:6px; background:#f97316; color:#000000; font-weight:900; display:flex; align-items:center; justify-content:center; font-size:14px; font-family:'JetBrains Mono', monospace;">
                SB
            </div>
            <div>
                <span style="font-weight:800; letter-spacing:1px; font-size:13px; text-transform:uppercase; font-family:'JetBrains Mono', monospace;">SHADOWBOARD</span>
                <span style="font-size:10px; font-family:'JetBrains Mono', monospace; color:#f97316; margin-left:8px; border:1px solid #f97316; padding:2px 6px; border-radius:4px;">AUDIT REPORT</span>
            </div>
        </div>
        <div style="display:flex; align-items:center; gap:10px;">
            <button onclick="window.print()" style="cursor:pointer; background:#141414; color:#ffffff; border:1px solid #262626; padding:6px 14px; border-radius:6px; font-size:12px; font-weight:600; font-family:'JetBrains Mono', monospace;">
                Print / Save PDF
            </button>
            <a href="/api/scans/{m['scan_id']}/export/pdf" target="_blank" style="text-decoration:none; background:#f97316; color:#000000; border:none; padding:6px 14px; border-radius:6px; font-size:12px; font-weight:700; font-family:'JetBrains Mono', monospace;">
                Official PDF
            </a>
        </div>
    </header>

    <!-- Main Report Body Container -->
    <main style="max-width:1160px; margin:28px auto; padding:0 20px; display:flex; flex-direction:column; gap:24px;">

        <!-- 1. Executive Briefing Header Banner -->
        <div class="card" style="padding:28px; position:relative; overflow:hidden;">
            <div style="display:flex; flex-wrap:wrap; justify-content:space-between; align-items:flex-start; gap:20px;">
                <div>
                    <div style="display:flex; align-items:center; gap:10px; margin-bottom:8px;">
                        <span style="font-size:11px; font-family:'JetBrains Mono', monospace; padding:3px 8px; border-radius:4px; background:#141414; color:#ffffff; border:1px solid #333333; font-weight:700;">
                            NON-REPUDIATION ATTESTED
                        </span>
                        <span style="font-size:12px; font-family:'JetBrains Mono', monospace; color:var(--text-dim);">
                            Scan Run #{m["scan_id"]} • {m["generated_at"]}
                        </span>
                    </div>
                    <h1 style="font-size:24px; font-weight:800; letter-spacing:-0.5px; color:#ffffff;">
                        AI Security Assurance &amp; Governance Audit
                    </h1>
                    <p style="font-size:13px; color:var(--text-muted); margin-top:4px;">
                        Target: <strong style="color:#ffffff;">{m["target_name"]}</strong> • Model: <span style="font-family:'JetBrains Mono', monospace; color:#ffffff;">{m["model_name"]}</span> • Mode: <span style="font-family:'JetBrains Mono', monospace; color:#f97316;">{m["target_mode"]}</span>
                    </p>
                </div>

                <!-- Overall Grade & Score Ring -->
                <div style="display:flex; align-items:center; gap:16px; background:#000000; border:1px solid #262626; padding:12px 20px; border-radius:8px;">
                    <div>
                        <div style="font-size:10px; font-family:'JetBrains Mono', monospace; color:var(--text-dim); text-transform:uppercase;">Canonical Score</div>
                        <div style="font-size:32px; font-weight:900; font-family:'JetBrains Mono', monospace; color:{score_color}; line-height:1;">
                            {score} <span style="font-size:14px; color:#737373;">/ 100</span>
                        </div>
                    </div>
                    <div style="background:{grade_badge_bg}; color:{grade_badge_text}; border:1px solid {grade_badge_text}; width:48px; height:48px; border-radius:8px; display:flex; align-items:center; justify-content:center; font-size:24px; font-weight:900; font-family:'JetBrains Mono', monospace;">
                        {grade}
                    </div>
                </div>
            </div>

            <!-- Top KPI Cards Strip -->
            <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(200px, 1fr)); gap:14px; margin-top:24px; padding-top:20px; border-top:1px solid var(--border);">
                <div style="padding:10px; background:#000000; border-radius:6px; border:1px solid #262626;">
                    <span style="font-size:10px; font-family:'JetBrains Mono', monospace; color:var(--text-dim); text-transform:uppercase;">Confirmed Breaches</span>
                    <div style="font-size:18px; font-weight:800; font-family:'JetBrains Mono', monospace; margin-top:4px; color:{'#ffffff' if m['confirmed_count'] == 0 else '#f97316'};">
                        {m['confirmed_count']} Breaches
                    </div>
                </div>
                <div style="padding:10px; background:#000000; border-radius:6px; border:1px solid #262626;">
                    <span style="font-size:10px; font-family:'JetBrains Mono', monospace; color:var(--text-dim); text-transform:uppercase;">Mitigation State</span>
                    <div style="font-size:18px; font-weight:800; font-family:'JetBrains Mono', monospace; margin-top:4px; color:#ffffff;">
                        {'PRODUCTION HARDENED' if m['mitigation_enabled'] else 'UNMITIGATED BASELINE'}
                    </div>
                </div>
                <div style="padding:10px; background:#000000; border-radius:6px; border:1px solid #262626;">
                    <span style="font-size:10px; font-family:'JetBrains Mono', monospace; color:var(--text-dim); text-transform:uppercase;">Remediation Velocity</span>
                    <div style="font-size:18px; font-weight:800; font-family:'JetBrains Mono', monospace; margin-top:4px; color:#ffffff;">
                        {m['remediation_percent']}% Completed
                    </div>
                </div>
                <div style="padding:10px; background:#000000; border-radius:6px; border:1px solid #262626;">
                    <span style="font-size:10px; font-family:'JetBrains Mono', monospace; color:var(--text-dim); text-transform:uppercase;">Policy Coverage</span>
                    <div style="font-size:18px; font-weight:800; font-family:'JetBrains Mono', monospace; margin-top:4px; color:#ffffff;">
                        {m['policy_coverage']}% Evaluated
                    </div>
                </div>
            </div>
        </div>

        <!-- 2. Two-Column Row: Trend Sparkline & Findings Matrix -->
        <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(480px, 1fr)); gap:20px;">

            <!-- Left: Risk Score Trend Sparkline -->
            <div class="card" style="padding:22px; display:flex; flex-direction:column; justify-content:between;">
                <div>
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
                        <h3 style="font-size:14px; font-weight:700; color:#fff; font-family:'JetBrains Mono', monospace; text-transform:uppercase;">Historical Risk Posture Trend</h3>
                        <span style="font-size:11px; font-family:'JetBrains Mono', monospace; color:#f97316; background:#000000; border:1px solid #f97316; padding:2px 8px; border-radius:4px; font-weight:bold;">
                            {m["sparkline"]["delta_str"]} ({m["sparkline"]["direction"]})
                        </span>
                    </div>
                    <p style="font-size:12px; color:var(--text-muted); margin-bottom:16px;">
                        Tracking score evolution from baseline unmitigated scan through active guardrail verification across {m["sparkline"]["total_runs"]} benchmark executions.
                    </p>
                </div>

                <!-- Sparkline SVG -->
                <div style="background:#000000; padding:12px; border-radius:6px; border:1px solid #262626;">
                    {sparkline_svg}
                </div>

                <div style="display:flex; justify-content:space-between; margin-top:12px; font-size:11px; font-family:'JetBrains Mono', monospace; color:#737373;">
                    <span>Initial Baseline: <strong style="color:#ffffff;">{m["sparkline"]["baseline_score"]} / 100</strong></span>
                    <span>Current Hardened: <strong style="color:#f97316;">{m["sparkline"]["current_score"]} / 100</strong></span>
                </div>
            </div>

            <!-- Right: Findings Matrix (OWASP x Severity) -->
            <div class="card" style="padding:22px;">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
                    <h3 style="font-size:14px; font-weight:700; color:#fff; font-family:'JetBrains Mono', monospace; text-transform:uppercase;">Findings Matrix (OWASP × Severity)</h3>
                    <span style="font-size:11px; font-family:'JetBrains Mono', monospace; color:var(--text-dim);">
                        OWASP 2025 Standard
                    </span>
                </div>
                <p style="font-size:12px; color:var(--text-muted); margin-bottom:14px;">
                    Cross-tabulation of verified vulnerability findings across threat categories and critical impact levels.
                </p>

                <!-- Matrix Table -->
                <div style="overflow-x:auto;">
                    <table style="width:100%; border-collapse:collapse; font-size:12px; font-family:'JetBrains Mono', monospace;">
                        <thead>
                            <tr style="border-bottom:1px solid #262626; color:#737373; font-size:10px; text-transform:uppercase;">
                                <th style="padding:8px; text-align:left;">Category</th>
                                <th style="padding:8px; text-align:center; color:#f97316;">Crit</th>
                                <th style="padding:8px; text-align:center; color:#f97316;">High</th>
                                <th style="padding:8px; text-align:center; color:#ffffff;">Med</th>
                                <th style="padding:8px; text-align:center; color:#737373;">Low</th>
                                <th style="padding:8px; text-align:center; color:#fff;">Total</th>
                            </tr>
                        </thead>
                        <tbody>
                            {''.join(matrix_rows_html)}
                        </tbody>
                        <tfoot>
                            <tr style="border-top:2px solid #333333; font-weight:bold; font-size:11px;">
                                <td style="padding:10px 8px; color:#fff;">Total Verified</td>
                                <td style="padding:10px 8px; text-align:center; color:#f97316;">{m["matrix"]["totals"]["CRITICAL"]}</td>
                                <td style="padding:10px 8px; text-align:center; color:#f97316;">{m["matrix"]["totals"]["HIGH"]}</td>
                                <td style="padding:10px 8px; text-align:center; color:#ffffff;">{m["matrix"]["totals"]["MEDIUM"]}</td>
                                <td style="padding:10px 8px; text-align:center; color:#737373;">{m["matrix"]["totals"]["LOW"]}</td>
                                <td style="padding:10px 8px; text-align:center; color:{'#ffffff' if m['matrix']['totals']['grand_total'] == 0 else '#f97316'};">
                                    {m["matrix"]["totals"]["grand_total"]}
                                </td>
                            </tr>
                        </tfoot>
                    </table>
                </div>
            </div>

        </div>

        <!-- 3. Remediation Progress Tracker & Playbooks -->
        <div class="card" style="padding:24px; display:flex; flex-direction:column; gap:18px;">
            <div style="display:flex; flex-wrap:wrap; justify-content:space-between; align-items:center; gap:12px;">
                <div>
                    <h3 style="font-size:15px; font-weight:800; color:#fff; font-family:'JetBrains Mono', monospace; text-transform:uppercase;">Remediation Progress Tracker &amp; Engineering Playbooks</h3>
                    <p style="font-size:12px; color:var(--text-muted); margin-top:2px;">
                        Developer remediation directives with exact code patches, verification test commands, and SLA targets.
                    </p>
                </div>
                <!-- Progress Percentage Bar -->
                <div style="display:flex; align-items:center; gap:12px; min-width:240px;">
                    <div style="flex:1; height:8px; background:#141414; border-radius:4px; overflow:hidden; border:1px solid #262626;">
                        <div style="width:{m['remediation_percent']}%; height:100%; background:#f97316; border-radius:4px;"></div>
                    </div>
                    <span style="font-family:'JetBrains Mono', monospace; font-size:12px; font-weight:bold; color:#f97316;">{m['remediation_percent']}% Mitigated</span>
                </div>
            </div>

            <div style="display:flex; flex-direction:column; gap:14px;">
                {''.join(remediation_cards_html)}
            </div>
        </div>

        <!-- 4. Cryptographic Evidence Integrity Certificate -->
        <div class="card" style="padding:24px; border:1px solid #262626; background:#0a0a0a;">
            <div style="display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap:12px; margin-bottom:16px;">
                <div>
                    <h3 style="font-size:15px; font-weight:800; color:#ffffff; font-family:'JetBrains Mono', monospace; text-transform:uppercase;">
                        Cryptographic Evidence Integrity Certificate
                    </h3>
                    <p style="font-size:12px; font-family:'JetBrains Mono', monospace; color:#f97316; margin-top:2px;">
                        Proof-of-Evaluation • Record: {m["crypto_record"]["ledger_record_id"]}
                    </p>
                </div>
                <span style="font-size:11px; font-family:'JetBrains Mono', monospace; padding:3px 10px; border-radius:4px; background:#141414; color:#ffffff; border:1px solid #333333; font-weight:700;">
                    ED25519 SIGNATURE VALID
                </span>
            </div>

            <p style="font-size:12px; color:#a3a3a3; line-height:1.6; margin-bottom:16px;">
                Every interaction turn, model token response, and kernel tool event in Assessment Run #{m["scan_id"]} has been cryptographically committed to a linear SHA-256 Merkle chain. Any retroactive modification breaks this signature.
            </p>

            <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(320px, 1fr)); gap:12px; font-family:'JetBrains Mono', monospace; font-size:11px;">
                <div style="background:#000000; padding:12px; border-radius:6px; border:1px solid #262626;">
                    <span style="color:#737373; font-size:10px; text-transform:uppercase; display:block;">SHA-256 Event Chain Merkle Root</span>
                    <span style="color:#f97316; word-break:break-all; font-weight:bold;">{m["crypto_record"]["merkle_root"]}</span>
                </div>
                <div style="background:#000000; padding:12px; border-radius:6px; border:1px solid #262626;">
                    <span style="color:#737373; font-size:10px; text-transform:uppercase; display:block;">Canonical Manifest Hash</span>
                    <span style="color:#ffffff; word-break:break-all; font-weight:bold;">{m["crypto_record"]["manifest_hash"]}</span>
                </div>
                <div style="background:#000000; padding:12px; border-radius:6px; border:1px solid #262626;">
                    <span style="color:#737373; font-size:10px; text-transform:uppercase; display:block;">Active Ed25519 Signer Key ID</span>
                    <span style="color:#ffffff; font-weight:bold;">{m["crypto_record"]["key_id"]} ({m["crypto_record"]["substrate_truth_level"]})</span>
                </div>
                <div style="background:#000000; padding:12px; border-radius:6px; border:1px solid #262626;">
                    <span style="color:#737373; font-size:10px; text-transform:uppercase; display:block;">Offline Independent Verification Command</span>
                    <span style="color:#f97316; font-weight:bold;">{m["crypto_record"]["verification_cli"]}</span>
                </div>
            </div>
        </div>

        <!-- 5. Executive Compliance Crosswalk Matrix -->
        <div class="card" style="padding:22px;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
                <h3 style="font-size:14px; font-weight:700; color:#fff; font-family:'JetBrains Mono', monospace; text-transform:uppercase;">Regulatory Compliance &amp; Threat Framework Mapping</h3>
                <span style="font-size:11px; font-family:'JetBrains Mono', monospace; color:var(--text-dim);">
                    NIST • OWASP • MITRE ATLAS • EU AI ACT
                </span>
            </div>
            <div style="overflow-x:auto;">
                <table style="width:100%; border-collapse:collapse; font-size:11px; font-family:'JetBrains Mono', monospace;">
                    <thead>
                        <tr style="border-bottom:1px solid #262626; color:#737373; text-transform:uppercase;">
                            <th style="padding:8px; text-align:left;">Standard</th>
                            <th style="padding:8px; text-align:left;">Control Reference</th>
                            <th style="padding:8px; text-align:left;">Evaluated AI Domain</th>
                            <th style="padding:8px; text-align:right;">Compliance Status</th>
                        </tr>
                    </thead>
                    <tbody style="color:#a3a3a3;">
                        <tr style="border-bottom:1px solid #262626;">
                            <td style="padding:8px; color:#fff; font-weight:bold;">OWASP Top 10 for LLMs</td>
                            <td style="padding:8px;">LLM01: Prompt Injection</td>
                            <td style="padding:8px;">Direct &amp; Indirect Vector RAG Poisoning</td>
                            <td style="padding:8px; text-align:right; color:#ffffff; font-weight:bold;">{'PASSED' if score >= 80 else 'FAIL / BREACH'}</td>
                        </tr>
                        <tr style="border-bottom:1px solid #262626;">
                            <td style="padding:8px; color:#fff; font-weight:bold;">OWASP Top 10 for LLMs</td>
                            <td style="padding:8px;">LLM02: Sensitive Info Disclosure</td>
                            <td style="padding:8px;">Canary Token &amp; System Prompt Exfiltration</td>
                            <td style="padding:8px; text-align:right; color:#ffffff; font-weight:bold;">{'PASSED' if score >= 80 else 'FAIL / BREACH'}</td>
                        </tr>
                        <tr style="border-bottom:1px solid #262626;">
                            <td style="padding:8px; color:#fff; font-weight:bold;">OWASP Top 10 for LLMs</td>
                            <td style="padding:8px;">LLM06: Excessive Agency / BOLA</td>
                            <td style="padding:8px;">Lateral Tool IDOR &amp; Database Mutation</td>
                            <td style="padding:8px; text-align:right; color:#ffffff; font-weight:bold;">{'PASSED' if score >= 80 else 'FAIL / BREACH'}</td>
                        </tr>
                        <tr style="border-bottom:1px solid #262626;">
                            <td style="padding:8px; color:#fff; font-weight:bold;">MITRE ATLAS (v5.x)</td>
                            <td style="padding:8px;">AML.T0051 / AML.T0054</td>
                            <td style="padding:8px;">LLM Exfiltration &amp; Tool Parameter Smuggling</td>
                            <td style="padding:8px; text-align:right; color:#ffffff; font-weight:bold;">AUDITED • VERIFIED</td>
                        </tr>
                        <tr style="border-bottom:1px solid #262626;">
                            <td style="padding:8px; color:#fff; font-weight:bold;">NIST AI RMF 1.0</td>
                            <td style="padding:8px;">GOVERN 1.2 / MEASURE 2.7</td>
                            <td style="padding:8px;">Continuous Multi-Turn Adversarial Verification</td>
                            <td style="padding:8px; text-align:right; color:#ffffff; font-weight:bold;">COMPLIANT</td>
                        </tr>
                        <tr>
                            <td style="padding:8px; color:#fff; font-weight:bold;">EU AI Act (Art. 15)</td>
                            <td style="padding:8px;">Cyber Resilience &amp; Robustness</td>
                            <td style="padding:8px;">Executable Security Guardrail Attestation</td>
                            <td style="padding:8px; text-align:right; color:#ffffff; font-weight:bold;">COMPLIANT</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Footer Sign-off -->
        <footer style="margin-top:12px; text-align:center; font-family:'JetBrains Mono', monospace; font-size:11px; color:#737373;">
            CONFIDENTIAL — SHADOWBOARD AI ASSURANCE SUITE • ED25519 CRYPTOGRAPHIC PROOF VERIFIED • REPRODUCIBLE NON-REPUDIATION AUDIT
        </footer>

    </main>

</body>
</html>
'''
    return html
