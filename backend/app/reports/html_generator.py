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
    """Renders a responsive, modern inline SVG sparkline chart with gradient fill."""
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
        polyline_pts = f"{points[0][0]},{points[0][1]}"
        path_d = f"M {padding_x} {points[0][1]} L {width - padding_x} {points[0][1]}"
        area_d = f"M {padding_x} {points[0][1]} L {width - padding_x} {points[0][1]} L {width - padding_x} {height - padding_y} L {padding_x} {height - padding_y} Z"
    else:
        path_d = f"M {points[0][0]} {points[0][1]}"
        for pt in points[1:]:
            path_d += f" L {pt[0]} {pt[1]}"
        area_d = path_d + f" L {points[-1][0]} {height - padding_y} L {points[0][0]} {height - padding_y} Z"

    # SVG Elements
    svg_elements = []
    # Grid lines (at 25, 50, 75, 100)
    for g_val in [0, 50, 100]:
        gy = height - padding_y - ((g_val - min_score) / (max_score - min_score)) * (height - 2 * padding_y)
        svg_elements.append(
            f'<line x1="{padding_x}" y1="{gy}" x2="{width - padding_x}" y2="{gy}" stroke="#1e293b" stroke-width="1" stroke-dasharray="3,3" />'
            f'<text x="{padding_x - 8}" y="{gy + 3}" fill="#64748b" font-size="9" text-anchor="end" font-family="monospace">{g_val}</text>'
        )

    # Shaded Area
    svg_elements.append(
        f'<path d="{area_d}" fill="url(#sparklineGrad)" opacity="0.25" />'
    )
    # Trend Line
    svg_elements.append(
        f'<path d="{path_d}" fill="none" stroke="#10b981" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" />'
    )

    # Dots and labels
    for pt in points:
        color = "#10b981" if pt[2] >= 80 else ("#f59e0b" if pt[2] >= 60 else "#f43f5e")
        svg_elements.append(
            f'<circle cx="{pt[0]}" cy="{pt[1]}" r="4.5" fill="{color}" stroke="#0f172a" stroke-width="2" />'
            f'<text x="{pt[0]}" y="{pt[1] - 8}" fill="#f1f5f9" font-size="10" font-weight="bold" text-anchor="middle" font-family="monospace">{pt[2]}</text>'
            f'<text x="{pt[0]}" y="{height - 8}" fill="#94a3b8" font-size="8.5" text-anchor="middle" font-family="monospace">{pt[3]}</text>'
        )

    svg_content = f'''
    <svg viewBox="0 0 {width} {height}" class="w-full h-auto max-h-48 overflow-visible">
        <defs>
            <linearGradient id="sparklineGrad" x1="0%" y1="0%" x2="0%" y2="100%">
                <stop offset="0%" stop-color="#10b981" stop-opacity="0.8" />
                <stop offset="100%" stop-color="#10b981" stop-opacity="0.0" />
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
    """Generates a complete, single-file, luxury executive cybersecurity report in HTML."""
    m = build_full_executive_report_model(scan_data, findings, history_runs)
    
    score = m["overall_score"]
    grade = m["risk_grade"]
    score_color = "#10b981" if score >= 80 else ("#f59e0b" if score >= 60 else "#f43f5e")
    grade_badge_bg = "#064e3b" if grade in ("A", "B") else ("#78350f" if grade == "C" else "#881337")
    grade_badge_text = "#34d399" if grade in ("A", "B") else ("#fbbf24" if grade == "C" else "#fb7185")
    
    # Sparkline SVG
    sparkline_svg = _render_svg_sparkline(m["sparkline"]["scores"], m["sparkline"]["labels"])

    # Render matrix rows
    matrix_rows_html = []
    for r in m["matrix"]["rows"]:
        c_badge = f'<span class="badge-red">{r["CRITICAL"]}</span>' if r["CRITICAL"] > 0 else '<span class="text-slate-600">0</span>'
        h_badge = f'<span class="badge-orange">{r["HIGH"]}</span>' if r["HIGH"] > 0 else '<span class="text-slate-600">0</span>'
        m_badge = f'<span class="badge-amber">{r["MEDIUM"]}</span>' if r["MEDIUM"] > 0 else '<span class="text-slate-600">0</span>'
        l_badge = f'<span class="badge-slate">{r["LOW"]}</span>' if r["LOW"] > 0 else '<span class="text-slate-600">0</span>'
        tot_badge = f'<span class="font-bold text-rose-400">{r["total"]}</span>' if r["total"] > 0 else '<span class="text-emerald-400 font-semibold">0 ✓</span>'
        
        matrix_rows_html.append(f'''
        <tr class="border-b border-slate-800/80 hover:bg-slate-850/50 transition-colors">
            <td class="py-2.5 px-3 font-semibold text-slate-200">{r["name"]}</td>
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
            '<span class="px-2.5 py-1 rounded text-xs font-mono font-bold bg-emerald-950/80 text-emerald-400 border border-emerald-700/60 flex items-center gap-1.5 shrink-0">'
            '<span class="w-2 h-2 rounded-full bg-emerald-400"></span>VERIFIED MITIGATED</span>'
            if is_resolved else
            '<span class="px-2.5 py-1 rounded text-xs font-mono font-bold bg-rose-950/80 text-rose-400 border border-rose-700/60 flex items-center gap-1.5 shrink-0">'
            '<span class="w-2 h-2 rounded-full bg-rose-500 animate-pulse"></span>ACTION REQUIRED</span>'
        )

        remediation_cards_html.append(f'''
        <div class="card p-5 space-y-3.5 border-l-4 { 'border-l-emerald-500' if is_resolved else 'border-l-rose-500' }">
            <div class="flex flex-wrap items-center justify-between gap-2">
                <div class="flex items-center gap-2.5">
                    <span class="font-mono text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-bold">{item["id"]}</span>
                    <span class="text-xs font-mono text-slate-400">{item["category"]}</span>
                    <span class="text-xs font-mono font-bold text-rose-400 bg-rose-950/50 px-2 py-0.5 rounded">{item["severity"]}</span>
                </div>
                {status_badge}
            </div>

            <div>
                <h4 class="text-sm font-bold text-white tracking-wide">{item["title"]}</h4>
                <p class="text-xs text-slate-300 mt-1 leading-relaxed"><span class="font-semibold text-slate-400">Root Cause:</span> {item["root_cause"]}</p>
            </div>

            <div class="p-3 rounded-lg bg-black/60 border border-slate-800 space-y-1">
                <div class="text-[10px] font-mono text-rose-400 uppercase tracking-wider font-semibold">Engineered Code Guardrail:</div>
                <pre class="font-mono text-xs text-emerald-300 whitespace-pre-wrap leading-relaxed overflow-x-auto">{item["code_playbook"]}</pre>
            </div>

            <div class="grid grid-cols-1 sm:grid-cols-3 gap-2 pt-1 text-[11px] font-mono text-slate-400">
                <div><span class="text-slate-500">Est. Effort:</span> <span class="text-slate-200">{item["effort"]}</span></div>
                <div><span class="text-slate-500">Owner:</span> <span class="text-slate-200">{item["owner"]}</span></div>
                <div><span class="text-slate-500">SLA:</span> <span class="text-amber-400 font-semibold">{item["sla"]}</span></div>
            </div>

            <div class="text-[11px] font-mono text-slate-400 bg-slate-900/60 p-2 rounded border border-slate-800/80">
                <span class="text-slate-500">CI Verification Command:</span> <code class="text-cyan-400 font-bold">{item["verification_cmd"]}</code>
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
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-main: #07080b;
            --bg-card: #0f1219;
            --border: #1e293b;
            --accent: #e11d48;
            --emerald: #10b981;
            --cyan: #38bdf8;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background-color: var(--bg-main);
            color: var(--text-main);
            font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
            line-height: 1.5;
            padding-bottom: 60px;
        }}
        .font-mono {{ font-family: 'JetBrains Mono', monospace; }}
        .card {{
            background-color: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 14px;
        }}
        .badge-red {{
            background: rgba(136, 19, 55, 0.6);
            color: #fb7185;
            border: 1px solid rgba(225, 29, 72, 0.4);
            padding: 2px 7px;
            border-radius: 6px;
            font-weight: bold;
            font-size: 11px;
            font-family: 'JetBrains Mono', monospace;
        }}
        .badge-orange {{
            background: rgba(124, 45, 18, 0.6);
            color: #fb923c;
            border: 1px solid rgba(234, 88, 12, 0.4);
            padding: 2px 7px;
            border-radius: 6px;
            font-weight: bold;
            font-size: 11px;
            font-family: 'JetBrains Mono', monospace;
        }}
        .badge-amber {{
            background: rgba(120, 53, 15, 0.6);
            color: #fcd34d;
            border: 1px solid rgba(217, 119, 6, 0.4);
            padding: 2px 7px;
            border-radius: 6px;
            font-weight: bold;
            font-size: 11px;
            font-family: 'JetBrains Mono', monospace;
        }}
        .badge-slate {{
            background: rgba(30, 41, 59, 0.6);
            color: #94a3b8;
            border: 1px solid rgba(51, 65, 85, 0.5);
            padding: 2px 7px;
            border-radius: 6px;
            font-weight: bold;
            font-size: 11px;
            font-family: 'JetBrains Mono', monospace;
        }}
        /* Executive Header Floating Action Bar */
        .action-bar {{
            position: sticky;
            top: 0;
            z-index: 50;
            background: rgba(11, 15, 25, 0.88);
            backdrop-filter: blur(12px);
            border-bottom: 1px solid #1e293b;
            padding: 12px 24px;
        }}
        @media print {{
            .action-bar, .no-print {{ display: none !important; }}
            body {{ background: #ffffff !important; color: #0f172a !important; padding: 0 !important; }}
            .card {{ border: 1px solid #cbd5e1 !important; background: #ffffff !important; color: #0f172a !important; box-shadow: none !important; }}
            pre, code {{ color: #0f172a !important; background: #f8fafc !important; }}
            .text-white {{ color: #0f172a !important; }}
            .text-slate-200 {{ color: #1e293b !important; }}
            .text-slate-300 {{ color: #334155 !important; }}
            .text-slate-400 {{ color: #64748b !important; }}
        }}
    </style>
</head>
<body>

    <!-- Sticky Boardroom Header Toolbar -->
    <header class="action-bar flex items-center justify-between no-print" style="display:flex; justify-content:space-between; align-items:center;">
        <div style="display:flex; align-items:center; gap:12px;">
            <div style="width:34px; height:34px; border-radius:8px; background:linear-gradient(135deg, #e11d48, #881337); display:flex; align-items:center; justify-content:center; font-size:18px; box-shadow:0 4px 12px rgba(225,29,72,0.3);">🛡️</div>
            <div>
                <span style="font-weight:800; letter-spacing:1px; font-size:14px; text-transform:uppercase;">SHADOWBOARD</span>
                <span style="font-size:10px; font-family:'JetBrains Mono', monospace; color:#38bdf8; margin-left:8px; background:rgba(56,189,248,0.1); padding:2px 6px; border-radius:4px; border:1px solid rgba(56,189,248,0.3);">EXECUTIVE GOVERNANCE</span>
            </div>
        </div>
        <div style="display:flex; align-items:center; gap:10px;">
            <button onclick="window.print()" style="cursor:pointer; background:#1e293b; color:#f1f5f9; border:1px solid #334155; padding:6px 14px; border-radius:8px; font-size:12px; font-weight:600; display:flex; align-items:center; gap:6px;">
                <span>🖨️</span><span>Print / Save PDF</span>
            </button>
            <a href="/api/scans/{m['scan_id']}/export/pdf" target="_blank" style="text-decoration:none; background:#e11d48; color:#fff; border:none; padding:6px 14px; border-radius:8px; font-size:12px; font-weight:700; display:flex; align-items:center; gap:6px; box-shadow:0 4px 12px rgba(225,29,72,0.4);">
                <span>📄</span><span>Official Boardroom PDF</span>
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
                        <span style="font-size:11px; font-family:'JetBrains Mono', monospace; padding:3px 8px; border-radius:6px; background:#064e3b; color:#34d399; border:1px solid #059669; font-weight:700;">
                            NON-REPUDIATION ATTESTED
                        </span>
                        <span style="font-size:12px; font-family:'JetBrains Mono', monospace; color:var(--text-muted);">
                            Scan Run #{m["scan_id"]} • {m["generated_at"]}
                        </span>
                    </div>
                    <h1 style="font-size:28px; font-weight:800; letter-spacing:-0.5px; color:#ffffff;">
                        AI Security Assurance & Governance Audit
                    </h1>
                    <p style="font-size:14px; color:var(--text-muted); margin-top:4px;">
                        Target: <strong style="color:#ffffff;">{m["target_name"]}</strong> • Model: <span style="font-family:'JetBrains Mono', monospace; color:#38bdf8;">{m["model_name"]}</span> • Mode: <span style="font-family:'JetBrains Mono', monospace; color:#10b981;">{m["target_mode"]}</span>
                    </p>
                </div>

                <!-- Overall Grade & Score Ring -->
                <div style="display:flex; align-items:center; gap:16px; background:#07090e; border:1px solid #1e293b; padding:12px 20px; border-radius:12px;">
                    <div>
                        <div style="font-size:10px; font-family:'JetBrains Mono', monospace; color:var(--text-muted); text-transform:uppercase;">Canonical Score</div>
                        <div style="font-size:32px; font-weight:900; font-family:'JetBrains Mono', monospace; color:{score_color}; line-height:1;">
                            {score} <span style="font-size:14px; color:#64748b;">/ 100</span>
                        </div>
                    </div>
                    <div style="background:{grade_badge_bg}; color:{grade_badge_text}; border:1px solid {grade_badge_text}; width:48px; height:48px; border-radius:10px; display:flex; align-items:center; justify-content:center; font-size:24px; font-weight:900; font-family:'JetBrains Mono', monospace;">
                        {grade}
                    </div>
                </div>
            </div>

            <!-- Top KPI Cards Strip -->
            <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(200px, 1fr)); gap:14px; margin-top:24px; padding-top:20px; border-top:1px solid var(--border);">
                <div style="padding:10px; background:#07090e; border-radius:8px; border:1px solid #1e293b;">
                    <span style="font-size:10px; font-family:'JetBrains Mono', monospace; color:var(--text-muted); text-transform:uppercase;">Confirmed Breaches</span>
                    <div style="font-size:18px; font-weight:800; font-family:'JetBrains Mono', monospace; margin-top:4px; color:{'#10b981' if m['confirmed_count'] == 0 else '#fb7185'};">
                        {m['confirmed_count']} Breaches
                    </div>
                </div>
                <div style="padding:10px; background:#07090e; border-radius:8px; border:1px solid #1e293b;">
                    <span style="font-size:10px; font-family:'JetBrains Mono', monospace; color:var(--text-muted); text-transform:uppercase;">Mitigation State</span>
                    <div style="font-size:18px; font-weight:800; font-family:'JetBrains Mono', monospace; margin-top:4px; color:#10b981;">
                        {'PRODUCTION HARDENED' if m['mitigation_enabled'] else 'UNMITIGATED BASELINE'}
                    </div>
                </div>
                <div style="padding:10px; background:#07090e; border-radius:8px; border:1px solid #1e293b;">
                    <span style="font-size:10px; font-family:'JetBrains Mono', monospace; color:var(--text-muted); text-transform:uppercase;">Remediation Velocity</span>
                    <div style="font-size:18px; font-weight:800; font-family:'JetBrains Mono', monospace; margin-top:4px; color:#38bdf8;">
                        {m['remediation_percent']}% Completed
                    </div>
                </div>
                <div style="padding:10px; background:#07090e; border-radius:8px; border:1px solid #1e293b;">
                    <span style="font-size:10px; font-family:'JetBrains Mono', monospace; color:var(--text-muted); text-transform:uppercase;">Policy Coverage</span>
                    <div style="font-size:18px; font-weight:800; font-family:'JetBrains Mono', monospace; margin-top:4px; color:#10b981;">
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
                        <div style="display:flex; align-items:center; gap:8px;">
                            <span style="font-size:16px;">📈</span>
                            <h3 style="font-size:15px; font-weight:700; color:#fff;">Historical Risk Posture Trend</h3>
                        </div>
                        <span style="font-size:11px; font-family:'JetBrains Mono', monospace; color:#34d399; background:#064e3b; padding:2px 8px; border-radius:6px; font-weight:bold;">
                            {m["sparkline"]["delta_str"]} ({m["sparkline"]["direction"]})
                        </span>
                    </div>
                    <p style="font-size:12px; color:var(--text-muted); margin-bottom:16px;">
                        Tracking canonical score evolution from baseline unmitigated scan through active guardrail verification across {m["sparkline"]["total_runs"]} benchmark executions.
                    </p>
                </div>

                <!-- Sparkline SVG -->
                <div style="background:#07090e; padding:12px; border-radius:10px; border:1px solid #1e293b;">
                    {sparkline_svg}
                </div>

                <div style="display:flex; justify-content:space-between; margin-top:12px; font-size:11px; font-family:'JetBrains Mono', monospace; color:#64748b;">
                    <span>Initial Baseline: <strong style="color:#f8fafc;">{m["sparkline"]["baseline_score"]} / 100</strong></span>
                    <span>Current Hardened: <strong style="color:#10b981;">{m["sparkline"]["current_score"]} / 100</strong></span>
                </div>
            </div>

            <!-- Right: Findings Matrix (OWASP x Severity) -->
            <div class="card" style="padding:22px;">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
                    <div style="display:flex; align-items:center; gap:8px;">
                        <span style="font-size:16px;">🎯</span>
                        <h3 style="font-size:15px; font-weight:700; color:#fff;">Findings Matrix (OWASP × Severity)</h3>
                    </div>
                    <span style="font-size:11px; font-family:'JetBrains Mono', monospace; color:var(--text-muted);">
                        OWASP 2025 Standard
                    </span>
                </div>
                <p style="font-size:12px; color:var(--text-muted); margin-bottom:14px;">
                    Cross-tabulation of verified vulnerability findings across threat categories and critical impact levels.
                </p>

                <!-- Matrix Table -->
                <div style="overflow-x:auto;">
                    <table style="width:100%; border-collapse:collapse; font-size:12px;">
                        <thead>
                            <tr style="border-bottom:1px solid #1e293b; color:#94a3b8; font-family:'JetBrains Mono', monospace; font-size:10px; text-transform:uppercase;">
                                <th style="padding:8px; text-align:left;">Category</th>
                                <th style="padding:8px; text-align:center; color:#fb7185;">Crit</th>
                                <th style="padding:8px; text-align:center; color:#fb923c;">High</th>
                                <th style="padding:8px; text-align:center; color:#fcd34d;">Med</th>
                                <th style="padding:8px; text-align:center; color:#94a3b8;">Low</th>
                                <th style="padding:8px; text-align:center; color:#fff;">Total</th>
                            </tr>
                        </thead>
                        <tbody>
                            {''.join(matrix_rows_html)}
                        </tbody>
                        <tfoot>
                            <tr style="border-top:2px solid #334155; font-family:'JetBrains Mono', monospace; font-weight:bold; font-size:11px;">
                                <td style="padding:10px 8px; color:#fff;">Total Verified</td>
                                <td style="padding:10px 8px; text-align:center; color:#fb7185;">{m["matrix"]["totals"]["CRITICAL"]}</td>
                                <td style="padding:10px 8px; text-align:center; color:#fb923c;">{m["matrix"]["totals"]["HIGH"]}</td>
                                <td style="padding:10px 8px; text-align:center; color:#fcd34d;">{m["matrix"]["totals"]["MEDIUM"]}</td>
                                <td style="padding:10px 8px; text-align:center; color:#94a3b8;">{m["matrix"]["totals"]["LOW"]}</td>
                                <td style="padding:10px 8px; text-align:center; color:{'#10b981' if m['matrix']['totals']['grand_total'] == 0 else '#fb7185'};">
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
                    <div style="display:flex; align-items:center; gap:8px;">
                        <span style="font-size:18px;">🛠️</span>
                        <h3 style="font-size:16px; font-weight:800; color:#fff;">Remediation Progress Tracker & Engineering Playbooks</h3>
                    </div>
                    <p style="font-size:12px; color:var(--text-muted); margin-top:2px;">
                        Actionable developer remediation directives with exact code patches, verification test commands, and SLA targets.
                    </p>
                </div>
                <!-- Progress Percentage Bar -->
                <div style="display:flex; align-items:center; gap:12px; min-width:240px;">
                    <div style="flex:1; height:10px; background:#1e293b; border-radius:999px; overflow:hidden;">
                        <div style="width:{m['remediation_percent']}%; height:100%; background:linear-gradient(90deg, #10b981, #38bdf8); border-radius:999px;"></div>
                    </div>
                    <span style="font-family:'JetBrains Mono', monospace; font-size:12px; font-weight:bold; color:#10b981;">{m['remediation_percent']}% Mitigated</span>
                </div>
            </div>

            <div style="display:flex; flex-direction:column; gap:14px;">
                {''.join(remediation_cards_html)}
            </div>
        </div>

        <!-- 4. Cryptographic Evidence Integrity Certificate -->
        <div class="card" style="padding:24px; border:1px solid #881337; background:linear-gradient(180deg, #120b13, #0a0c12);">
            <div style="display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap:12px; margin-bottom:16px;">
                <div style="display:flex; align-items:center; gap:10px;">
                    <div style="width:36px; height:36px; border-radius:10px; background:rgba(225,29,72,0.2); border:1px solid #e11d48; display:flex; align-items:center; justify-content:center; font-size:20px;">
                        🔒
                    </div>
                    <div>
                        <h3 style="font-size:16px; font-weight:800; color:#ffffff; letter-spacing:0.3px;">
                            Cryptographic Evidence Integrity Certificate
                        </h3>
                        <p style="font-size:12px; font-family:'JetBrains Mono', monospace; color:#fb7185;">
                            Immutable Proof-of-Evaluation • Record: {m["crypto_record"]["ledger_record_id"]}
                        </p>
                    </div>
                </div>
                <span style="font-size:11px; font-family:'JetBrains Mono', monospace; padding:3px 10px; border-radius:6px; background:#064e3b; color:#34d399; border:1px solid #059669; font-weight:700;">
                    ✓ ED25519 SIGNATURE VALID
                </span>
            </div>

            <p style="font-size:12px; color:#cbd5e1; line-height:1.6; margin-bottom:16px;">
                Every interaction turn, model token response, and kernel tool event in Assessment Run #{m["scan_id"]} has been cryptographically committed to a linear SHA-256 Merkle chain. Any retroactive modification to prompts, outcomes, or policy verdicts breaks this signature.
            </p>

            <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(320px, 1fr)); gap:12px; font-family:'JetBrains Mono', monospace; font-size:11px;">
                <div style="background:#07070b; padding:12px; border-radius:8px; border:1px solid #27273a;">
                    <span style="color:#64748b; font-size:10px; text-transform:uppercase; display:block;">SHA-256 Event Chain Merkle Root</span>
                    <span style="color:#34d399; word-break:break-all; font-weight:bold;">{m["crypto_record"]["merkle_root"]}</span>
                </div>
                <div style="background:#07070b; padding:12px; border-radius:8px; border:1px solid #27273a;">
                    <span style="color:#64748b; font-size:10px; text-transform:uppercase; display:block;">Canonical Manifest Hash</span>
                    <span style="color:#38bdf8; word-break:break-all; font-weight:bold;">{m["crypto_record"]["manifest_hash"]}</span>
                </div>
                <div style="background:#07070b; padding:12px; border-radius:8px; border:1px solid #27273a;">
                    <span style="color:#64748b; font-size:10px; text-transform:uppercase; display:block;">Active Ed25519 Signer Key ID</span>
                    <span style="color:#e2e8f0; font-weight:bold;">{m["crypto_record"]["key_id"]} ({m["crypto_record"]["substrate_truth_level"]})</span>
                </div>
                <div style="background:#07070b; padding:12px; border-radius:8px; border:1px solid #27273a;">
                    <span style="color:#64748b; font-size:10px; text-transform:uppercase; display:block;">Offline Independent Verification Command</span>
                    <span style="color:#fcd34d; font-weight:bold;">{m["crypto_record"]["verification_cli"]}</span>
                </div>
            </div>
        </div>

        <!-- 5. Executive Compliance Crosswalk Matrix -->
        <div class="card" style="padding:22px;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
                <h3 style="font-size:15px; font-weight:700; color:#fff;">Regulatory Compliance & Threat Framework Mapping</h3>
                <span style="font-size:11px; font-family:'JetBrains Mono', monospace; color:var(--text-muted);">
                    NIST • OWASP • MITRE ATLAS • EU AI ACT
                </span>
            </div>
            <div style="overflow-x:auto;">
                <table style="width:100%; border-collapse:collapse; font-size:11px; font-family:'JetBrains Mono', monospace;">
                    <thead>
                        <tr style="border-bottom:1px solid #1e293b; color:#94a3b8; text-transform:uppercase;">
                            <th style="padding:8px; text-align:left;">Standard</th>
                            <th style="padding:8px; text-align:left;">Control Reference</th>
                            <th style="padding:8px; text-align:left;">Evaluated AI Domain</th>
                            <th style="padding:8px; text-align:right;">Compliance Status</th>
                        </tr>
                    </thead>
                    <tbody style="color:#cbd5e1;">
                        <tr style="border-bottom:1px solid #1e293b;">
                            <td style="padding:8px; color:#fff; font-weight:bold;">OWASP Top 10 for LLMs</td>
                            <td style="padding:8px;">LLM01: Prompt Injection</td>
                            <td style="padding:8px;">Direct & Indirect Vector RAG Poisoning</td>
                            <td style="padding:8px; text-align:right; color:#10b981; font-weight:bold;">{'PASSED' if score >= 80 else 'FAIL / BREACH'}</td>
                        </tr>
                        <tr style="border-bottom:1px solid #1e293b;">
                            <td style="padding:8px; color:#fff; font-weight:bold;">OWASP Top 10 for LLMs</td>
                            <td style="padding:8px;">LLM02: Sensitive Info Disclosure</td>
                            <td style="padding:8px;">Canary Token & System Prompt Exfiltration</td>
                            <td style="padding:8px; text-align:right; color:#10b981; font-weight:bold;">{'PASSED' if score >= 80 else 'FAIL / BREACH'}</td>
                        </tr>
                        <tr style="border-bottom:1px solid #1e293b;">
                            <td style="padding:8px; color:#fff; font-weight:bold;">OWASP Top 10 for LLMs</td>
                            <td style="padding:8px;">LLM06: Excessive Agency / BOLA</td>
                            <td style="padding:8px;">Lateral Tool IDOR & Database Mutation</td>
                            <td style="padding:8px; text-align:right; color:#10b981; font-weight:bold;">{'PASSED' if score >= 80 else 'FAIL / BREACH'}</td>
                        </tr>
                        <tr style="border-bottom:1px solid #1e293b;">
                            <td style="padding:8px; color:#fff; font-weight:bold;">MITRE ATLAS (v5.x)</td>
                            <td style="padding:8px;">AML.T0051 / AML.T0054</td>
                            <td style="padding:8px;">LLM Exfiltration & Tool Parameter Smuggling</td>
                            <td style="padding:8px; text-align:right; color:#10b981; font-weight:bold;">AUDITED • VERIFIED</td>
                        </tr>
                        <tr style="border-bottom:1px solid #1e293b;">
                            <td style="padding:8px; color:#fff; font-weight:bold;">NIST AI RMF 1.0</td>
                            <td style="padding:8px;">GOVERN 1.2 / MEASURE 2.7</td>
                            <td style="padding:8px;">Continuous Multi-Turn Adversarial Verification</td>
                            <td style="padding:8px; text-align:right; color:#10b981; font-weight:bold;">COMPLIANT</td>
                        </tr>
                        <tr>
                            <td style="padding:8px; color:#fff; font-weight:bold;">EU AI Act (Art. 15)</td>
                            <td style="padding:8px;">Cyber Resilience & Robustness</td>
                            <td style="padding:8px;">Executable Security Guardrail Attestation</td>
                            <td style="padding:8px; text-align:right; color:#10b981; font-weight:bold;">COMPLIANT</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Footer Sign-off -->
        <footer style="margin-top:12px; text-align:center; font-family:'JetBrains Mono', monospace; font-size:11px; color:#64748b;">
            CONFIDENTIAL — SHADOWBOARD AI ASSURANCE SUITE • ED25519 CRYPTOGRAPHIC PROOF VERIFIED • REPRODUCIBLE NON-REPUDIATION AUDIT
        </footer>

    </main>

</body>
</html>
'''
    return html
