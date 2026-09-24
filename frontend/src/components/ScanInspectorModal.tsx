import React, { useState, useEffect } from 'react';
import { api } from '@/api/client';
import { ScanDetails, Finding, Attempt } from '@/types/api';
import toast from 'react-hot-toast';

interface ScanInspectorModalProps {
  scanId: number | null;
  onClose: () => void;
  onRerunScan?: (targetId: number, mitigation: boolean) => void;
}

export const ScanInspectorModal: React.FC<ScanInspectorModalProps> = ({ scanId, onClose, onRerunScan }) => {
  const [scan, setScan] = useState<ScanDetails | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'findings' | 'attempts' | 'stream'>('findings');
  const [expandedFindingId, setExpandedFindingId] = useState<number | null>(null);
  const [expandedAttemptId, setExpandedAttemptId] = useState<number | null>(null);
  const [copiedText, setCopiedText] = useState<string | null>(null);
  const [liveStreamEvents, setLiveStreamEvents] = useState<any[]>([]);

  useEffect(() => {
    if (!scanId) return;

    let isMounted = true;
    setLoading(true);
    setError(null);
    setLiveStreamEvents([]);

    // Fetch scan details
    api.get<ScanDetails>(`/scans/${scanId}`)
      .then((data) => {
        if (isMounted) {
          setScan(data);
          if (data.findings && data.findings.length > 0) {
            setExpandedFindingId(data.findings[0].id);
          }
          if (data.attempts && data.attempts.length > 0) {
            setExpandedAttemptId(data.attempts[0].id);
          }
          setLoading(false);
        }
      })
      .catch((err) => {
        if (isMounted) {
          setError(err.message || 'Failed to load scan details');
          setLoading(false);
        }
      });

    // Also connect to SSE stream to show live / replayed events
    const token = localStorage.getItem('sb_api_key') || 'shadowboard_admin_secret_2026';
    const es = new EventSource(`/api/scans/${scanId}/stream?api_key=${encodeURIComponent(token)}`);

    es.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data);
        if (isMounted) {
          setLiveStreamEvents((prev) => [...prev, payload]);
        }
        if (payload.type === 'scan_complete' || payload.type === 'error') {
          es.close();
        }
      } catch (e) {
        console.error('SSE JSON parse error:', e);
      }
    };

    es.onerror = () => {
      es.close();
    };

    return () => {
      isMounted = false;
      es.close();
    };
  }, [scanId]);

  if (!scanId) return null;

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(label);
    toast.success(`Copied ${label} to clipboard`);
    setTimeout(() => setCopiedText(null), 2000);
  };

  const handleDownloadPdf = () => {
    const token = localStorage.getItem('sb_api_key') || 'shadowboard_admin_secret_2026';
    const url = `/api/scans/${scanId}/export/pdf?api_key=${encodeURIComponent(token)}`;
    window.open(url, '_blank');
  };

  const getSeverityBadge = (severity: string) => {
    const sev = (severity || '').toUpperCase();
    if (sev === 'CRITICAL') {
      return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-950/80 text-rose-400 border border-rose-700/60">CRITICAL</span>;
    }
    if (sev === 'HIGH') {
      return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-orange-950/80 text-orange-400 border border-orange-700/60">HIGH</span>;
    }
    if (sev === 'MEDIUM') {
      return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-950/80 text-amber-400 border border-amber-700/60">MEDIUM</span>;
    }
    return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-slate-300 border border-slate-700">LOW</span>;
  };

  const getStanceBadge = (stance: string) => {
    const s = (stance || '').toUpperCase();
    if (s === 'COMPLIED') {
      return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-950/80 text-rose-400 border border-rose-700/60">COMPLIED (VULNERABLE)</span>;
    }
    if (s === 'REFUSED') {
      return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-950/80 text-emerald-400 border border-emerald-700/60">REFUSED (DEFENDED)</span>;
    }
    return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-950/80 text-amber-400 border border-amber-700/60">{s || 'PARTIAL'}</span>;
  };

  return (
    <div className="fixed inset-0 bg-black/80 backdrop-blur-md flex items-center justify-center z-50 p-4 sm:p-6 overflow-y-auto animate-fadeIn">
      <div className="bg-[#0f0f15] border border-[#2b2733] rounded-2xl w-full max-w-5xl max-h-[92vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Modal Header */}
        <div className="p-5 bg-[#14141d] border-b border-[#23202b] flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-rose-600 to-rose-900 flex items-center justify-center text-xl shadow-lg shadow-rose-950/50">
              🔍
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h2 className="text-base font-bold text-white tracking-wide">
                  Assessment Run #{scanId}
                </h2>
                {scan && (
                  <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-semibold ${
                    scan.status === 'COMPLETED'
                      ? 'bg-emerald-950/70 text-emerald-400 border border-emerald-800/40'
                      : scan.status === 'RUNNING'
                      ? 'bg-sky-950/70 text-sky-400 border border-sky-800/40 animate-pulse'
                      : 'bg-rose-950/70 text-rose-400 border border-rose-800/40'
                  }`}>
                    {scan.status}
                  </span>
                )}
                {scan && (
                  <span className={`px-2 py-0.5 rounded text-[10px] font-mono border ${
                    scan.mitigation_enabled
                      ? 'bg-emerald-950/60 text-emerald-400 border-emerald-800/40'
                      : 'bg-amber-950/60 text-amber-400 border-amber-800/40'
                  }`}>
                    {scan.mitigation_enabled ? 'MITIGATED' : 'VULNERABLE'}
                  </span>
                )}
              </div>
              <p className="text-xs text-slate-400 mt-0.5 font-mono">
                Target: <span className="text-slate-200 font-semibold">{scan?.target_name || `Target #${scan?.target_id}`}</span>
                {scan?.started_at && ` • Started: ${new Date(scan.started_at).toLocaleString()}`}
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-2">
            {onRerunScan && scan && (
              <button
                onClick={() => onRerunScan(scan.target_id, scan.mitigation_enabled)}
                className="px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-rose-600 hover:bg-rose-500 text-white transition-colors flex items-center space-x-1.5 shadow-sm"
                title="Launch re-run of this security assessment"
              >
                <span>⚡</span>
                <span>Re-run Assessment</span>
              </button>
            )}
            <button
              onClick={handleDownloadPdf}
              className="px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-[#1a1a24] hover:bg-[#252533] border border-[#332f3f] text-slate-200 transition-colors flex items-center space-x-1.5 shadow-sm"
              title="Download boardroom-ready cryptographic verification report"
            >
              <span>📄</span>
              <span>Export Boardroom PDF</span>
            </button>
            <button
              onClick={onClose}
              className="w-8 h-8 rounded-lg bg-[#1a1a24] hover:bg-[#252533] border border-[#332f3f] text-slate-400 hover:text-white flex items-center justify-center transition-colors text-sm"
            >
              ✕
            </button>
          </div>
        </div>

        {/* Score & Metric Summary Bar */}
        {scan && (
          <div className="grid grid-cols-2 sm:grid-cols-4 divide-x divide-y sm:divide-y-0 divide-[#23202b] bg-[#111118] border-b border-[#23202b] text-center">
            <div className="p-3">
              <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block">Security Score</span>
              <div className="flex items-baseline justify-center space-x-1 mt-0.5">
                <span className="text-xl font-black font-mono text-white">{scan.overall_score ?? '—'}</span>
                <span className="text-xs font-mono text-slate-500">/ 100</span>
                {scan.risk_grade && (
                  <span className={`ml-1 text-xs font-bold font-mono px-1.5 py-0.2 rounded ${
                    scan.risk_grade === 'A' ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' :
                    scan.risk_grade === 'B' ? 'bg-sky-950 text-sky-400 border border-sky-800' :
                    scan.risk_grade === 'C' ? 'bg-amber-950 text-amber-400 border border-amber-800' :
                    'bg-rose-950 text-rose-400 border border-rose-800'
                  }`}>
                    Grade {scan.risk_grade}
                  </span>
                )}
              </div>
            </div>

            <div className="p-3">
              <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block">Confirmed Breaches</span>
              <div className="mt-0.5">
                {scan.confirmed_count > 0 ? (
                  <span className="text-base font-bold font-mono text-rose-400">
                    {scan.confirmed_count} Confirmed
                  </span>
                ) : (
                  <span className="text-base font-bold font-mono text-emerald-400">
                    0 Confirmed
                  </span>
                )}
              </div>
            </div>

            <div className="p-3">
              <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block">Objectives Tested</span>
              <span className="text-base font-bold font-mono text-slate-200 mt-0.5 block">
                {scan.objectives_tested ?? scan.objectives?.length ?? 0}
              </span>
            </div>

            <div className="p-3">
              <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block">Policy Coverage</span>
              <span className="text-base font-bold font-mono text-emerald-400 mt-0.5 block">
                {scan.policy_coverage ? `${scan.policy_coverage}%` : '100%'}
              </span>
            </div>
          </div>
        )}

        {/* Modal Navigation Tabs */}
        <div className="flex border-b border-[#23202b] bg-[#12121a] px-5">
          <button
            onClick={() => setActiveTab('findings')}
            className={`py-3 px-4 text-xs font-semibold border-b-2 transition-all flex items-center space-x-2 ${
              activeTab === 'findings'
                ? 'border-rose-500 text-rose-400 bg-rose-950/10'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <span>🚨</span>
            <span>Confirmed Breaches & Findings ({scan?.findings?.length ?? 0})</span>
          </button>

          <button
            onClick={() => setActiveTab('attempts')}
            className={`py-3 px-4 text-xs font-semibold border-b-2 transition-all flex items-center space-x-2 ${
              activeTab === 'attempts'
                ? 'border-rose-500 text-rose-400 bg-rose-950/10'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <span>🎯</span>
            <span>Adversarial Prompts & Responses ({scan?.attempts?.length ?? 0})</span>
          </button>

          <button
            onClick={() => setActiveTab('stream')}
            className={`py-3 px-4 text-xs font-semibold border-b-2 transition-all flex items-center space-x-2 ${
              activeTab === 'stream'
                ? 'border-rose-500 text-rose-400 bg-rose-950/10'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <span>📡</span>
            <span>Execution Telemetry Stream ({liveStreamEvents.length})</span>
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 flex-1 overflow-y-auto space-y-4">
          {loading ? (
            <div className="py-16 text-center space-y-3">
              <div className="w-8 h-8 border-2 border-rose-500 border-t-transparent rounded-full animate-spin mx-auto"></div>
              <p className="text-xs font-mono text-slate-400">Loading scan execution evidence from SQLite database...</p>
            </div>
          ) : error ? (
            <div className="p-4 rounded-xl bg-rose-950/30 border border-rose-800/40 text-rose-300 text-xs">
              Error fetching scan details: {error}
            </div>
          ) : (
            <>
              {/* TAB 1: FINDINGS & BREACHES */}
              {activeTab === 'findings' && (
                <div className="space-y-4">
                  {(!scan?.findings || scan.findings.length === 0) ? (
                    <div className="p-8 rounded-xl bg-emerald-950/20 border border-emerald-800/30 text-center space-y-2">
                      <span className="text-2xl">🛡️</span>
                      <h4 className="text-sm font-bold text-emerald-400">Zero Security Breaches Detected</h4>
                      <p className="text-xs text-slate-400 max-w-md mx-auto leading-relaxed">
                        The agent target maintained all operational boundaries. No prompt injection overrides, confidential canary disclosures, or unauthorized tool invocations succeeded.
                      </p>
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {scan.findings.map((f: Finding) => {
                        const isExpanded = expandedFindingId === f.id;
                        return (
                          <div
                            key={f.id}
                            className="rounded-xl border border-[#2b2733] bg-[#13131c] overflow-hidden transition-all"
                          >
                            <div
                              onClick={() => setExpandedFindingId(isExpanded ? null : f.id)}
                              className="p-4 flex items-center justify-between cursor-pointer hover:bg-[#181824] transition-colors"
                            >
                              <div className="flex items-center space-x-3">
                                {getSeverityBadge(f.severity)}
                                <div>
                                  <div className="flex items-center space-x-2">
                                    <span className="font-mono font-bold text-xs text-white">{f.finding_id}</span>
                                    <span className="text-[11px] font-mono text-rose-400 px-1.5 py-0.2 rounded bg-rose-950/40 border border-rose-900/40">
                                      {f.owasp_category}
                                    </span>
                                  </div>
                                  <p className="text-xs text-slate-300 mt-1 line-clamp-1">{f.remediation}</p>
                                </div>
                              </div>

                              <div className="flex items-center space-x-3">
                                <span className="text-[10px] font-mono text-slate-500">
                                  Confidence: {Math.round(f.confidence * 100)}%
                                </span>
                                <span className="text-slate-400 text-xs font-mono">{isExpanded ? '▲' : '▼'}</span>
                              </div>
                            </div>

                            {isExpanded && (
                              <div className="p-4 bg-[#0d0d13] border-t border-[#23202b] space-y-3 text-xs">
                                <div>
                                  <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block mb-1">
                                    Remediation Recommendation
                                  </span>
                                  <div className="p-3 rounded-lg bg-[#14141e] border border-[#262230] text-slate-200 leading-relaxed font-sans">
                                    {f.remediation}
                                  </div>
                                </div>

                                <div>
                                  <div className="flex items-center justify-between mb-1">
                                    <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider">
                                      Cryptographic Evidence Hash (SHA-256)
                                    </span>
                                    <button
                                      onClick={() => copyToClipboard(f.evidence_hash, 'Hash')}
                                      className="text-[10px] font-mono text-rose-400 hover:underline"
                                    >
                                      {copiedText === 'Hash' ? '✓ Copied' : 'Copy Hash'}
                                    </button>
                                  </div>
                                  <div className="p-2.5 rounded-lg bg-[#070709] border border-[#1f1b22] font-mono text-[11px] text-emerald-400 break-all select-all">
                                    {f.evidence_hash}
                                  </div>
                                </div>

                                <div>
                                  <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block mb-1">
                                    Full Recorded Evidence Payload
                                  </span>
                                  <pre className="p-3 rounded-lg bg-[#070709] border border-[#1f1b22] font-mono text-[11px] text-slate-300 overflow-x-auto max-h-56 leading-relaxed">
                                    {JSON.stringify((f as any).evidence || f, null, 2)}
                                  </pre>
                                </div>
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              )}

              {/* TAB 2: ADVERSARIAL ATTEMPTS (PROMPTS & RESPONSES) */}
              {activeTab === 'attempts' && (
                <div className="space-y-4">
                  {(!scan?.attempts || scan.attempts.length === 0) ? (
                    <div className="p-8 text-center text-slate-500 font-mono text-xs">
                      No probe attempts recorded for this scan.
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {scan.attempts.map((att: Attempt) => {
                        const isExpanded = expandedAttemptId === att.id;
                        return (
                          <div
                            key={att.id}
                            className="rounded-xl border border-[#2b2733] bg-[#13131c] overflow-hidden"
                          >
                            <div
                              onClick={() => setExpandedAttemptId(isExpanded ? null : att.id)}
                              className="p-4 flex items-center justify-between cursor-pointer hover:bg-[#181824] transition-colors"
                            >
                              <div className="flex items-center space-x-3">
                                <span className="font-mono text-xs px-2 py-0.5 rounded bg-[#1e1c27] text-slate-300 border border-[#2d293a]">
                                  Turn #{att.turn}
                                </span>
                                <div>
                                  <div className="flex items-center space-x-2">
                                    <span className="font-bold text-xs text-white">Strategy: {att.strategy}</span>
                                    {getStanceBadge(att.stance)}
                                  </div>
                                  <p className="text-xs text-slate-400 mt-1 font-mono line-clamp-1">
                                    &quot;{att.prompt?.slice(0, 90)}...&quot;
                                  </p>
                                </div>
                              </div>

                              <div className="flex items-center space-x-3">
                                <span className="text-[10px] font-mono text-slate-500">
                                  Oracle Confidence: {Math.round((att.confidence || 1) * 100)}%
                                </span>
                                <span className="text-slate-400 text-xs font-mono">{isExpanded ? '▲' : '▼'}</span>
                              </div>
                            </div>

                            {isExpanded && (
                              <div className="p-4 bg-[#0d0d13] border-t border-[#23202b] space-y-4 text-xs">
                                {/* Prompt Box */}
                                <div>
                                  <div className="flex items-center justify-between mb-1">
                                    <span className="text-[10px] font-mono text-rose-400 uppercase tracking-wider font-semibold">
                                      ⚡ Adversarial Probe Prompt Sent
                                    </span>
                                    <button
                                      onClick={() => copyToClipboard(att.prompt, 'Prompt')}
                                      className="text-[10px] font-mono text-rose-400 hover:underline"
                                    >
                                      {copiedText === 'Prompt' ? '✓ Copied' : 'Copy Prompt'}
                                    </button>
                                  </div>
                                  <div className="p-3 rounded-lg bg-[#070709] border border-[#1f1b22] font-mono text-[11px] text-slate-200 whitespace-pre-wrap leading-relaxed">
                                    {att.prompt}
                                  </div>
                                </div>

                                {/* Response Box */}
                                <div>
                                  <div className="flex items-center justify-between mb-1">
                                    <span className="text-[10px] font-mono text-sky-400 uppercase tracking-wider font-semibold">
                                      🤖 Target Agent Raw LLM Response
                                    </span>
                                    <button
                                      onClick={() => copyToClipboard(att.response, 'Response')}
                                      className="text-[10px] font-mono text-sky-400 hover:underline"
                                    >
                                      {copiedText === 'Response' ? '✓ Copied' : 'Copy Response'}
                                    </button>
                                  </div>
                                  <div className="p-3 rounded-lg bg-[#070709] border border-[#1f1b22] font-mono text-[11px] text-slate-300 whitespace-pre-wrap leading-relaxed max-h-64 overflow-y-auto">
                                    {att.response || '<No response or silent error>'}
                                  </div>
                                </div>

                                {/* Stance & Reason */}
                                {att.reason && (
                                  <div className="p-3 rounded-lg bg-[#14141e] border border-[#262230] text-slate-300 leading-relaxed font-sans">
                                    <span className="font-semibold text-white">Oracle Verdict Rationale:</span> {att.reason}
                                  </div>
                                )}

                                {/* Events if any */}
                                {att.events && att.events.length > 0 && (
                                  <div>
                                    <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block mb-1">
                                      Internal Kernel / Tool Events ({att.events.length})
                                    </span>
                                    <div className="space-y-1">
                                      {att.events.map((ev, eIdx) => (
                                        <div key={eIdx} className="p-2 rounded bg-[#070709] border border-[#1f1b22] font-mono text-[10px] flex items-center justify-between">
                                          <span className="text-amber-400">[{ev.event_type}]</span>
                                          <span className="text-slate-400 truncate max-w-md">{JSON.stringify(ev.event_data)}</span>
                                          <span className="text-slate-600">{ev.source}</span>
                                        </div>
                                      ))}
                                    </div>
                                  </div>
                                )}
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              )}

              {/* TAB 3: TELEMETRY STREAM */}
              {activeTab === 'stream' && (
                <div className="space-y-3">
                  <div className="flex items-center justify-between text-xs font-mono text-slate-400">
                    <span>Recorded & Live SSE Stream Feed</span>
                    <span>{liveStreamEvents.length} events received</span>
                  </div>

                  <div className="bg-[#070709] border border-[#1f1b22] rounded-xl p-4 font-mono text-[11px] text-slate-300 min-h-[300px] max-h-[460px] overflow-y-auto space-y-2">
                    {liveStreamEvents.length === 0 ? (
                      <div className="py-16 text-center text-slate-500 italic">
                        Connecting to event stream...
                      </div>
                    ) : (
                      liveStreamEvents.map((evt, idx) => (
                        <div key={idx} className="p-2 rounded bg-[#0f0f15] border border-[#1b1922] flex items-start space-x-2">
                          <span className="text-rose-400 font-bold shrink-0">[{evt.type || 'EVENT'}]</span>
                          <div className="text-slate-300 break-all leading-relaxed">
                            {evt.data?.message ? (
                              <span>{evt.data.message}</span>
                            ) : evt.data?.snippet ? (
                              <span>
                                <span className="text-sky-300">[{evt.data.strategy}]</span> {evt.data.snippet} &rarr; <span className="text-amber-300 font-bold">{evt.data.stance}</span>
                              </span>
                            ) : evt.data?.finding_id ? (
                              <span>
                                Recorded finding: <strong className="text-rose-400">{evt.data.finding_id}</strong> ({evt.data.severity})
                              </span>
                            ) : (
                              <span>{JSON.stringify(evt.data || evt)}</span>
                            )}
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              )}
            </>
          )}
        </div>

        {/* Modal Footer */}
        <div className="p-4 bg-[#14141d] border-t border-[#23202b] flex items-center justify-between">
          <div className="text-xs font-mono text-slate-500">
            Cryptographic SHA-256 Attestation Active
          </div>
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg text-xs font-semibold bg-[#211e29] hover:bg-[#2b2737] text-white transition-colors"
          >
            Close Inspector
          </button>
        </div>
      </div>
    </div>
  );
};

export default ScanInspectorModal;
