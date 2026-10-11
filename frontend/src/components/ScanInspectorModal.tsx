import React, { useState, useEffect } from 'react';
import { api } from '@/api/client';
import { ScanDetails, Finding, Attempt } from '@/types/api';

interface ScanInspectorModalProps {
  scanId: number | null;
  onClose: () => void;
  onRerunScan?: (targetId: number, mitigation: boolean) => void;
}

export const ScanInspectorModal: React.FC<ScanInspectorModalProps> = ({ scanId, onClose, onRerunScan }) => {
  const [scan, setScan] = useState<ScanDetails | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'findings' | 'trace'>('findings');
  const [expandedFindingId, setExpandedFindingId] = useState<number | null>(null);
  const [expandedTurnId, setExpandedTurnId] = useState<number | null>(null);

  useEffect(() => {
    if (!scanId) return;

    let isMounted = true;
    setLoading(true);
    setError(null);

    api.get<ScanDetails>(`/scans/${scanId}`)
      .then((data) => {
        if (isMounted) {
          setScan(data);
          if (data.findings && data.findings.length > 0) {
            setExpandedFindingId(data.findings[0].id);
          }
          if (data.attempts && data.attempts.length > 0) {
            setExpandedTurnId(data.attempts[0].id);
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

    const es = new EventSource(`/api/scans/${scanId}/stream`);

    es.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data);
        if (payload.type === 'scan_complete' || payload.type === 'error') {
          if (isMounted) {
            api.get<ScanDetails>(`/scans/${scanId}`).then((d) => isMounted && setScan(d)).catch(() => {});
          }
          es.close();
        }
      } catch (e) {
        console.error('SSE parse error:', e);
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

  const getSeverityBadge = (severity: string) => {
    const sev = (severity || '').toUpperCase();
    if (sev === 'CRITICAL' || sev === 'HIGH') {
      return (
        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold text-[#f97316] border border-[#f97316] bg-black">
          {sev}
        </span>
      );
    }
    return (
      <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold text-white border border-[#333333] bg-[#121212]">
        {sev}
      </span>
    );
  };

  const getStanceBadge = (stance: string) => {
    const s = (stance || '').toUpperCase();
    if (s === 'COMPLIED') {
      return (
        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold text-[#f97316] border border-[#f97316] bg-black">
          BREACH (COMPLIED)
        </span>
      );
    }
    if (s === 'REFUSED') {
      return (
        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold text-white border border-[#333333] bg-[#121212]">
          DEFENDED (REFUSED)
        </span>
      );
    }
    return (
      <span className="px-2 py-0.5 rounded text-[10px] font-mono text-[#a3a3a3] border border-[#262626]">
        {s || 'EVALUATED'}
      </span>
    );
  };

  const findingsCount = scan?.findings?.length ?? 0;
  const attemptsCount = scan?.attempts?.length ?? 0;

  return (
    <div className="fixed inset-0 bg-black/85 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="bg-[#0a0a0a] border border-[#262626] rounded-lg w-full max-w-5xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden font-sans">
        
        {/* Header */}
        <div className="p-4 bg-black border-b border-[#262626] flex flex-wrap items-center justify-between gap-4">
          <div>
            <div className="flex items-center space-x-3">
              <h2 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
                Scan #{scanId}
              </h2>
              {scan && (
                <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                  scan.status === 'COMPLETED'
                    ? 'text-white border border-[#333333] bg-[#121212]'
                    : scan.status === 'RUNNING'
                    ? 'text-[#f97316] border border-[#f97316] bg-black animate-pulse'
                    : 'text-[#f97316] border border-[#f97316] bg-black'
                }`}>
                  {scan.status}
                </span>
              )}
            </div>
            <p className="text-xs text-[#a3a3a3] mt-0.5 font-mono">
              Target: <span className="text-white font-semibold">{scan?.target_name || `Target #${scan?.target_id}`}</span>
            </p>
          </div>

          <div className="flex items-center space-x-2">
            {onRerunScan && scan && (
              <button
                onClick={() => onRerunScan(scan.target_id, scan.mitigation_enabled)}
                className="px-3.5 py-1.5 rounded text-xs font-mono font-bold bg-[#f97316] hover:bg-[#ea580c] text-black transition-colors"
              >
                Re-run Scan
              </button>
            )}
            <a
              href={`/api/scans/${scanId}/export/html`}
              target="_blank"
              rel="noreferrer"
              className="px-3 py-1.5 rounded text-xs font-mono text-white border border-[#333333] hover:border-[#f97316] transition-colors"
            >
              HTML Report
            </a>
            <a
              href={`/api/scans/${scanId}/export/pdf`}
              target="_blank"
              rel="noreferrer"
              className="px-3 py-1.5 rounded text-xs font-mono text-white border border-[#333333] hover:border-[#f97316] transition-colors"
            >
              PDF Report
            </a>
            <button
              onClick={onClose}
              className="w-8 h-8 rounded border border-[#262626] text-[#a3a3a3] hover:text-white flex items-center justify-center transition-colors text-xs font-mono"
            >
              ✕
            </button>
          </div>
        </div>

        {/* 3 Metric Score Bar */}
        {scan && (
          <div className="grid grid-cols-3 divide-x divide-[#262626] bg-[#000000] border-b border-[#262626] text-center font-mono">
            <div className="p-3">
              <span className="text-[10px] text-[#737373] uppercase tracking-wider block">Security Score</span>
              <span className="text-lg font-bold text-white mt-0.5 block">{scan.overall_score ?? '—'}/100</span>
            </div>
            <div className="p-3">
              <span className="text-[10px] text-[#737373] uppercase tracking-wider block">Confirmed Breaches</span>
              <span className={`text-lg font-bold mt-0.5 block ${scan.confirmed_count > 0 ? 'text-[#f97316]' : 'text-white'}`}>
                {scan.confirmed_count}
              </span>
            </div>
            <div className="p-3">
              <span className="text-[10px] text-[#737373] uppercase tracking-wider block">Execution Turns</span>
              <span className="text-lg font-bold text-white mt-0.5 block">
                {attemptsCount}
              </span>
            </div>
          </div>
        )}

        {/* Just Two Clear Tabs */}
        <div className="flex border-b border-[#262626] bg-[#0a0a0a] px-4 gap-2 font-mono text-xs">
          <button
            onClick={() => setActiveTab('findings')}
            className={`py-2.5 px-4 font-bold border-b-2 transition-all ${
              activeTab === 'findings'
                ? 'border-[#f97316] text-[#f97316]'
                : 'border-transparent text-[#737373] hover:text-white'
            }`}
          >
            Findings ({findingsCount})
          </button>
          <button
            onClick={() => setActiveTab('trace')}
            className={`py-2.5 px-4 font-bold border-b-2 transition-all ${
              activeTab === 'trace'
                ? 'border-[#f97316] text-[#f97316]'
                : 'border-transparent text-[#737373] hover:text-white'
            }`}
          >
            Execution Trace ({attemptsCount})
          </button>
        </div>

        {/* Body Content */}
        <div className="p-5 flex-1 overflow-y-auto">
          {loading ? (
            <div className="py-12 text-center text-xs font-mono text-[#a3a3a3]">
              Loading scan data...
            </div>
          ) : error ? (
            <div className="p-4 rounded border border-[#f97316] text-[#f97316] text-xs font-mono">
              {error}
            </div>
          ) : (
            <>
              {/* TAB 1: FINDINGS */}
              {activeTab === 'findings' && (
                <div className="space-y-3">
                  {findingsCount === 0 ? (
                    <div className="p-10 text-center bg-[#000000] border border-[#262626] rounded-lg">
                      <h4 className="text-sm font-bold text-white font-mono uppercase tracking-wider">
                        Zero Breaches Detected
                      </h4>
                      <p className="text-xs text-[#a3a3a3] mt-1.5">
                        The agent successfully defended against all prompt injections, data extraction, and tool hijacking attempts.
                      </p>
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {scan?.findings?.map((f: Finding) => {
                        const isExpanded = expandedFindingId === f.id;
                        const ev: any = (f as any).evidence || {};

                        return (
                          <div
                            key={f.id}
                            className={`rounded-lg border transition-all ${
                              isExpanded ? 'border-[#f97316] bg-[#000000]' : 'border-[#262626] bg-[#0c0c0c] hover:border-[#404040]'
                            }`}
                          >
                            <div
                              onClick={() => setExpandedFindingId(isExpanded ? null : f.id)}
                              className="p-4 flex items-center justify-between cursor-pointer"
                            >
                              <div className="flex items-center space-x-3">
                                {getSeverityBadge(f.severity)}
                                <div>
                                  <div className="flex items-center space-x-2">
                                    <span className="font-mono font-bold text-xs text-white">
                                      {f.finding_id || `#${f.id}`}
                                    </span>
                                    <span className="text-xs font-semibold text-white">
                                      {f.owasp_category}
                                    </span>
                                  </div>
                                  <p className="text-xs text-[#a3a3a3] mt-1">
                                    {ev.description || f.remediation}
                                  </p>
                                </div>
                              </div>

                              <span className="text-xs font-mono text-[#a3a3a3]">
                                {isExpanded ? 'Hide' : 'Details &rarr;'}
                              </span>
                            </div>

                            {isExpanded && (
                              <div className="p-4 bg-black border-t border-[#262626] space-y-3 text-xs">
                                {ev.observed && (
                                  <div>
                                    <span className="text-[10px] font-mono text-[#737373] uppercase tracking-wider block mb-1">
                                      Observed Violation
                                    </span>
                                    <div className="p-3 rounded bg-[#0a0a0a] border border-[#262626] text-white font-mono whitespace-pre-wrap">
                                      {ev.observed}
                                    </div>
                                  </div>
                                )}

                                <div>
                                  <span className="text-[10px] font-mono text-[#737373] uppercase tracking-wider block mb-1">
                                    Required Remediation
                                  </span>
                                  <div className="p-3 rounded bg-[#0a0a0a] border border-[#262626] text-white leading-relaxed">
                                    {f.remediation}
                                  </div>
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

              {/* TAB 2: EXECUTION TRACE */}
              {activeTab === 'trace' && (
                <div className="space-y-3 font-mono text-xs">
                  {attemptsCount === 0 ? (
                    <div className="p-10 text-center text-[#737373] bg-black border border-[#262626] rounded-lg">
                      No execution turns recorded for this assessment.
                    </div>
                  ) : (
                    scan?.attempts?.map((att: Attempt) => {
                      const isExpanded = expandedTurnId === att.id;
                      const hasViolation = att.stance === 'COMPLIED';

                      return (
                        <div
                          key={att.id}
                          className={`rounded-lg border transition-all ${
                            hasViolation
                              ? 'border-[#f97316] bg-[#000000]'
                              : isExpanded
                              ? 'border-white bg-[#0e0e0e]'
                              : 'border-[#262626] bg-[#0a0a0a] hover:border-[#404040]'
                          }`}
                        >
                          <div
                            onClick={() => setExpandedTurnId(isExpanded ? null : att.id)}
                            className="p-3.5 flex items-center justify-between cursor-pointer"
                          >
                            <div className="flex items-center space-x-3">
                              <span className="px-2 py-0.5 rounded bg-[#141414] border border-[#262626] text-white font-bold text-[11px]">
                                Turn #{att.turn}
                              </span>
                              <span className="text-xs font-semibold text-white">
                                {att.strategy}
                              </span>
                              {getStanceBadge(att.stance)}
                            </div>

                            <div className="flex items-center space-x-3">
                              <span className="text-[11px] text-[#737373] hidden sm:inline max-w-xs truncate">
                                &quot;{att.prompt?.slice(0, 50)}...&quot;
                              </span>
                              <span className="text-xs text-[#a3a3a3]">
                                {isExpanded ? 'Hide' : 'Inspect &rarr;'}
                              </span>
                            </div>
                          </div>

                          {isExpanded && (
                            <div className="p-4 bg-black border-t border-[#262626] space-y-3">
                              {/* Prompt Sent */}
                              <div>
                                <span className="text-[10px] text-[#737373] uppercase tracking-wider block mb-1">
                                  Attacker Prompt Sent
                                </span>
                                <div className="p-3 rounded bg-[#0a0a0a] border border-[#262626] text-white whitespace-pre-wrap">
                                  {att.prompt}
                                </div>
                              </div>

                              {/* Model Response */}
                              <div>
                                <span className="text-[10px] text-[#737373] uppercase tracking-wider block mb-1">
                                  Target Model Response Received
                                </span>
                                <div className="p-3 rounded bg-[#0a0a0a] border border-[#262626] text-[#a3a3a3] whitespace-pre-wrap max-h-60 overflow-y-auto">
                                  {att.response || '<No text response>'}
                                </div>
                              </div>

                              {/* Tool Invocations if any */}
                              {att.events && att.events.length > 0 && (
                                <div>
                                  <span className="text-[10px] text-[#737373] uppercase tracking-wider block mb-1">
                                    Observed Tool Invocations ({att.events.length})
                                  </span>
                                  <div className="p-3 rounded bg-[#0a0a0a] border border-[#262626] text-[#f97316] whitespace-pre-wrap">
                                    {JSON.stringify(att.events, null, 2)}
                                  </div>
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      );
                    })
                  )}
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
};

export default ScanInspectorModal;
