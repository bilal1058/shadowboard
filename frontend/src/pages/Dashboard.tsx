import React, { useState, useEffect } from 'react';
import { useTargets, useScans, useTriggerScan, useScanStream } from '@/hooks/useApi';
import { api } from '@/api/client';
import { Target } from '@/types/api';
import toast from 'react-hot-toast';
import ScanInspectorModal from '@/components/ScanInspectorModal';
import TargetInspectorModal from '@/components/TargetInspectorModal';

export const DashboardPage: React.FC = () => {
  const { targets, loading: targetsLoading, error: targetsError, refresh: refreshTargets } = useTargets();
  const { scans, loading: scansLoading, refresh: refreshScans } = useScans();

  const [activeTab, setActiveTab] = useState<'dashboard' | 'targets' | 'history'>('dashboard');
  const [selectedTargetId, setSelectedTargetId] = useState<number>(1);
  const [mitigationEnabled, setMitigationEnabled] = useState<boolean>(false);
  const [activeScanId, setActiveScanId] = useState<number | null>(null);
  const [selectedScanModalId, setSelectedScanModalId] = useState<number | null>(null);
  const [inspectingTarget, setInspectingTarget] = useState<Target | null>(null);
  const [apiKey, setApiKey] = useState<string>(() => localStorage.getItem('sb_api_key') || 'shadowboard_admin_secret_2026');
  const [apiKeyModalOpen, setApiKeyModalOpen] = useState<boolean>(false);
  const [healthStatus, setHealthStatus] = useState<'checking' | 'healthy' | 'unreachable'>('checking');
  const [targetPingResults, setTargetPingResults] = useState<Record<number, { latency: number; status: string }>>({});

  const { trigger, isScanning } = useTriggerScan(selectedTargetId, mitigationEnabled);
  const { events: liveEvents, isStreaming } = useScanStream(activeScanId || 0);

  // Check health on mount
  useEffect(() => {
    fetch('/api/health')
      .then((res) => {
        if (res.ok) setHealthStatus('healthy');
        else setHealthStatus('unreachable');
      })
      .catch(() => setHealthStatus('unreachable'));
  }, []);

  const handleSaveApiKey = (key: string) => {
    setApiKey(key);
    if (key.trim()) {
      api.setApiKey(key.trim());
      toast.success('Admin API Key saved');
    } else {
      api.clearApiKey();
      toast.success('Admin API Key cleared');
    }
    setApiKeyModalOpen(false);
    refreshTargets();
    refreshScans();
  };

  const handleStartScan = async () => {
    try {
      toast.loading('Initiating security assessment...', { id: 'scan-trigger' });
      const result = await trigger();
      toast.success(`Scan #${result.scan_id} initiated`, { id: 'scan-trigger' });
      setActiveScanId(result.scan_id);
      setSelectedScanModalId(result.scan_id);
      setTimeout(refreshScans, 1500);
    } catch (err: any) {
      toast.error(err.message || 'Failed to start scan', { id: 'scan-trigger' });
    }
  };

  const pingTarget = async (tgt: Target) => {
    try {
      const t0 = performance.now();
      await api.post('/targets/test-connection', { base_url: tgt.base_url });
      const latency = Math.round(performance.now() - t0);
      setTargetPingResults((prev) => ({
        ...prev,
        [tgt.id]: { latency, status: 'HEALTHY' },
      }));
      toast.success(`Target #${tgt.id} reachable in ${latency}ms`);
    } catch (err: any) {
      setTargetPingResults((prev) => ({
        ...prev,
        [tgt.id]: { latency: 0, status: 'ERROR' },
      }));
      toast.error(`Target #${tgt.id} connection failed`);
    }
  };

  return (
    <div className="min-h-screen bg-[#070709] text-slate-100 flex flex-col font-sans">
      {/* Navigation Bar */}
      <nav className="h-16 px-6 bg-[#0c0c10] border-b border-[#1f1b22] flex items-center justify-between sticky top-0 z-40">
        <div className="flex items-center space-x-6">
          <div className="flex items-center space-x-3 cursor-pointer" onClick={() => setActiveTab('dashboard')}>
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-rose-600 to-rose-900 flex items-center justify-center font-black text-white text-base shadow-lg shadow-rose-900/30">
              🛡️
            </div>
            <span className="text-base font-extrabold tracking-wider text-white uppercase">ShadowBoard</span>
            <span className="px-2 py-0.5 rounded text-[10px] bg-rose-950/80 text-rose-400 font-mono border border-rose-600/40">
              SECURITY CONSOLE
            </span>
          </div>

          {/* Navigation Links */}
          <div className="hidden md:flex items-center space-x-1 font-mono text-xs">
            <button
              onClick={() => setActiveTab('dashboard')}
              className={`px-3 py-1.5 rounded-lg transition-colors flex items-center space-x-1.5 ${
                activeTab === 'dashboard'
                  ? 'bg-rose-950/40 text-rose-400 border border-rose-800/40'
                  : 'text-slate-400 hover:text-white hover:bg-[#16161e]'
              }`}
            >
              <span>📊</span>
              <span>Overview</span>
            </button>

            <button
              onClick={() => setActiveTab('targets')}
              className={`px-3 py-1.5 rounded-lg transition-colors flex items-center space-x-1.5 ${
                activeTab === 'targets'
                  ? 'bg-rose-950/40 text-rose-400 border border-rose-800/40'
                  : 'text-slate-400 hover:text-white hover:bg-[#16161e]'
              }`}
            >
              <span>🎯</span>
              <span>Targets Substrate ({targets.length})</span>
            </button>

            <button
              onClick={() => setActiveTab('history')}
              className={`px-3 py-1.5 rounded-lg transition-colors flex items-center space-x-1.5 ${
                activeTab === 'history'
                  ? 'bg-rose-950/40 text-rose-400 border border-rose-800/40'
                  : 'text-slate-400 hover:text-white hover:bg-[#16161e]'
              }`}
            >
              <span>📋</span>
              <span>Scans & Reports ({scans.length})</span>
            </button>
          </div>
        </div>

        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2 text-xs font-mono">
            <span
              className={`w-2 h-2 rounded-full ${
                healthStatus === 'healthy'
                  ? 'bg-emerald-500 animate-pulse'
                  : healthStatus === 'checking'
                  ? 'bg-amber-500'
                  : 'bg-rose-500'
              }`}
            />
            <span className="text-slate-400">
              API:{' '}
              <span
                className={
                  healthStatus === 'healthy'
                    ? 'text-emerald-400'
                    : healthStatus === 'checking'
                    ? 'text-amber-400'
                    : 'text-rose-400'
                }
              >
                {healthStatus.toUpperCase()}
              </span>
            </span>
          </div>

          <button
            onClick={() => setApiKeyModalOpen(true)}
            className="px-3 py-1.5 rounded text-xs bg-[#16161e] hover:bg-[#20202c] border border-[#2b2733] text-slate-300 font-mono transition-colors"
          >
            {apiKey ? '🔑 Key Configured' : '⚙️ Set API Key'}
          </button>
        </div>
      </nav>

      {/* Main Container */}
      <main className="flex-1 p-6 max-w-7xl w-full mx-auto space-y-6">
        {/* API Key Modal */}
        {apiKeyModalOpen && (
          <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4">
            <div className="bg-[#111116] border border-[#2b2733] rounded-xl max-w-md w-full p-6 space-y-4 shadow-2xl">
              <h3 className="text-base font-bold text-white flex items-center space-x-2">
                <span>🔑</span>
                <span>Configure Admin Authentication</span>
              </h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                When <code className="text-rose-300 bg-rose-950/50 px-1 py-0.5 rounded">SHADOWBOARD_ADMIN_KEY</code> is enabled on the backend, all scan management endpoints require bearer token authentication.
              </p>
              <div>
                <label className="block text-xs font-mono text-slate-300 mb-1">Admin API Key</label>
                <input
                  type="password"
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                  placeholder="Enter SHADOWBOARD_ADMIN_KEY..."
                  className="w-full bg-[#070709] border border-[#2b2733] rounded px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-rose-500"
                />
              </div>
              <div className="flex justify-end space-x-2 pt-2">
                <button
                  onClick={() => setApiKeyModalOpen(false)}
                  className="px-3 py-1.5 rounded text-xs text-slate-400 hover:text-white"
                >
                  Cancel
                </button>
                <button
                  onClick={() => handleSaveApiKey(apiKey)}
                  className="px-4 py-1.5 rounded text-xs font-semibold bg-rose-600 hover:bg-rose-500 text-white shadow-md shadow-rose-900/40"
                >
                  Save Key
                </button>
              </div>
            </div>
          </div>
        )}

        {/* TAB 1: DASHBOARD / OVERVIEW */}
        {activeTab === 'dashboard' && (
          <>
            {/* Top Section: Quick Scan Dispatcher & Active Target Info */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Target Selection & Scan Trigger */}
              <div className="lg:col-span-2 bg-[#111116] border border-[#1f1b22] rounded-xl p-5 space-y-4">
                <div className="flex items-center justify-between border-b border-[#1f1b22] pb-3">
                  <div>
                    <h2 className="text-sm font-bold text-white tracking-wide uppercase flex items-center space-x-2">
                      <span>🎯</span>
                      <span>Target Substrate & Dispatcher</span>
                    </h2>
                    <p className="text-xs text-slate-400 mt-0.5">Select a registered AI agent to execute automated adversarial probes</p>
                  </div>
                  <div className="flex items-center space-x-2">
                    <button
                      onClick={() => setActiveTab('targets')}
                      className="text-xs text-indigo-400 hover:underline font-mono"
                    >
                      View All Targets ↗
                    </button>
                    <button
                      onClick={refreshTargets}
                      className="text-xs text-slate-400 hover:text-slate-200 font-mono ml-2"
                    >
                      ⟳ Refresh
                    </button>
                  </div>
                </div>

                {targetsLoading ? (
                  <div className="text-xs text-slate-500 py-6 text-center">Loading targets from persistence...</div>
                ) : targetsError ? (
                  <div className="text-xs text-rose-400 py-4 bg-rose-950/20 border border-rose-900/40 rounded p-3">
                    Error loading targets: {targetsError}
                  </div>
                ) : (
                  <div className="space-y-4">
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                      {targets.map((tgt) => {
                        const caps: any = tgt.capabilities || {};
                        const isSelected = selectedTargetId === tgt.id;
                        return (
                          <div
                            key={tgt.id}
                            className={`rounded-lg p-3 border transition-all flex flex-col justify-between ${
                              isSelected
                                ? 'border-rose-500/80 bg-rose-950/20 shadow-md shadow-rose-950/30'
                                : 'border-[#1f1b22] bg-[#0c0c10] hover:border-slate-700'
                            }`}
                          >
                            <div
                              onClick={() => setSelectedTargetId(tgt.id)}
                              className="cursor-pointer space-y-2"
                            >
                              <div className="flex items-center justify-between">
                                <span className="font-semibold text-xs text-white">#{tgt.id} {tgt.name}</span>
                                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[#16161e] text-slate-400 border border-[#26202c]">
                                  {tgt.target_type || 'AGENT'}
                                </span>
                              </div>
                              <div className="text-[11px] font-mono text-slate-400 truncate">
                                {tgt.base_url}
                              </div>

                              {/* Capabilities tags */}
                              <div className="flex flex-wrap gap-1.5 pt-1">
                                {caps.chat !== false && (
                                  <span className="px-1.5 py-0.2 rounded text-[9px] font-mono bg-emerald-950/80 text-emerald-400 border border-emerald-800/40">
                                    CHAT
                                  </span>
                                )}
                                {caps.rag && (
                                  <span className="px-1.5 py-0.2 rounded text-[9px] font-mono bg-indigo-950/80 text-indigo-400 border border-indigo-800/40">
                                    RAG
                                  </span>
                                )}
                                {caps.tools && (
                                  <span className="px-1.5 py-0.2 rounded text-[9px] font-mono bg-amber-950/80 text-amber-400 border border-amber-800/40">
                                    {caps.tool_names?.length ? `${caps.tool_names.length} TOOLS` : 'TOOLS'}
                                  </span>
                                )}
                                {caps.data_access && (
                                  <span className="px-1.5 py-0.2 rounded text-[9px] font-mono bg-rose-950/80 text-rose-400 border border-rose-800/40">
                                    DB
                                  </span>
                                )}
                              </div>
                            </div>

                            <div className="mt-3 pt-2 border-t border-[#1f1b22] flex items-center justify-between">
                              <button
                                onClick={(e) => {
                                  e.stopPropagation();
                                  setInspectingTarget(tgt);
                                }}
                                className="text-[11px] font-mono text-indigo-400 hover:text-indigo-300 transition-colors"
                              >
                                🔍 Inspect Target & Sandbox &rarr;
                              </button>
                              <button
                                onClick={(e) => {
                                  e.stopPropagation();
                                  setSelectedTargetId(tgt.id);
                                }}
                                className={`text-[10px] font-mono px-2 py-0.5 rounded ${
                                  isSelected ? 'bg-rose-600 text-white' : 'bg-[#181822] text-slate-400'
                                }`}
                              >
                                {isSelected ? 'Selected' : 'Select'}
                              </button>
                            </div>
                          </div>
                        );
                      })}
                    </div>

                    <div className="pt-2 border-t border-[#1f1b22] flex flex-wrap items-center justify-between gap-4">
                      <label className="flex items-center space-x-2 text-xs cursor-pointer select-none">
                        <input
                          type="checkbox"
                          checked={mitigationEnabled}
                          onChange={(e) => setMitigationEnabled(e.target.checked)}
                          className="rounded bg-[#070709] border-slate-700 text-rose-600 focus:ring-0 focus:ring-offset-0"
                        />
                        <span className="text-slate-300 font-medium">Enable Target Mitigation / Guardrails</span>
                        <span className="text-[10px] text-slate-500 font-mono">
                          ({mitigationEnabled ? 'Mitigated Mode' : 'Vulnerable Mode'})
                        </span>
                      </label>

                      <button
                        onClick={handleStartScan}
                        disabled={isScanning || targets.length === 0}
                        className="px-5 py-2 rounded-lg text-xs font-bold tracking-wide uppercase bg-rose-600 hover:bg-rose-500 disabled:opacity-50 text-white shadow-lg shadow-rose-900/40 transition-all flex items-center space-x-2"
                      >
                        <span>{isScanning ? '⏳ Executing...' : '⚡ Launch Security Assessment'}</span>
                      </button>
                    </div>
                  </div>
                )}
              </div>

              {/* Real-time Status Card */}
              <div className="bg-[#111116] border border-[#1f1b22] rounded-xl p-5 flex flex-col justify-between">
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <h2 className="text-sm font-bold text-white tracking-wide uppercase flex items-center space-x-2">
                      <span>📡</span>
                      <span>Active Telemetry Feed</span>
                    </h2>
                    {activeScanId && (
                      <span className="text-[10px] font-mono text-slate-400">
                        Scan #{activeScanId}
                      </span>
                    )}
                  </div>

                  <div className="bg-[#070709] border border-[#1f1b22] rounded-lg p-3 font-mono text-[11px] text-slate-300 min-h-[160px] max-h-[220px] overflow-y-auto space-y-1.5">
                    {liveEvents.length === 0 ? (
                      <div className="text-slate-500 italic py-10 text-center">
                        {isStreaming
                          ? 'Connecting to scan SSE stream...'
                          : 'No active SSE stream. Launch a scan or click "View Stream" on any historical scan below.'}
                      </div>
                    ) : (
                      liveEvents.map((evt, idx) => (
                        <div key={idx} className="leading-tight flex items-start space-x-1.5">
                          <span className="text-rose-400 font-bold shrink-0">[{evt.type || 'EVENT'}]</span>
                          <span className="text-slate-300 break-all">
                            {evt.data?.message || (evt.data?.snippet ? `${evt.data.strategy}: ${evt.data.snippet}` : evt.finding_id ? `${evt.finding_id}: ${evt.status || ''}` : JSON.stringify(evt.data || evt))}
                          </span>
                        </div>
                      ))
                    )}
                  </div>
                </div>

                <div className="pt-3 border-t border-[#1f1b22] flex justify-between items-center text-[10px] font-mono text-slate-500">
                  <div className="flex items-center space-x-2">
                    <span className={`w-2 h-2 rounded-full ${isStreaming ? 'bg-emerald-500 animate-pulse' : 'bg-slate-600'}`} />
                    <span>Stream: {isStreaming ? 'STREAMING' : 'IDLE'}</span>
                  </div>
                  <span>Events: {liveEvents.length}</span>
                </div>
              </div>
            </div>

            {/* Scan History Table */}
            <div className="bg-[#111116] border border-[#1f1b22] rounded-xl p-5 space-y-4">
              <div className="flex items-center justify-between border-b border-[#1f1b22] pb-3">
                <div>
                  <h2 className="text-sm font-bold text-white tracking-wide uppercase flex items-center space-x-2">
                    <span>📋</span>
                    <span>Security Assessment History</span>
                  </h2>
                  <p className="text-xs text-slate-400 mt-0.5">Historical verification runs, risk scores, and cryptographic findings</p>
                </div>
                <button
                  onClick={refreshScans}
                  className="text-xs text-slate-400 hover:text-slate-200 font-mono"
                >
                  ⟳ Refresh
                </button>
              </div>

              {scansLoading ? (
                <div className="text-xs text-slate-500 py-6 text-center">Loading scan runs...</div>
              ) : scans.length === 0 ? (
                <div className="text-xs text-slate-500 py-8 text-center border border-dashed border-[#1f1b22] rounded-lg">
                  No scan assessments executed yet. Click &quot;Launch Security Assessment&quot; above.
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead>
                      <tr className="border-b border-[#1f1b22] text-slate-400 font-mono text-[11px]">
                        <th className="py-2.5 px-3">SCAN ID</th>
                        <th className="py-2.5 px-3">TARGET</th>
                        <th className="py-2.5 px-3">MODE</th>
                        <th className="py-2.5 px-3">STATUS</th>
                        <th className="py-2.5 px-3">CONFIRMED VULNS</th>
                        <th className="py-2.5 px-3">RISK SCORE</th>
                        <th className="py-2.5 px-3">STARTED</th>
                        <th className="py-2.5 px-3 text-right">ACTIONS</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#1f1b22]">
                      {scans.map((scan) => (
                        <tr
                          key={scan.id}
                          className="hover:bg-[#16161e] transition-colors cursor-pointer"
                          onClick={() => {
                            setActiveScanId(scan.id);
                            setSelectedScanModalId(scan.id);
                          }}
                        >
                          <td className="py-3 px-3 font-mono font-bold text-white">#{scan.id}</td>
                          <td className="py-3 px-3 text-slate-200 font-medium">{scan.target_name || `Target #${scan.target_id}`}</td>
                          <td className="py-3 px-3">
                            <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono border ${
                              scan.mitigation_enabled
                                ? 'bg-emerald-950/60 text-emerald-400 border-emerald-800/40'
                                : 'bg-amber-950/60 text-amber-400 border-amber-800/40'
                            }`}>
                              {scan.mitigation_enabled ? 'MITIGATED' : 'VULNERABLE'}
                            </span>
                          </td>
                          <td className="py-3 px-3">
                            <span className={`font-mono text-[11px] ${
                              scan.status === 'COMPLETED'
                                ? 'text-emerald-400'
                                : scan.status === 'RUNNING'
                                ? 'text-sky-400 animate-pulse'
                                : 'text-rose-400'
                            }`}>
                              {scan.status}
                            </span>
                          </td>
                          <td className="py-3 px-3 font-mono">
                            {scan.confirmed_count > 0 ? (
                              <span className="text-rose-400 font-bold bg-rose-950/40 px-2 py-0.5 rounded border border-rose-800/30">
                                {scan.confirmed_count} Breach{scan.confirmed_count > 1 ? 'es' : ''}
                              </span>
                            ) : (
                              <span className="text-emerald-400">0 Breaches</span>
                            )}
                          </td>
                          <td className="py-3 px-3 font-mono">
                            <span className="text-slate-300 font-bold">{scan.overall_score ?? '—'}</span>
                            {scan.risk_grade && (
                              <span className="ml-1 text-slate-500 font-normal">({scan.risk_grade})</span>
                            )}
                          </td>
                          <td className="py-3 px-3 font-mono text-[11px] text-slate-400">
                            {scan.started_at ? new Date(scan.started_at).toLocaleTimeString() : '—'}
                          </td>
                          <td className="py-3 px-3 text-right" onClick={(e) => e.stopPropagation()}>
                            <div className="flex items-center justify-end space-x-2">
                              <button
                                onClick={() => {
                                  setActiveScanId(scan.id);
                                  setSelectedScanModalId(scan.id);
                                }}
                                className="px-2.5 py-1 rounded text-[11px] font-mono bg-rose-950/40 hover:bg-rose-900/60 text-rose-300 border border-rose-800/40 transition-colors flex items-center space-x-1"
                              >
                                <span>🔍</span>
                                <span>View Stream</span>
                              </button>
                              <a
                                href={`/api/scans/${scan.id}/export/pdf?api_key=${encodeURIComponent(apiKey)}`}
                                target="_blank"
                                rel="noreferrer"
                                className="px-2 py-1 rounded text-[11px] font-mono bg-[#1f1b22] hover:bg-slate-700 text-slate-300 transition-colors"
                                title="Download Boardroom PDF"
                              >
                                PDF
                              </a>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </>
        )}

        {/* TAB 2: DEDICATED TARGETS SUBSTRATE PAGE ("can we see targets") */}
        {activeTab === 'targets' && (
          <div className="space-y-6">
            <div className="flex items-center justify-between border-b border-[#1f1b22] pb-4">
              <div>
                <h2 className="text-base font-bold text-white tracking-wide uppercase flex items-center space-x-2">
                  <span>🎯</span>
                  <span>Registered AI Targets Substrate</span>
                </h2>
                <p className="text-xs text-slate-400 mt-1">
                  Inspect active models, verify endpoint connectivity, explore knowledge base documents, and test directly in the interactive sandbox.
                </p>
              </div>
              <button
                onClick={refreshTargets}
                className="px-3 py-1.5 rounded-lg text-xs font-mono bg-[#16161e] border border-[#2b2733] text-slate-300 hover:text-white transition-colors"
              >
                ⟳ Refresh Targets
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {targets.map((tgt) => {
                const caps: any = tgt.capabilities || {};
                const hasRag = Boolean(caps.rag || tgt.target_type === 'INTERNAL_RAG' || tgt.base_url.includes('internal-rag'));
                const ping = targetPingResults[tgt.id];

                return (
                  <div
                    key={tgt.id}
                    className="bg-[#111116] border border-[#1f1b22] rounded-xl p-5 space-y-4 hover:border-slate-700 transition-all flex flex-col justify-between"
                  >
                    <div className="space-y-3">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-2">
                          <span className="font-extrabold text-sm text-white">#{tgt.id} {tgt.name}</span>
                        </div>
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-indigo-950 text-indigo-400 border border-indigo-800/40">
                          {tgt.target_type || 'AGENT'}
                        </span>
                      </div>

                      <div className="p-3 rounded-lg bg-[#070709] border border-[#1b1922] space-y-1.5 text-xs font-mono">
                        <div className="flex justify-between">
                          <span className="text-slate-500">Base Endpoint:</span>
                          <span className="text-slate-300 truncate max-w-[220px]">{tgt.base_url}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-slate-500">Target Model:</span>
                          <span className="text-white font-semibold">{tgt.model_name || 'qwen-flash'}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-slate-500">Operating Mode:</span>
                          <span className="text-emerald-400">{tgt.target_mode || 'INSTRUMENTED'}</span>
                        </div>
                      </div>

                      {/* Capabilities Matrix */}
                      <div>
                        <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider block mb-1.5">
                          Capabilities & Architecture
                        </span>
                        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                          <div className="p-2 rounded bg-[#0d0d14] border border-[#1f1b25] text-center">
                            <span className="text-xs block">💬</span>
                            <span className="text-[10px] font-mono font-bold text-emerald-400">CHAT</span>
                          </div>
                          <div className={`p-2 rounded border text-center ${
                            hasRag ? 'bg-indigo-950/30 border-indigo-800/40 text-indigo-300' : 'bg-[#0d0d14] border-[#1f1b25] text-slate-600'
                          }`}>
                            <span className="text-xs block">📚</span>
                            <span className="text-[10px] font-mono font-bold">{hasRag ? 'RAG ON' : 'NO RAG'}</span>
                          </div>
                          <div className={`p-2 rounded border text-center ${
                            caps.tools ? 'bg-amber-950/30 border-amber-800/40 text-amber-300' : 'bg-[#0d0d14] border-[#1f1b25] text-slate-600'
                          }`}>
                            <span className="text-xs block">🛠️</span>
                            <span className="text-[10px] font-mono font-bold">{caps.tools ? 'TOOLS' : 'NO TOOLS'}</span>
                          </div>
                          <div className={`p-2 rounded border text-center ${
                            caps.data_access ? 'bg-rose-950/30 border-rose-800/40 text-rose-300' : 'bg-[#0d0d14] border-[#1f1b25] text-slate-600'
                          }`}>
                            <span className="text-xs block">🗄️</span>
                            <span className="text-[10px] font-mono font-bold">{caps.data_access ? 'DATABASE' : 'NO DB'}</span>
                          </div>
                        </div>
                      </div>

                      {/* Ping Status */}
                      {ping && (
                        <div className={`p-2 rounded-lg text-xs font-mono flex items-center justify-between ${
                          ping.status === 'HEALTHY' ? 'bg-emerald-950/30 border border-emerald-800/40 text-emerald-300' : 'bg-rose-950/30 border border-rose-800/40 text-rose-300'
                        }`}>
                          <span>Status: {ping.status}</span>
                          {ping.latency > 0 && <span>Latency: {ping.latency}ms</span>}
                        </div>
                      )}
                    </div>

                    <div className="pt-3 border-t border-[#1f1b22] flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center space-x-2">
                        <button
                          onClick={() => pingTarget(tgt)}
                          className="px-2.5 py-1.5 rounded-lg text-xs font-mono bg-[#16161e] hover:bg-[#20202c] border border-[#2b2733] text-slate-300 transition-colors"
                        >
                          ⚡ Ping Endpoint
                        </button>
                        <a
                          href={tgt.base_url}
                          target="_blank"
                          rel="noreferrer"
                          className="px-2.5 py-1.5 rounded-lg text-xs font-mono bg-[#16161e] hover:bg-[#20202c] border border-[#2b2733] text-slate-400 hover:text-slate-200 transition-colors"
                        >
                          App ↗
                        </a>
                      </div>

                      <div className="flex items-center space-x-2">
                        <button
                          onClick={() => setInspectingTarget(tgt)}
                          className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 text-white transition-colors shadow-sm"
                        >
                          🔍 Inspect & Sandbox
                        </button>
                        <button
                          onClick={() => {
                            setSelectedTargetId(tgt.id);
                            setActiveTab('dashboard');
                            toast.success(`Selected Target #${tgt.id} for assessment`);
                          }}
                          className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-rose-600 hover:bg-rose-500 text-white transition-colors shadow-sm"
                        >
                          Run Scan
                        </button>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* TAB 3: SCANS HISTORY PAGE */}
        {activeTab === 'history' && (
          <div className="space-y-6">
            <div className="flex items-center justify-between border-b border-[#1f1b22] pb-4">
              <div>
                <h2 className="text-base font-bold text-white tracking-wide uppercase flex items-center space-x-2">
                  <span>📋</span>
                  <span>Security Audit Log & Scan Archive</span>
                </h2>
                <p className="text-xs text-slate-400 mt-1">
                  Full historical records of adversarial simulations, cryptographic findings, and executive PDF reports.
                </p>
              </div>
              <button
                onClick={refreshScans}
                className="px-3 py-1.5 rounded-lg text-xs font-mono bg-[#16161e] border border-[#2b2733] text-slate-300 hover:text-white transition-colors"
              >
                ⟳ Refresh Scans
              </button>
            </div>

            <div className="bg-[#111116] border border-[#1f1b22] rounded-xl overflow-hidden">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-[#1f1b22] bg-[#0c0c10] text-slate-400 font-mono text-[11px]">
                    <th className="py-3 px-4">SCAN ID</th>
                    <th className="py-3 px-4">TARGET</th>
                    <th className="py-3 px-4">MODE</th>
                    <th className="py-3 px-4">STATUS</th>
                    <th className="py-3 px-4">BREACHES</th>
                    <th className="py-3 px-4">RISK SCORE</th>
                    <th className="py-3 px-4">STARTED AT</th>
                    <th className="py-3 px-4 text-right">ACTIONS</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1f1b22]">
                  {scans.map((scan) => (
                    <tr
                      key={scan.id}
                      className="hover:bg-[#16161e] transition-colors cursor-pointer"
                      onClick={() => {
                        setActiveScanId(scan.id);
                        setSelectedScanModalId(scan.id);
                      }}
                    >
                      <td className="py-3.5 px-4 font-mono font-bold text-white">#{scan.id}</td>
                      <td className="py-3.5 px-4 text-slate-200 font-medium">{scan.target_name || `Target #${scan.target_id}`}</td>
                      <td className="py-3.5 px-4">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-mono border ${
                          scan.mitigation_enabled
                            ? 'bg-emerald-950/60 text-emerald-400 border-emerald-800/40'
                            : 'bg-amber-950/60 text-amber-400 border-amber-800/40'
                        }`}>
                          {scan.mitigation_enabled ? 'MITIGATED' : 'VULNERABLE'}
                        </span>
                      </td>
                      <td className="py-3.5 px-4">
                        <span className={`font-mono text-xs ${
                          scan.status === 'COMPLETED'
                            ? 'text-emerald-400'
                            : scan.status === 'RUNNING'
                            ? 'text-sky-400 animate-pulse'
                            : 'text-rose-400'
                        }`}>
                          {scan.status}
                        </span>
                      </td>
                      <td className="py-3.5 px-4 font-mono">
                        {scan.confirmed_count > 0 ? (
                          <span className="text-rose-400 font-bold bg-rose-950/40 px-2 py-0.5 rounded border border-rose-800/30">
                            {scan.confirmed_count} Breach{scan.confirmed_count > 1 ? 'es' : ''}
                          </span>
                        ) : (
                          <span className="text-emerald-400">0 Breaches</span>
                        )}
                      </td>
                      <td className="py-3.5 px-4 font-mono">
                        <span className="text-white font-bold">{scan.overall_score ?? '—'}</span>
                        {scan.risk_grade && (
                          <span className="ml-1 text-slate-400">({scan.risk_grade})</span>
                        )}
                      </td>
                      <td className="py-3.5 px-4 font-mono text-[11px] text-slate-400">
                        {scan.started_at ? new Date(scan.started_at).toLocaleString() : '—'}
                      </td>
                      <td className="py-3.5 px-4 text-right" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-center justify-end space-x-2">
                          <button
                            onClick={() => {
                              setActiveScanId(scan.id);
                              setSelectedScanModalId(scan.id);
                            }}
                            className="px-3 py-1 rounded text-xs font-mono bg-rose-600 hover:bg-rose-500 text-white transition-colors"
                          >
                            Inspect & Stream
                          </button>
                          <a
                            href={`/api/scans/${scan.id}/export/pdf?api_key=${encodeURIComponent(apiKey)}`}
                            target="_blank"
                            rel="noreferrer"
                            className="px-2.5 py-1 rounded text-xs font-mono bg-[#1e1c26] hover:bg-slate-700 text-slate-300 transition-colors"
                          >
                            PDF
                          </a>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Scan Inspector Modal */}
        <ScanInspectorModal
          scanId={selectedScanModalId}
          onClose={() => setSelectedScanModalId(null)}
          onRerunScan={(tgtId, mit) => {
            setSelectedTargetId(tgtId);
            setMitigationEnabled(mit);
            setSelectedScanModalId(null);
            handleStartScan();
          }}
        />

        {/* Target Inspector Modal */}
        <TargetInspectorModal
          target={inspectingTarget}
          onClose={() => setInspectingTarget(null)}
          onSelectForScan={(tgtId) => {
            setSelectedTargetId(tgtId);
            setActiveTab('dashboard');
            toast.success(`Target #${tgtId} selected for assessment`);
          }}
        />
      </main>
    </div>
  );
};

export default DashboardPage;
