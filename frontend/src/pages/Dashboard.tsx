import React, { useState, useEffect } from 'react';
import { useTargets, useScans, useTriggerScan, useScanStream } from '@/hooks/useApi';
import { api } from '@/api/client';
import toast from 'react-hot-toast';

export const DashboardPage: React.FC = () => {
  const { targets, loading: targetsLoading, error: targetsError, refresh: refreshTargets } = useTargets();
  const { scans, loading: scansLoading, refresh: refreshScans } = useScans();

  const [selectedTargetId, setSelectedTargetId] = useState<number>(1);
  const [mitigationEnabled, setMitigationEnabled] = useState<boolean>(false);
  const [activeScanId, setActiveScanId] = useState<number | null>(null);
  const [apiKey, setApiKey] = useState<string>(() => localStorage.getItem('sb_api_key') || 'shadowboard_admin_secret_2026');
  const [apiKeyModalOpen, setApiKeyModalOpen] = useState<boolean>(false);
  const [healthStatus, setHealthStatus] = useState<'checking' | 'healthy' | 'unreachable'>('checking');

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
      setTimeout(refreshScans, 1500);
    } catch (err: any) {
      toast.error(err.message || 'Failed to start scan', { id: 'scan-trigger' });
    }
  };

  return (
    <div className="min-h-screen bg-[#070709] text-slate-100 flex flex-col font-sans">
      {/* Navigation Bar */}
      <nav className="h-16 px-6 bg-[#0c0c10] border-b border-[#1f1b22] flex items-center justify-between sticky top-0 z-40">
        <div className="flex items-center space-x-3">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-rose-600 to-rose-900 flex items-center justify-center font-black text-white text-base shadow-lg shadow-rose-900/30">
            🛡️
          </div>
          <span className="text-base font-extrabold tracking-wider text-white uppercase">ShadowBoard</span>
          <span className="px-2 py-0.5 rounded text-[10px] bg-rose-950/80 text-rose-400 font-mono border border-rose-600/40">
            SECURITY CONSOLE
          </span>
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
              <button
                onClick={refreshTargets}
                className="text-xs text-slate-400 hover:text-slate-200 font-mono"
              >
                ⟳ Refresh
              </button>
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
                  {targets.map((tgt) => (
                    <div
                      key={tgt.id}
                      onClick={() => setSelectedTargetId(tgt.id)}
                      className={`cursor-pointer rounded-lg p-3 border transition-all ${
                        selectedTargetId === tgt.id
                          ? 'border-rose-500/80 bg-rose-950/20 shadow-md shadow-rose-950/30'
                          : 'border-[#1f1b22] bg-[#0c0c10] hover:border-slate-700'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-xs text-white">#{tgt.id} {tgt.name}</span>
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[#16161e] text-slate-400 border border-[#26202c]">
                          {tgt.target_type || 'AGENT'}
                        </span>
                      </div>
                      <div className="text-[11px] font-mono text-slate-400 mt-2 truncate">
                        {tgt.base_url}
                      </div>
                    </div>
                  ))}
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
              <h2 className="text-sm font-bold text-white tracking-wide uppercase flex items-center space-x-2">
                <span>📡</span>
                <span>Active Telemetry Feed</span>
              </h2>
              <div className="bg-[#070709] border border-[#1f1b22] rounded-lg p-3 font-mono text-[11px] text-slate-300 min-h-[140px] max-h-[180px] overflow-y-auto space-y-1">
                {liveEvents.length === 0 ? (
                  <div className="text-slate-500 italic py-8 text-center">
                    {isStreaming ? 'Connecting to scan SSE stream...' : 'No active SSE stream. Launch a scan to observe real-time execution events.'}
                  </div>
                ) : (
                  liveEvents.map((evt, idx) => (
                    <div key={idx} className="leading-tight">
                      <span className="text-rose-400">[{evt.type || 'EVENT'}]</span>{' '}
                      <span className="text-slate-300">
                        {evt.finding_id ? `${evt.finding_id}: ${evt.status || ''}` : JSON.stringify(evt.data || evt)}
                      </span>
                    </div>
                  ))
                )}
              </div>
            </div>
            <div className="pt-3 border-t border-[#1f1b22] flex justify-between items-center text-[10px] font-mono text-slate-500">
              <span>Stream: {isStreaming ? 'CONNECTED' : 'IDLE'}</span>
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
                    <tr key={scan.id} className="hover:bg-[#16161e] transition-colors">
                      <td className="py-3 px-3 font-mono font-bold text-white">#{scan.id}</td>
                      <td className="py-3 px-3 text-slate-200">{scan.target_name || `Target #${scan.target_id}`}</td>
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
                            ? 'text-sky-400'
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
                      <td className="py-3 px-3 text-right">
                        <button
                          onClick={() => setActiveScanId(scan.id)}
                          className="px-2 py-1 rounded text-[11px] font-mono bg-[#1f1b22] hover:bg-slate-700 text-slate-300 transition-colors"
                        >
                          View Stream
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </main>
    </div>
  );
};

export default DashboardPage;
