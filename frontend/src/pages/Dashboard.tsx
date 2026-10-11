import React, { useState, useEffect } from 'react';
import { useTargets, useScans, useTriggerScan } from '@/hooks/useApi';
import { api } from '@/api/client';
import { Target } from '@/types/api';
import toast from 'react-hot-toast';
import ScanInspectorModal from '@/components/ScanInspectorModal';
import TargetInspectorModal from '@/components/TargetInspectorModal';
import OnboardTargetModal from '@/components/OnboardTargetModal';
import DifferentialAuthMatrixViewer from '@/components/DifferentialAuthMatrixViewer';

export const DashboardPage: React.FC = () => {
  const { targets, loading: targetsLoading, error: targetsError, refresh: refreshTargets } = useTargets();
  const { scans, loading: scansLoading, refresh: refreshScans } = useScans();

  const [activeTab, setActiveTab] = useState<'dashboard' | 'targets' | 'diff_auth' | 'history'>('dashboard');
  const [onboardModalOpen, setOnboardModalOpen] = useState<boolean>(false);
  const [selectedTargetId, setSelectedTargetId] = useState<number>(0);
  const [selectedScanModalId, setSelectedScanModalId] = useState<number | null>(null);
  const [inspectingTarget, setInspectingTarget] = useState<Target | null>(null);
  const [apiKey, setApiKey] = useState<string>('');
  const [adminSessionActive, setAdminSessionActive] = useState<boolean>(false);
  const [apiKeyModalOpen, setApiKeyModalOpen] = useState<boolean>(false);

  const { trigger, isScanning } = useTriggerScan(selectedTargetId);

  // Check saved admin session on mount
  useEffect(() => {
    api.checkSession().then((active) => {
      if (active) {
        setAdminSessionActive(true);
      }
    });
  }, []);

  // Sync selected target when targets list updates
  useEffect(() => {
    if (targets.length > 0) {
      if (!selectedTargetId || !targets.some((t) => t.id === selectedTargetId)) {
        setSelectedTargetId(targets[0].id);
      }
    }
  }, [targets, selectedTargetId]);

  // Reload targets and scans when admin session becomes active
  useEffect(() => {
    if (adminSessionActive) {
      refreshTargets();
      refreshScans();
    }
  }, [adminSessionActive]);

  const handleSaveApiKey = async (key: string) => {
    const cleanKey = key.trim();
    if (!cleanKey) return;
    try {
      await api.establishBrowserSession(cleanKey);
      setAdminSessionActive(true);
      setApiKeyModalOpen(false);
      setApiKey('');
      toast.success('Session authenticated');
      await refreshTargets();
      await refreshScans();
    } catch (error: any) {
      toast.error(error.message || 'Authentication failed');
    }
  };

  const handleStartScan = async () => {
    try {
      toast.loading('Starting security scan...', { id: 'scan-trigger' });
      const result = await trigger();
      toast.success(`Scan #${result.scan_id} started`, { id: 'scan-trigger' });
      setSelectedScanModalId(result.scan_id);
      setTimeout(refreshScans, 1500);
    } catch (err: any) {
      toast.error(err.message || 'Failed to start scan', { id: 'scan-trigger' });
    }
  };

  const handleDeleteScan = async (scanId: number, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!window.confirm(`Delete scan #${scanId} record?`)) return;
    try {
      const res = await fetch(`/api/scans/${scanId}`, { method: 'DELETE' });
      if (res.ok) {
        toast.success(`Scan #${scanId} deleted`);
        refreshScans();
      } else {
        toast.error('Failed to delete scan');
      }
    } catch (err: any) {
      toast.error(err.message || 'Failed to delete scan');
    }
  };

  const handleStopScan = async (scanId: number, e: React.MouseEvent) => {
    e.stopPropagation();
    try {
      const res = await fetch(`/api/scans/${scanId}/stop`, { method: 'POST' });
      if (res.ok) {
        toast.success(`Scan #${scanId} stopped`);
        refreshScans();
      }
    } catch (err: any) {
      toast.error(err.message || 'Failed to stop scan');
    }
  };

  const selectedTarget = targets.find((t) => t.id === selectedTargetId);

  return (
    <div className="min-h-screen bg-black text-white flex flex-col font-sans selection:bg-orange-500 selection:text-black">
      {/* Navigation Bar */}
      <nav className="h-16 px-6 bg-black border-b border-[#262626] flex items-center justify-between sticky top-0 z-40">
        <div className="flex items-center space-x-8">
          <div
            className="flex items-center space-x-3 cursor-pointer"
            onClick={() => setActiveTab('dashboard')}
          >
            <div className="w-8 h-8 rounded bg-orange-500 flex items-center justify-center font-black text-black text-sm tracking-tighter">
              SB
            </div>
            <span className="text-sm font-bold tracking-widest text-white uppercase font-mono">
              SHADOWBOARD
            </span>
          </div>

          {/* Navigation Links */}
          <div className="hidden md:flex items-center space-x-1 font-mono text-xs">
            <button
              onClick={() => setActiveTab('dashboard')}
              className={`px-3 py-1.5 rounded transition-colors ${
                activeTab === 'dashboard'
                  ? 'bg-[#141414] text-orange-400 border border-orange-500/40 font-semibold'
                  : 'text-[#a3a3a3] hover:text-white hover:bg-[#141414]'
              }`}
            >
              Overview
            </button>

            <button
              onClick={() => setActiveTab('targets')}
              className={`px-3 py-1.5 rounded transition-colors ${
                activeTab === 'targets'
                  ? 'bg-[#141414] text-orange-400 border border-orange-500/40 font-semibold'
                  : 'text-[#a3a3a3] hover:text-white hover:bg-[#141414]'
              }`}
            >
              Targets ({targets.length})
            </button>

            <button
              onClick={() => setActiveTab('diff_auth')}
              className={`px-3 py-1.5 rounded transition-colors ${
                activeTab === 'diff_auth'
                  ? 'bg-[#141414] text-orange-400 border border-orange-500/40 font-semibold'
                  : 'text-[#a3a3a3] hover:text-white hover:bg-[#141414]'
              }`}
            >
              Diff Auth
            </button>

            <button
              onClick={() => setActiveTab('history')}
              className={`px-3 py-1.5 rounded transition-colors ${
                activeTab === 'history'
                  ? 'bg-[#141414] text-orange-400 border border-orange-500/40 font-semibold'
                  : 'text-[#a3a3a3] hover:text-white hover:bg-[#141414]'
              }`}
            >
              Scans ({scans.length})
            </button>
          </div>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={() => setOnboardModalOpen(true)}
            className="px-3.5 py-1.5 rounded text-xs font-semibold bg-orange-500 hover:bg-orange-600 text-black font-mono transition-colors"
          >
            + Onboard Target
          </button>

          <button
            onClick={() => setApiKeyModalOpen(true)}
            className="px-3 py-1.5 rounded text-xs bg-[#141414] hover:bg-[#1a1a1a] border border-[#262626] text-[#a3a3a3] hover:text-white font-mono transition-colors"
          >
            {adminSessionActive ? 'Session Active' : 'Authenticate'}
          </button>
        </div>
      </nav>

      {/* Main Container */}
      <main className="flex-1 p-6 max-w-7xl w-full mx-auto space-y-6">
        {/* Authentication Modal */}
        {apiKeyModalOpen && (
          <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50 p-4">
            <div className="bg-[#0a0a0a] border border-[#262626] rounded-lg max-w-md w-full p-6 space-y-4">
              <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
                Admin Authentication
              </h3>
              <p className="text-xs text-[#a3a3a3] leading-relaxed">
                Enter your admin API key to manage targets and scans.
              </p>
              <div>
                <label className="block text-xs font-mono text-[#a3a3a3] mb-1">API Key</label>
                <input
                  type="password"
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                  placeholder="Enter SHADOWBOARD_ADMIN_KEY..."
                  className="w-full bg-black border border-[#262626] rounded px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-orange-500"
                />
              </div>
              <div className="flex justify-end space-x-2 pt-2">
                <button
                  onClick={() => setApiKeyModalOpen(false)}
                  className="px-3 py-1.5 rounded text-xs text-[#a3a3a3] hover:text-white font-mono"
                >
                  Cancel
                </button>
                <button
                  onClick={() => handleSaveApiKey(apiKey)}
                  className="px-4 py-1.5 rounded text-xs font-semibold bg-orange-500 hover:bg-orange-600 text-black font-mono"
                >
                  Save Key
                </button>
              </div>
            </div>
          </div>
        )}

        {/* TAB 1: OVERVIEW */}
        {activeTab === 'dashboard' && (
          <>
            {/* Target Selector Card */}
            <div className="bg-[#0a0a0a] border border-[#262626] rounded-lg p-5 space-y-4">
              <div className="flex flex-wrap items-center justify-between border-b border-[#262626] pb-3 gap-3">
                <div>
                  <h2 className="text-xs font-bold text-white uppercase tracking-widest font-mono">
                    Target Dispatcher
                  </h2>
                  <p className="text-xs text-[#a3a3a3] mt-0.5">
                    Select a target agent and launch adversarial security tests.
                  </p>
                </div>
                <div className="flex items-center space-x-2">
                  <button
                    onClick={() => setActiveTab('targets')}
                    className="px-3 py-1.5 rounded text-xs text-[#a3a3a3] hover:text-white bg-[#141414] border border-[#262626] font-mono transition-colors"
                  >
                    View All Targets
                  </button>
                  <button
                    onClick={refreshTargets}
                    className="px-3 py-1.5 rounded text-xs text-[#a3a3a3] hover:text-white bg-[#141414] border border-[#262626] font-mono transition-colors"
                  >
                    Refresh
                  </button>
                </div>
              </div>

              {targetsLoading ? (
                <div className="text-xs text-[#737373] py-6 text-center font-mono">
                  Loading targets...
                </div>
              ) : targetsError ? (
                <div className="text-xs text-orange-400 py-4 bg-orange-950/20 border border-orange-500/40 rounded p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div>Admin key required to access targets.</div>
                  <button
                    onClick={() => setApiKeyModalOpen(true)}
                    className="px-3.5 py-1.5 rounded text-xs font-semibold bg-orange-500 hover:bg-orange-600 text-black font-mono shrink-0"
                  >
                    Authenticate
                  </button>
                </div>
              ) : targets.length === 0 ? (
                <div className="text-xs text-[#737373] py-8 text-center border border-dashed border-[#262626] rounded font-mono">
                  No targets registered. Click &quot;+ Onboard Target&quot; above.
                </div>
              ) : (
                <div className="space-y-4">
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                    {targets.map((tgt) => {
                      const isSelected = selectedTargetId === tgt.id;
                      return (
                        <div
                          key={tgt.id}
                          onClick={() => setSelectedTargetId(tgt.id)}
                          className={`rounded-lg p-3.5 border transition-all cursor-pointer flex flex-col justify-between ${
                            isSelected
                              ? 'border-orange-500 bg-orange-950/20'
                              : 'border-[#262626] bg-black hover:border-[#404040]'
                          }`}
                        >
                          <div className="space-y-2">
                            <div className="flex items-center justify-between">
                              <span className="font-semibold text-xs text-white font-mono">
                                #{tgt.id} {tgt.name}
                              </span>
                              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[#141414] text-[#a3a3a3] border border-[#262626]">
                                {tgt.target_type || 'AGENT'}
                              </span>
                            </div>
                            <div className="text-[11px] font-mono text-[#a3a3a3] truncate">
                              {tgt.base_url}
                            </div>
                            <div className="text-[10px] font-mono text-[#737373]">
                              Model: <span className="text-white">{tgt.model_name || 'default'}</span>
                            </div>
                          </div>

                          <div className="mt-3 pt-2.5 border-t border-[#262626] flex items-center justify-between">
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                setInspectingTarget(tgt);
                              }}
                              className="text-[11px] font-mono text-orange-400 hover:text-orange-300 transition-colors"
                            >
                              Sandbox &rarr;
                            </button>
                            <span
                              className={`text-[10px] font-mono px-2 py-0.5 rounded ${
                                isSelected
                                  ? 'bg-orange-500 text-black font-semibold'
                                  : 'bg-[#141414] text-[#737373]'
                              }`}
                            >
                              {isSelected ? 'Selected' : 'Select'}
                            </span>
                          </div>
                        </div>
                      );
                    })}
                  </div>

                  <div className="pt-3 border-t border-[#262626] flex flex-wrap items-center justify-between gap-4">
                    <div className="text-xs font-mono text-[#a3a3a3]">
                      Target Active:{' '}
                      <span className="text-white font-semibold">
                        {selectedTarget ? `#${selectedTarget.id} ${selectedTarget.name}` : 'None'}
                      </span>
                    </div>

                    <button
                      onClick={handleStartScan}
                      disabled={isScanning || targets.length === 0}
                      className="px-5 py-2 rounded text-xs font-bold uppercase tracking-wider bg-orange-500 hover:bg-orange-600 disabled:opacity-50 text-black font-mono transition-colors"
                    >
                      {isScanning ? 'Executing Scan...' : 'Run Security Scan'}
                    </button>
                  </div>
                </div>
              )}
            </div>

            {/* Recent Scans Table */}
            <div className="bg-[#0a0a0a] border border-[#262626] rounded-lg p-5 space-y-4">
              <div className="flex items-center justify-between border-b border-[#262626] pb-3">
                <div>
                  <h2 className="text-xs font-bold text-white uppercase tracking-widest font-mono">
                    Recent Scans
                  </h2>
                  <p className="text-xs text-[#a3a3a3] mt-0.5">
                    Security verification runs and audit findings.
                  </p>
                </div>
                <button
                  onClick={refreshScans}
                  className="text-xs text-[#a3a3a3] hover:text-white font-mono"
                >
                  Refresh
                </button>
              </div>

              {scansLoading ? (
                <div className="text-xs text-[#737373] py-6 text-center font-mono">
                  Loading scans...
                </div>
              ) : scans.length === 0 ? (
                <div className="text-xs text-[#737373] py-8 text-center border border-dashed border-[#262626] rounded font-mono">
                  No scans executed yet. Click &quot;Run Security Scan&quot; above.
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs font-mono">
                    <thead>
                      <tr className="border-b border-[#262626] text-[#a3a3a3] text-[11px]">
                        <th className="py-2.5 px-3">SCAN ID</th>
                        <th className="py-2.5 px-3">TARGET</th>
                        <th className="py-2.5 px-3">STATUS</th>
                        <th className="py-2.5 px-3">BREACHES</th>
                        <th className="py-2.5 px-3">SCORE</th>
                        <th className="py-2.5 px-3">STARTED</th>
                        <th className="py-2.5 px-3 text-right">ACTIONS</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#262626]">
                      {scans.map((scan) => (
                        <tr
                          key={scan.id}
                          className="hover:bg-[#141414] transition-colors cursor-pointer"
                          onClick={() => setSelectedScanModalId(scan.id)}
                        >
                          <td className="py-3 px-3 font-bold text-white">#{scan.id}</td>
                          <td className="py-3 px-3 text-white">
                            {scan.target_name || `Target #${scan.target_id}`}
                          </td>
                          <td className="py-3 px-3">
                            <span
                              className={`text-[11px] ${
                                scan.status === 'COMPLETED'
                                  ? 'text-white'
                                  : scan.status === 'RUNNING'
                                  ? 'text-orange-400 font-semibold'
                                  : 'text-[#737373]'
                              }`}
                            >
                              {scan.status}
                            </span>
                          </td>
                          <td className="py-3 px-3">
                            {scan.confirmed_count > 0 ? (
                              <span className="text-orange-400 font-semibold">
                                {scan.confirmed_count} Breach{scan.confirmed_count > 1 ? 'es' : ''}
                              </span>
                            ) : (
                              <span className="text-[#a3a3a3]">0 Breaches</span>
                            )}
                          </td>
                          <td className="py-3 px-3 text-white font-bold">
                            {scan.overall_score ?? '—'}
                          </td>
                          <td className="py-3 px-3 text-[11px] text-[#737373]">
                            {scan.started_at ? new Date(scan.started_at).toLocaleTimeString() : '—'}
                          </td>
                          <td className="py-3 px-3 text-right" onClick={(e) => e.stopPropagation()}>
                            <div className="flex items-center justify-end space-x-2">
                              {scan.status === 'RUNNING' && (
                                <button
                                  onClick={(e) => handleStopScan(scan.id, e)}
                                  className="px-2 py-1 rounded text-[11px] bg-black hover:bg-[#141414] text-orange-400 border border-orange-500/40 font-semibold transition-colors"
                                  title="Stop running scan"
                                >
                                  Stop
                                </button>
                              )}
                              <button
                                onClick={() => setSelectedScanModalId(scan.id)}
                                className="px-2.5 py-1 rounded text-[11px] bg-[#141414] hover:bg-[#1a1a1a] text-orange-400 border border-orange-500/30 transition-colors"
                              >
                                View Details
                              </button>
                              <a
                                href={`/api/scans/${scan.id}/export/html`}
                                target="_blank"
                                rel="noreferrer"
                                className="px-2 py-1 rounded text-[11px] bg-black hover:bg-[#141414] text-white border border-[#262626] transition-colors"
                              >
                                HTML
                              </a>
                              <a
                                href={`/api/scans/${scan.id}/export/pdf`}
                                target="_blank"
                                rel="noreferrer"
                                className="px-2 py-1 rounded text-[11px] bg-black hover:bg-[#141414] text-[#a3a3a3] hover:text-white border border-[#262626] transition-colors"
                              >
                                PDF
                              </a>
                              <button
                                onClick={(e) => handleDeleteScan(scan.id, e)}
                                className="px-2 py-1 rounded text-[11px] bg-black hover:bg-[#141414] text-[#737373] hover:text-white border border-[#262626] transition-colors"
                                title="Delete scan record"
                              >
                                Delete
                              </button>
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

        {/* TAB 2: TARGETS SUBSTRATE */}
        {activeTab === 'targets' && (
          <div className="space-y-6">
            <div className="flex items-center justify-between border-b border-[#262626] pb-4">
              <div>
                <h2 className="text-sm font-bold text-white uppercase tracking-widest font-mono">
                  Registered Targets
                </h2>
                <p className="text-xs text-[#a3a3a3] mt-1 font-mono">
                  Configured targets available for adversarial evaluation.
                </p>
              </div>
              <div className="flex items-center space-x-2">
                <button
                  onClick={() => setOnboardModalOpen(true)}
                  className="px-3.5 py-1.5 rounded text-xs font-semibold bg-orange-500 hover:bg-orange-600 text-black font-mono transition-colors"
                >
                  + Onboard Target
                </button>
                <button
                  onClick={refreshTargets}
                  className="px-3 py-1.5 rounded text-xs font-mono bg-[#141414] border border-[#262626] text-[#a3a3a3] hover:text-white transition-colors"
                >
                  Refresh
                </button>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {targets.map((tgt) => {
                const caps: any = tgt.capabilities || {};
                const isSelected = selectedTargetId === tgt.id;

                return (
                  <div
                    key={tgt.id}
                    className="bg-[#0a0a0a] border border-[#262626] rounded-lg p-5 space-y-4 hover:border-[#404040] transition-colors flex flex-col justify-between"
                  >
                    <div className="space-y-3">
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-sm text-white font-mono">
                          #{tgt.id} {tgt.name}
                        </span>
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#141414] text-[#a3a3a3] border border-[#262626]">
                          {tgt.target_type || 'AGENT'}
                        </span>
                      </div>

                      <div className="p-3 rounded bg-black border border-[#262626] space-y-1.5 text-xs font-mono">
                        <div className="flex justify-between">
                          <span className="text-[#737373]">Endpoint:</span>
                          <span className="text-white truncate max-w-[240px]">{tgt.base_url}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-[#737373]">Model:</span>
                          <span className="text-white">{tgt.model_name || 'default'}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-[#737373]">Mode:</span>
                          <span className="text-white">{tgt.target_mode || 'INSTRUMENTED'}</span>
                        </div>
                      </div>

                      {/* Capabilities */}
                      <div className="flex flex-wrap gap-1.5 font-mono text-[10px]">
                        {caps.chat !== false && (
                          <span className="px-2 py-0.5 rounded bg-[#141414] text-white border border-[#262626]">
                            CHAT
                          </span>
                        )}
                        {caps.rag && (
                          <span className="px-2 py-0.5 rounded bg-orange-950/20 text-orange-400 border border-orange-500/30">
                            RAG
                          </span>
                        )}
                        {caps.tools && (
                          <span className="px-2 py-0.5 rounded bg-orange-950/20 text-orange-400 border border-orange-500/30">
                            {caps.tool_names?.length ? `${caps.tool_names.length} TOOLS` : 'TOOLS'}
                          </span>
                        )}
                        {caps.data_access && (
                          <span className="px-2 py-0.5 rounded bg-orange-950/20 text-orange-400 border border-orange-500/30">
                            DATABASE
                          </span>
                        )}
                      </div>
                    </div>

                    <div className="pt-3 border-t border-[#262626] flex items-center justify-between gap-2">
                      <button
                        onClick={() => setInspectingTarget(tgt)}
                        className="text-xs font-mono text-orange-400 hover:text-orange-300 transition-colors"
                      >
                        Inspect &amp; Sandbox &rarr;
                      </button>

                      <button
                        onClick={() => {
                          setSelectedTargetId(tgt.id);
                          setActiveTab('dashboard');
                          toast.success(`Selected Target #${tgt.id}`);
                        }}
                        className={`px-3 py-1.5 rounded text-xs font-mono font-semibold transition-colors ${
                          isSelected
                            ? 'bg-orange-500 text-black'
                            : 'bg-[#141414] hover:bg-[#1a1a1a] text-white border border-[#262626]'
                        }`}
                      >
                        {isSelected ? 'Active Target' : 'Select Target'}
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* TAB 3: DIFFERENTIAL AUTH MATRIX */}
        {activeTab === 'diff_auth' && (
          <div className="space-y-6">
            <div className="border-b border-[#262626] pb-4">
              <h2 className="text-sm font-bold text-white uppercase tracking-widest font-mono">
                Differential Authorization Matrix
              </h2>
              <p className="text-xs text-[#a3a3a3] mt-1 font-mono">
                Evaluates cross-tenant and role-boundary authorization directly against the target.
              </p>
            </div>
            <DifferentialAuthMatrixViewer />
          </div>
        )}

        {/* TAB 4: SCANS HISTORY */}
        {activeTab === 'history' && (
          <div className="space-y-6">
            <div className="flex items-center justify-between border-b border-[#262626] pb-4">
              <div>
                <h2 className="text-sm font-bold text-white uppercase tracking-widest font-mono">
                  Scan History
                </h2>
                <p className="text-xs text-[#a3a3a3] mt-1 font-mono">
                  Historical security audit records and exportable reports.
                </p>
              </div>
              <button
                onClick={refreshScans}
                className="px-3 py-1.5 rounded text-xs font-mono bg-[#141414] border border-[#262626] text-[#a3a3a3] hover:text-white transition-colors"
              >
                Refresh
              </button>
            </div>

            <div className="bg-[#0a0a0a] border border-[#262626] rounded-lg overflow-hidden">
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-[#262626] bg-black text-[#a3a3a3] text-[11px]">
                    <th className="py-3 px-4">SCAN ID</th>
                    <th className="py-3 px-4">TARGET</th>
                    <th className="py-3 px-4">STATUS</th>
                    <th className="py-3 px-4">BREACHES</th>
                    <th className="py-3 px-4">SCORE</th>
                    <th className="py-3 px-4">STARTED AT</th>
                    <th className="py-3 px-4 text-right">ACTIONS</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#262626]">
                  {scans.map((scan) => (
                    <tr
                      key={scan.id}
                      className="hover:bg-[#141414] transition-colors cursor-pointer"
                      onClick={() => setSelectedScanModalId(scan.id)}
                    >
                      <td className="py-3.5 px-4 font-bold text-white">#{scan.id}</td>
                      <td className="py-3.5 px-4 text-white">
                        {scan.target_name || `Target #${scan.target_id}`}
                      </td>
                      <td className="py-3.5 px-4">
                        <span
                          className={`text-xs ${
                            scan.status === 'COMPLETED'
                              ? 'text-white'
                              : scan.status === 'RUNNING'
                              ? 'text-orange-400 font-semibold'
                              : 'text-[#737373]'
                          }`}
                        >
                          {scan.status}
                        </span>
                      </td>
                      <td className="py-3.5 px-4">
                        {scan.confirmed_count > 0 ? (
                          <span className="text-orange-400 font-bold">
                            {scan.confirmed_count} Breach{scan.confirmed_count > 1 ? 'es' : ''}
                          </span>
                        ) : (
                          <span className="text-[#a3a3a3]">0 Breaches</span>
                        )}
                      </td>
                      <td className="py-3.5 px-4 text-white font-bold">
                        {scan.overall_score ?? '—'}
                      </td>
                      <td className="py-3.5 px-4 text-[11px] text-[#737373]">
                        {scan.started_at ? new Date(scan.started_at).toLocaleString() : '—'}
                      </td>
                      <td className="py-3.5 px-4 text-right" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-center justify-end space-x-2">
                          {scan.status === 'RUNNING' && (
                            <button
                              onClick={(e) => handleStopScan(scan.id, e)}
                              className="px-2.5 py-1 rounded text-xs bg-black hover:bg-[#141414] text-orange-400 border border-orange-500/40 font-semibold transition-colors"
                              title="Stop running scan"
                            >
                              Stop
                            </button>
                          )}
                          <button
                            onClick={() => setSelectedScanModalId(scan.id)}
                            className="px-3 py-1 rounded text-xs bg-orange-500 hover:bg-orange-600 text-black font-semibold transition-colors"
                          >
                            Inspect
                          </button>
                          <a
                            href={`/api/scans/${scan.id}/export/html`}
                            target="_blank"
                            rel="noreferrer"
                            className="px-2.5 py-1 rounded text-xs bg-black hover:bg-[#141414] text-white border border-[#262626] transition-colors"
                          >
                            HTML
                          </a>
                          <a
                            href={`/api/scans/${scan.id}/export/pdf`}
                            target="_blank"
                            rel="noreferrer"
                            className="px-2.5 py-1 rounded text-xs bg-black hover:bg-[#141414] text-[#a3a3a3] hover:text-white border border-[#262626] transition-colors"
                          >
                            PDF
                          </a>
                          <button
                            onClick={(e) => handleDeleteScan(scan.id, e)}
                            className="px-2.5 py-1 rounded text-xs bg-black hover:bg-[#141414] text-[#737373] hover:text-white border border-[#262626] transition-colors"
                            title="Delete scan record"
                          >
                            Delete
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Modals */}
        <ScanInspectorModal
          scanId={selectedScanModalId}
          onClose={() => setSelectedScanModalId(null)}
          onRerunScan={(tgtId) => {
            setSelectedTargetId(tgtId);
            setSelectedScanModalId(null);
            handleStartScan();
          }}
        />

        <TargetInspectorModal
          target={inspectingTarget}
          onClose={() => setInspectingTarget(null)}
          onSelectForScan={(tgtId) => {
            setSelectedTargetId(tgtId);
            setActiveTab('dashboard');
            toast.success(`Target #${tgtId} selected`);
          }}
        />

        <OnboardTargetModal
          isOpen={onboardModalOpen}
          onClose={() => setOnboardModalOpen(false)}
          onTargetCreated={refreshTargets}
        />
      </main>
    </div>
  );
};

export default DashboardPage;
