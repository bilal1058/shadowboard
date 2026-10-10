import React, { useState, useEffect } from 'react';
import { useTargets, useScans, useTriggerScan } from '@/hooks/useApi';
import { api } from '@/api/client';
import { Target } from '@/types/api';
import toast from 'react-hot-toast';
import ScanInspectorModal from '@/components/ScanInspectorModal';
import TargetInspectorModal from '@/components/TargetInspectorModal';

export const DashboardPage: React.FC = () => {
  const { targets, loading: targetsLoading, error: targetsError, refresh: refreshTargets } = useTargets();
  const { scans, loading: scansLoading, refresh: refreshScans } = useScans();

  const [activeTab, setActiveTab] = useState<'dashboard' | 'targets' | 'history'>('dashboard');
  const [selectedTargetId, setSelectedTargetId] = useState<number>(0);
  const [selectedScanModalId, setSelectedScanModalId] = useState<number | null>(null);
  const [inspectingTarget, setInspectingTarget] = useState<Target | null>(null);
  const [apiKey, setApiKey] = useState<string>('');
  const [adminSessionActive, setAdminSessionActive] = useState<boolean>(false);
  const [apiKeyModalOpen, setApiKeyModalOpen] = useState<boolean>(false);

  // Registered reference targets available to the console.
  const visibleTargets = targets;

  const { trigger, isScanning } = useTriggerScan(selectedTargetId);

  // Check saved admin session on mount via HttpOnly cookie
  useEffect(() => {
    api.checkSession().then((active) => {
      if (active) {
        setAdminSessionActive(true);
      }
    });
  }, []);

  // Sync selected target when visible targets list updates
  useEffect(() => {
    if (visibleTargets.length > 0) {
      if (!selectedTargetId || !visibleTargets.some((t) => t.id === selectedTargetId)) {
        setSelectedTargetId(visibleTargets[0].id);
      }
    }
  }, [visibleTargets, selectedTargetId]);

  // Automatically reload targets and scans when admin session becomes active
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
      toast.success('Administrative session established');
      await refreshTargets();
      await refreshScans();
    } catch (error: any) {
      toast.error(error.message || 'Administrative authentication failed');
    }
  };

  const handleStartScan = async () => {
    try {
      toast.loading('Initiating security assessment...', { id: 'scan-trigger' });
      const result = await trigger();
      toast.success(`Scan #${result.scan_id} initiated`, { id: 'scan-trigger' });
      setSelectedScanModalId(result.scan_id);
      setTimeout(refreshScans, 1500);
    } catch (err: any) {
      toast.error(err.message || 'Failed to start scan', { id: 'scan-trigger' });
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
              <span>Targets Substrate ({visibleTargets.length})</span>
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

        <div className="flex items-center space-x-3">
          <button
            onClick={() => setApiKeyModalOpen(true)}
            className="px-3 py-1.5 rounded text-xs bg-[#16161e] hover:bg-[#20202c] border border-[#2b2733] text-slate-300 font-mono transition-colors flex items-center space-x-1.5"
          >
            <span>{adminSessionActive ? '🔑 Session Active' : '⚙️ Authenticate'}</span>
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
            {/* Target Selection & Scan Trigger */}
            <div className="bg-[#111116] border border-[#1f1b22] rounded-xl p-5 space-y-4">
              <div className="flex flex-wrap items-center justify-between border-b border-[#1f1b22] pb-3 gap-3">
                <div>
                  <h2 className="text-sm font-bold text-white tracking-wide uppercase flex items-center space-x-2">
                    <span>🎯</span>
                    <span>Target Substrate &amp; Dispatcher</span>
                  </h2>
                  <p className="text-xs text-slate-400 mt-0.5">Select a registered reference agent to execute automated adversarial probes.</p>
                </div>
                <div className="flex items-center space-x-2">
                  <button
                    onClick={() => setActiveTab('targets')}
                    className="px-3 py-1.5 rounded-lg text-xs text-slate-300 hover:text-white bg-[#181822] border border-[#2b2733] font-mono transition-colors"
                  >
                    View All Targets ↗
                  </button>
                  <button
                    onClick={refreshTargets}
                    className="px-3 py-1.5 rounded-lg text-xs text-slate-400 hover:text-slate-200 bg-[#181822] border border-[#2b2733] font-mono transition-colors"
                  >
                    ⟳ Refresh
                  </button>
                </div>
              </div>

              {targetsLoading ? (
                <div className="text-xs text-slate-500 py-6 text-center">Loading targets from persistence...</div>
              ) : targetsError ? (
                <div className="text-xs text-amber-300 py-4 bg-amber-950/20 border border-amber-900/40 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div className="flex items-center space-x-2">
                    <span>🔐</span>
                    <span>Admin authentication key required to view targets and execute assessments.</span>
                  </div>
                  <button
                    onClick={() => setApiKeyModalOpen(true)}
                    className="px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-rose-600 hover:bg-rose-500 text-white shadow-sm shrink-0"
                  >
                    Authenticate Now
                  </button>
                </div>
              ) : (
                <div className="space-y-4">
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                    {visibleTargets.map((tgt) => {
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
                                  CHATBOT
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
                                  DATA ACCESS
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
                              🔍 Inspect &amp; Sandbox &rarr;
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
                    <div className="flex items-center space-x-2 text-xs text-slate-400 font-mono">
                      <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
                      <span className="text-emerald-400 font-semibold">100% Policy Enforcement &amp; Guardrails Enforced</span>
                      <span className="text-slate-500 hidden sm:inline">• Production Hardened Baseline</span>
                    </div>

                    <button
                      onClick={handleStartScan}
                      disabled={isScanning || visibleTargets.length === 0}
                      className="px-5 py-2 rounded-lg text-xs font-bold tracking-wide uppercase bg-rose-600 hover:bg-rose-500 disabled:opacity-50 text-white shadow-lg shadow-rose-900/40 transition-all flex items-center space-x-2"
                    >
                      <span>{isScanning ? '⏳ Executing...' : '⚡ Launch Security Assessment'}</span>
                    </button>
                  </div>
                </div>
              )}
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
                            setSelectedScanModalId(scan.id);
                          }}
                        >
                          <td className="py-3 px-3 font-mono font-bold text-white">#{scan.id}</td>
                          <td className="py-3 px-3 text-slate-200 font-medium">{scan.target_name || `Target #${scan.target_id}`}</td>
                          <td className="py-3 px-3">
                            <span className="px-1.5 py-0.5 rounded text-[10px] font-mono border bg-emerald-950/60 text-emerald-400 border-emerald-800/40">
                              HARDENED
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
                                  setSelectedScanModalId(scan.id);
                                }}
                                className="px-2.5 py-1 rounded text-[11px] font-mono bg-rose-950/40 hover:bg-rose-900/60 text-rose-300 border border-rose-800/40 transition-colors flex items-center space-x-1"
                              >
                                <span>🔍</span>
                                <span>View Details</span>
                              </button>
                              <a
                                href={`/api/scans/${scan.id}/export/pdf`}
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
              <div className="flex items-center space-x-2">
                <button
                  onClick={refreshTargets}
                  className="px-3 py-1.5 rounded-lg text-xs font-mono bg-[#16161e] border border-[#2b2733] text-slate-300 hover:text-white transition-colors"
                >
                  ⟳ Refresh Targets
                </button>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {visibleTargets.map((tgt) => {
                const caps: any = tgt.capabilities || {};
                const hasRag = Boolean(caps.rag || tgt.target_type === 'INTERNAL_RAG' || tgt.base_url.includes('internal-rag'));

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

                      {/* Security Baseline */}
                      <div className="p-2.5 rounded-lg bg-[#070709] border border-[#1b1922] text-xs font-mono flex items-center justify-between">
                        <span className="text-slate-400">Security Posture:</span>
                        <span className="text-emerald-400 font-semibold">PRODUCTION HARDENED</span>
                      </div>
                    </div>

                    <div className="pt-3 border-t border-[#1f1b22] flex flex-wrap items-center justify-between gap-2">
                      {tgt.base_url.startsWith('http') && !tgt.base_url.includes('127.0.0.1') && !tgt.base_url.includes('localhost') ? (
                        <a
                          href={tgt.base_url.replace(/\/+$/, '') + '/'}
                          target="_blank"
                          rel="noreferrer"
                          className="px-3 py-1.5 rounded-lg text-xs font-mono bg-[#16161e] hover:bg-[#20202c] border border-[#2b2733] text-slate-300 hover:text-white transition-colors"
                        >
                          Open URL ↗
                        </a>
                      ) : (
                        <span className="text-[11px] font-mono text-slate-500">Local Service</span>
                      )}

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
                        setSelectedScanModalId(scan.id);
                      }}
                    >
                      <td className="py-3.5 px-4 font-mono font-bold text-white">#{scan.id}</td>
                      <td className="py-3.5 px-4 text-slate-200 font-medium">{scan.target_name || `Target #${scan.target_id}`}</td>
                      <td className="py-3.5 px-4">
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono border bg-emerald-950/60 text-emerald-400 border-emerald-800/40">
                          HARDENED
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
                              setSelectedScanModalId(scan.id);
                            }}
                            className="px-3 py-1 rounded text-xs font-mono bg-rose-600 hover:bg-rose-500 text-white transition-colors"
                          >
                            Inspect & Audit
                          </button>
                          <a
                            href={`/api/scans/${scan.id}/export/pdf`}
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
          onRerunScan={(tgtId) => {
            setSelectedTargetId(tgtId);
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
