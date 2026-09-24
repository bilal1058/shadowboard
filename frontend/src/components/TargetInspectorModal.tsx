import React, { useState, useEffect } from 'react';
import { api } from '@/api/client';
import { Target } from '@/types/api';
import toast from 'react-hot-toast';

interface TargetInspectorModalProps {
  target: Target | null;
  onClose: () => void;
  onSelectForScan?: (targetId: number) => void;
}

export const TargetInspectorModal: React.FC<TargetInspectorModalProps> = ({
  target,
  onClose,
  onSelectForScan,
}) => {
  const [activeTab, setActiveTab] = useState<'overview' | 'test' | 'documents' | 'sandbox'>('overview');
  const [testResult, setTestResult] = useState<any>(null);
  const [isTesting, setIsTesting] = useState(false);
  const [documents, setDocuments] = useState<any[]>([]);
  const [loadingDocs, setLoadingDocs] = useState(false);

  // Interactive Sandbox Chat State
  const [chatMessages, setChatMessages] = useState<Array<{ role: 'user' | 'assistant'; content: string; latency?: number }>>([
    { role: 'assistant', content: 'Hello! I am ready to test. Send a prompt to verify my operational boundaries and responses.' }
  ]);
  const [promptInput, setPromptInput] = useState('');
  const [isSending, setIsSending] = useState(false);

  useEffect(() => {
    if (!target) return;
    setTestResult(null);

    // If target has RAG, pre-load document catalog
    const caps: any = target.capabilities || {};
    if (caps.rag || target.target_type === 'INTERNAL_RAG' || target.base_url.includes('internal-rag')) {
      loadDocuments();
    }
  }, [target]);

  if (!target) return null;

  const caps: any = target.capabilities || {};
  const hasRag = Boolean(caps.rag || target.target_type === 'INTERNAL_RAG' || target.base_url.includes('internal-rag'));
  const hasTools = Boolean(caps.tools || (caps.tool_names && caps.tool_names.length > 0));
  const toolNames: string[] = caps.tool_names || [];

  const handleTestConnection = async () => {
    setIsTesting(true);
    setTestResult(null);
    try {
      const t0 = performance.now();
      const res = await api.post<any>('/targets/test-connection', {
        base_url: target.base_url,
      });
      const t1 = performance.now();
      setTestResult({
        success: true,
        latency: Math.round(t1 - t0),
        data: res,
      });
      toast.success(`Target responded in ${Math.round(t1 - t0)}ms`);
    } catch (err: any) {
      setTestResult({
        success: false,
        error: err.message || 'Connection failed',
      });
      toast.error('Connection check failed');
    } finally {
      setIsTesting(false);
    }
  };

  const loadDocuments = async () => {
    setLoadingDocs(true);
    try {
      const res = await api.get<any>(`/targets/${target.id}/documents`);
      setDocuments(res.documents || []);
    } catch (err) {
      console.error('Failed to load target documents:', err);
    } finally {
      setLoadingDocs(false);
    }
  };

  const handleSendMessage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!promptInput.trim() || isSending) return;

    const userMsg = promptInput.trim();
    setPromptInput('');
    setChatMessages((prev) => [...prev, { role: 'user', content: userMsg }]);
    setIsSending(true);

    try {
      const t0 = performance.now();
      const chatEndpoint = `${target.base_url}/chat`;
      const response = await fetch(chatEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-session-id': `sandbox_${Date.now()}`,
        },
        body: JSON.stringify({
          messages: [{ role: 'user', content: userMsg }],
        }),
      });

      const t1 = performance.now();
      if (!response.ok) {
        throw new Error(`Target responded with HTTP ${response.status}`);
      }

      const data = await response.json();
      const replyText = data.reply || data.response || JSON.stringify(data);

      setChatMessages((prev) => [
        ...prev,
        { role: 'assistant', content: replyText, latency: Math.round(t1 - t0) },
      ]);
    } catch (err: any) {
      setChatMessages((prev) => [
        ...prev,
        { role: 'assistant', content: `[Error: ${err.message || 'Target communication failed'}]` },
      ]);
    } finally {
      setIsSending(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/80 backdrop-blur-md flex items-center justify-center z-50 p-4 sm:p-6 overflow-y-auto animate-fadeIn">
      <div className="bg-[#0f0f15] border border-[#2b2733] rounded-2xl w-full max-w-4xl max-h-[92vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="p-5 bg-[#14141d] border-b border-[#23202b] flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-indigo-600 to-indigo-900 flex items-center justify-center text-xl shadow-lg shadow-indigo-950/50">
              🎯
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h2 className="text-base font-bold text-white tracking-wide">
                  Target #{target.id}: {target.name}
                </h2>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-indigo-950 text-indigo-400 border border-indigo-800/40">
                  {target.target_type || 'AGENT'}
                </span>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-[#1c1a24] text-slate-400 border border-[#2c2838]">
                  {target.model_name || 'qwen-flash'}
                </span>
              </div>
              <p className="text-xs text-slate-400 font-mono mt-0.5 truncate max-w-lg">
                Endpoint: <span className="text-slate-200">{target.base_url}</span>
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-2">
            {onSelectForScan && (
              <button
                onClick={() => {
                  onSelectForScan(target.id);
                  onClose();
                }}
                className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-rose-600 hover:bg-rose-500 text-white transition-colors shadow-md shadow-rose-950/50"
              >
                Select for Assessment
              </button>
            )}
            <a
              href={target.base_url}
              target="_blank"
              rel="noreferrer"
              className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-[#1a1a24] hover:bg-[#252533] border border-[#332f3f] text-slate-300 transition-colors"
            >
              Open Web App ↗
            </a>
            <button
              onClick={onClose}
              className="w-8 h-8 rounded-lg bg-[#1a1a24] hover:bg-[#252533] border border-[#332f3f] text-slate-400 hover:text-white flex items-center justify-center transition-colors text-sm"
            >
              ✕
            </button>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="flex border-b border-[#23202b] bg-[#12121a] px-5">
          <button
            onClick={() => setActiveTab('overview')}
            className={`py-3 px-4 text-xs font-semibold border-b-2 transition-all flex items-center space-x-2 ${
              activeTab === 'overview'
                ? 'border-indigo-500 text-indigo-400 bg-indigo-950/10'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <span>⚙️</span>
            <span>Target Specifications</span>
          </button>

          <button
            onClick={() => setActiveTab('test')}
            className={`py-3 px-4 text-xs font-semibold border-b-2 transition-all flex items-center space-x-2 ${
              activeTab === 'test'
                ? 'border-indigo-500 text-indigo-400 bg-indigo-950/10'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <span>⚡</span>
            <span>Live Health & Connectivity</span>
          </button>

          {hasRag && (
            <button
              onClick={() => setActiveTab('documents')}
              className={`py-3 px-4 text-xs font-semibold border-b-2 transition-all flex items-center space-x-2 ${
                activeTab === 'documents'
                  ? 'border-indigo-500 text-indigo-400 bg-indigo-950/10'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <span>📚</span>
              <span>Knowledge Base Documents ({documents.length})</span>
            </button>
          )}

          <button
            onClick={() => setActiveTab('sandbox')}
            className={`py-3 px-4 text-xs font-semibold border-b-2 transition-all flex items-center space-x-2 ${
              activeTab === 'sandbox'
                ? 'border-indigo-500 text-indigo-400 bg-indigo-950/10'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <span>💬</span>
            <span>Interactive Chat Sandbox</span>
          </button>
        </div>

        {/* Body Content */}
        <div className="p-6 flex-1 overflow-y-auto space-y-6">
          {/* TAB 1: OVERVIEW & CAPABILITIES */}
          {activeTab === 'overview' && (
            <div className="space-y-6">
              {/* Core Specs Grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="p-4 rounded-xl bg-[#13131c] border border-[#23202b] space-y-2">
                  <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block">Target Identity</span>
                  <div className="space-y-1 text-xs">
                    <div className="flex justify-between py-1 border-b border-[#1b1922]">
                      <span className="text-slate-400">Target ID:</span>
                      <span className="font-mono text-white">#{target.id}</span>
                    </div>
                    <div className="flex justify-between py-1 border-b border-[#1b1922]">
                      <span className="text-slate-400">Display Name:</span>
                      <span className="font-semibold text-white">{target.name}</span>
                    </div>
                    <div className="flex justify-between py-1 border-b border-[#1b1922]">
                      <span className="text-slate-400">Classification:</span>
                      <span className="font-mono text-indigo-400">{target.target_type}</span>
                    </div>
                    <div className="flex justify-between py-1">
                      <span className="text-slate-400">Security Mode:</span>
                      <span className="font-mono text-emerald-400">{target.target_mode || 'INSTRUMENTED'}</span>
                    </div>
                  </div>
                </div>

                <div className="p-4 rounded-xl bg-[#13131c] border border-[#23202b] space-y-2">
                  <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block">Model & Network</span>
                  <div className="space-y-1 text-xs">
                    <div className="flex justify-between py-1 border-b border-[#1b1922]">
                      <span className="text-slate-400">Active LLM:</span>
                      <span className="font-mono text-white">{target.model_name || 'qwen-flash'}</span>
                    </div>
                    <div className="flex justify-between py-1 border-b border-[#1b1922]">
                      <span className="text-slate-400">Base URL:</span>
                      <span className="font-mono text-slate-300 truncate max-w-[200px]">{target.base_url}</span>
                    </div>
                    <div className="flex justify-between py-1 border-b border-[#1b1922]">
                      <span className="text-slate-400">Chat Endpoint:</span>
                      <span className="font-mono text-slate-300">{target.base_url}/chat</span>
                    </div>
                    <div className="flex justify-between py-1">
                      <span className="text-slate-400">Health Endpoint:</span>
                      <span className="font-mono text-slate-300">{target.base_url}/health</span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Capabilities Detailed Breakdown */}
              <div className="p-4 rounded-xl bg-[#13131c] border border-[#23202b] space-y-4">
                <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block">
                  Declared Capabilities & Attack Attack Surfaces
                </span>

                <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3">
                  {/* Chat */}
                  <div className="p-3 rounded-lg bg-[#0d0d14] border border-[#1f1b25] space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="text-base">💬</span>
                      <span className="px-1.5 py-0.2 rounded text-[9px] font-mono bg-emerald-950 text-emerald-400 border border-emerald-800">
                        ACTIVE
                      </span>
                    </div>
                    <h4 className="text-xs font-bold text-white">Conversational Chat</h4>
                    <p className="text-[11px] text-slate-400">Accepts interactive multi-turn messages via HTTP POST</p>
                  </div>

                  {/* RAG */}
                  <div className={`p-3 rounded-lg border space-y-1 ${
                    hasRag
                      ? 'bg-indigo-950/20 border-indigo-800/40 text-white'
                      : 'bg-[#0d0d14] border-[#1f1b25] text-slate-400'
                  }`}>
                    <div className="flex items-center justify-between">
                      <span className="text-base">📚</span>
                      <span className={`px-1.5 py-0.2 rounded text-[9px] font-mono border ${
                        hasRag
                          ? 'bg-indigo-950 text-indigo-300 border-indigo-700'
                          : 'bg-slate-900 text-slate-500 border-slate-800'
                      }`}>
                        {hasRag ? 'ENABLED' : 'DISABLED'}
                      </span>
                    </div>
                    <h4 className="text-xs font-bold">Knowledge Base RAG</h4>
                    <p className="text-[11px] text-slate-400">
                      {hasRag ? 'Retrieves internal documents & runbooks' : 'No external retrieval context'}
                    </p>
                  </div>

                  {/* Tools */}
                  <div className={`p-3 rounded-lg border space-y-1 ${
                    hasTools
                      ? 'bg-amber-950/20 border-amber-800/40 text-white'
                      : 'bg-[#0d0d14] border-[#1f1b25] text-slate-400'
                  }`}>
                    <div className="flex items-center justify-between">
                      <span className="text-base">🛠️</span>
                      <span className={`px-1.5 py-0.2 rounded text-[9px] font-mono border ${
                        hasTools
                          ? 'bg-amber-950 text-amber-300 border-amber-700'
                          : 'bg-slate-900 text-slate-500 border-slate-800'
                      }`}>
                        {hasTools ? `${toolNames.length} TOOLS` : 'DISABLED'}
                      </span>
                    </div>
                    <h4 className="text-xs font-bold">Tool Execution</h4>
                    <p className="text-[11px] text-slate-400">
                      {hasTools ? `Tools: ${toolNames.join(', ')}` : 'No function calling capabilities'}
                    </p>
                  </div>

                  {/* Database */}
                  <div className={`p-3 rounded-lg border space-y-1 ${
                    caps.data_access
                      ? 'bg-rose-950/20 border-rose-800/40 text-white'
                      : 'bg-[#0d0d14] border-[#1f1b25] text-slate-400'
                  }`}>
                    <div className="flex items-center justify-between">
                      <span className="text-base">🗄️</span>
                      <span className={`px-1.5 py-0.2 rounded text-[9px] font-mono border ${
                        caps.data_access
                          ? 'bg-rose-950 text-rose-300 border-rose-700'
                          : 'bg-slate-900 text-slate-500 border-slate-800'
                      }`}>
                        {caps.data_access ? 'CONNECTED' : 'NONE'}
                      </span>
                    </div>
                    <h4 className="text-xs font-bold">Tenant Data Access</h4>
                    <p className="text-[11px] text-slate-400">
                      {caps.data_access ? 'Live queries against SQLite tenant records' : 'No direct DB connectivity'}
                    </p>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: LIVE HEALTH & CONNECTIVITY */}
          {activeTab === 'test' && (
            <div className="space-y-4">
              <div className="p-4 rounded-xl bg-[#13131c] border border-[#23202b] flex items-center justify-between">
                <div>
                  <h4 className="text-xs font-bold text-white">Target Endpoint Diagnostics</h4>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Validates target health, contract schema, and response latency with SSRF boundary checks
                  </p>
                </div>
                <button
                  onClick={handleTestConnection}
                  disabled={isTesting}
                  className="px-4 py-2 rounded-lg text-xs font-bold tracking-wide uppercase bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white transition-colors shadow-md shadow-indigo-950/40 flex items-center space-x-2"
                >
                  <span>{isTesting ? '⏳ Testing...' : '⚡ Test Connection Now'}</span>
                </button>
              </div>

              {testResult && (
                <div className={`p-4 rounded-xl border ${
                  testResult.success
                    ? 'bg-emerald-950/20 border-emerald-800/40'
                    : 'bg-rose-950/20 border-rose-800/40'
                }`}>
                  <div className="flex items-center space-x-2 mb-3">
                    <span className="text-base">{testResult.success ? '🟢' : '🔴'}</span>
                    <span className={`font-bold text-xs ${testResult.success ? 'text-emerald-400' : 'text-rose-400'}`}>
                      {testResult.success ? `Target Responding (Latency: ${testResult.latency}ms)` : 'Target Unreachable'}
                    </span>
                  </div>

                  {testResult.success ? (
                    <div className="space-y-3 text-xs">
                      <div>
                        <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block mb-1">
                          Health Check Response (/health)
                        </span>
                        <pre className="p-3 rounded-lg bg-[#070709] border border-[#1f1b22] font-mono text-[11px] text-emerald-400">
                          {JSON.stringify(testResult.data?.health || {}, null, 2)}
                        </pre>
                      </div>

                      {testResult.data?.contract && (
                        <div>
                          <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block mb-1">
                            Contract Schema (/contract)
                          </span>
                          <pre className="p-3 rounded-lg bg-[#070709] border border-[#1f1b22] font-mono text-[11px] text-slate-300 max-h-48 overflow-y-auto">
                            {JSON.stringify(testResult.data.contract, null, 2)}
                          </pre>
                        </div>
                      )}
                    </div>
                  ) : (
                    <p className="text-xs text-rose-300 font-mono">{testResult.error}</p>
                  )}
                </div>
              )}
            </div>
          )}

          {/* TAB 3: RAG DOCUMENTS */}
          {activeTab === 'documents' && hasRag && (
            <div className="space-y-4">
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span>Vector Store Knowledge Base Catalog</span>
                <span className="font-mono">{documents.length} documents indexed</span>
              </div>

              {loadingDocs ? (
                <div className="py-8 text-center text-slate-500 font-mono text-xs">
                  Loading document catalog...
                </div>
              ) : documents.length === 0 ? (
                <div className="p-8 text-center text-slate-500 font-mono text-xs border border-dashed border-[#23202b] rounded-xl">
                  No documents found in knowledge base store.
                </div>
              ) : (
                <div className="space-y-2">
                  {documents.map((doc, dIdx) => (
                    <div
                      key={dIdx}
                      className="p-3 rounded-xl bg-[#13131c] border border-[#23202b] flex items-center justify-between text-xs"
                    >
                      <div className="space-y-0.5">
                        <div className="flex items-center space-x-2">
                          <span className="font-semibold text-white">{doc.title || doc.name || `Document #${dIdx + 1}`}</span>
                          {doc.classification && (
                            <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-rose-950/60 text-rose-400 border border-rose-800/40">
                              {doc.classification}
                            </span>
                          )}
                        </div>
                        <p className="text-[11px] text-slate-400 font-mono">{doc.id || doc.doc_id || doc.filename}</p>
                      </div>

                      <div className="text-right font-mono text-[11px] text-slate-500">
                        {doc.tenant_id ? `Tenant: ${doc.tenant_id}` : 'Global Context'}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* TAB 4: INTERACTIVE CHAT SANDBOX */}
          {activeTab === 'sandbox' && (
            <div className="space-y-4 flex flex-col h-[480px]">
              <div className="flex-1 bg-[#070709] border border-[#23202b] rounded-xl p-4 overflow-y-auto space-y-3 font-mono text-xs">
                {chatMessages.map((msg, idx) => (
                  <div
                    key={idx}
                    className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
                  >
                    <div
                      className={`max-w-[80%] rounded-xl p-3 leading-relaxed whitespace-pre-wrap ${
                        msg.role === 'user'
                          ? 'bg-indigo-600 text-white shadow-md shadow-indigo-950/40 font-sans'
                          : 'bg-[#14141d] border border-[#262331] text-slate-200'
                      }`}
                    >
                      <div className="text-[10px] font-mono opacity-70 mb-1 flex items-center justify-between space-x-2">
                        <span>{msg.role === 'user' ? 'USER' : target.name}</span>
                        {msg.latency && <span>{msg.latency}ms</span>}
                      </div>
                      <div>{msg.content}</div>
                    </div>
                  </div>
                ))}
                {isSending && (
                  <div className="flex justify-start">
                    <div className="bg-[#14141d] border border-[#262331] text-slate-400 rounded-xl p-3 text-xs italic">
                      {target.name} is thinking...
                    </div>
                  </div>
                )}
              </div>

              <form onSubmit={handleSendMessage} className="flex gap-2">
                <input
                  type="text"
                  value={promptInput}
                  onChange={(e) => setPromptInput(e.target.value)}
                  placeholder={`Send a probe message to ${target.name}...`}
                  className="flex-1 bg-[#0d0d14] border border-[#2b2733] rounded-xl px-4 py-2.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500"
                />
                <button
                  type="submit"
                  disabled={!promptInput.trim() || isSending}
                  className="px-5 py-2.5 rounded-xl text-xs font-bold uppercase tracking-wider bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white transition-colors"
                >
                  Send
                </button>
              </form>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-4 bg-[#14141d] border-t border-[#23202b] flex items-center justify-between">
          <div className="text-xs font-mono text-slate-500">
            Target ID: #{target.id} • Mode: {target.target_mode || 'INSTRUMENTED'}
          </div>
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg text-xs font-semibold bg-[#211e29] hover:bg-[#2b2737] text-white transition-colors"
          >
            Close Details
          </button>
        </div>
      </div>
    </div>
  );
};

export default TargetInspectorModal;
