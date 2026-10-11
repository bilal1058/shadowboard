import React, { useState } from 'react';
import { api } from '@/api/client';
import { Target } from '@/types/api';

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
  const [activeTab, setActiveTab] = useState<'sandbox' | 'specs'>('sandbox');
  const [chatMessages, setChatMessages] = useState<Array<{ role: 'user' | 'assistant'; content: string; latency?: number; verdict?: string }>>([
    { role: 'assistant', content: 'Target ready. Send a probe to evaluate responses.' }
  ]);
  const [promptInput, setPromptInput] = useState('');
  const [isSending, setIsSending] = useState(false);

  if (!target) return null;

  const handleSendMessage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!promptInput.trim() || isSending) return;

    const userMsg = promptInput.trim();
    setPromptInput('');
    setChatMessages((prev) => [...prev, { role: 'user', content: userMsg }]);
    setIsSending(true);

    try {
      const t0 = performance.now();
      const res = await api.post<any>('/scans/sandbox/probe', {
        target_id: target.id,
        prompt: userMsg,
        mitigation_enabled: true,
      });
      const t1 = performance.now();
      const replyText = res.response_text || res.reply || res.response || JSON.stringify(res);

      setChatMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          content: replyText,
          latency: res.latency_ms || Math.round(t1 - t0),
          verdict: res.verdict,
        },
      ]);
    } catch (err: any) {
      setChatMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          content: `Target communication error: ${err.message || 'Endpoint unreachable'}`,
          verdict: 'ERROR',
        },
      ]);
    } finally {
      setIsSending(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="bg-[#0a0a0a] border border-[#262626] rounded-lg w-full max-w-3xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="p-4 bg-black border-b border-[#262626] flex items-center justify-between">
          <div>
            <div className="flex items-center space-x-2">
              <h2 className="text-sm font-bold text-white uppercase tracking-wider">
                Target #{target.id}: {target.name}
              </h2>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold text-[#f97316] border border-[#f97316]/50 bg-black">
                {target.target_mode || 'INSTRUMENTED'}
              </span>
            </div>
            <p className="text-xs text-[#737373] font-mono mt-0.5 truncate max-w-md">
              Endpoint: {target.base_url}
            </p>
          </div>

          <div className="flex items-center space-x-2">
            {onSelectForScan && (
              <button
                onClick={() => {
                  onSelectForScan(target.id);
                  onClose();
                }}
                className="px-3 py-1 rounded text-xs font-mono font-bold bg-[#f97316] hover:bg-[#ea580c] text-black transition-colors"
              >
                Select for Scan
              </button>
            )}
            <button
              onClick={onClose}
              className="w-7 h-7 rounded border border-[#262626] text-[#a3a3a3] hover:text-white flex items-center justify-center transition-colors text-xs"
            >
              ✕
            </button>
          </div>
        </div>

        {/* Tab Controls */}
        <div className="flex border-b border-[#262626] bg-[#0c0c0c] px-4">
          <button
            onClick={() => setActiveTab('sandbox')}
            className={`py-2.5 px-3 text-xs font-mono font-bold border-b-2 transition-all ${
              activeTab === 'sandbox'
                ? 'border-[#f97316] text-[#f97316]'
                : 'border-transparent text-[#737373] hover:text-white'
            }`}
          >
            Probe Sandbox
          </button>
          <button
            onClick={() => setActiveTab('specs')}
            className={`py-2.5 px-3 text-xs font-mono font-bold border-b-2 transition-all ${
              activeTab === 'specs'
                ? 'border-[#f97316] text-[#f97316]'
                : 'border-transparent text-[#737373] hover:text-white'
            }`}
          >
            Specifications
          </button>
        </div>

        {/* Body */}
        <div className="p-4 flex-1 overflow-y-auto">
          {activeTab === 'specs' && (
            <div className="space-y-3 font-mono text-xs">
              <div className="bg-[#0f0f0f] border border-[#262626] rounded p-3 space-y-2">
                <div className="flex justify-between py-1 border-b border-[#1f1f1f]">
                  <span className="text-[#737373]">Target ID</span>
                  <span className="text-white">#{target.id}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-[#1f1f1f]">
                  <span className="text-[#737373]">Name</span>
                  <span className="text-white">{target.name}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-[#1f1f1f]">
                  <span className="text-[#737373]">Endpoint</span>
                  <span className="text-white">{target.base_url}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-[#1f1f1f]">
                  <span className="text-[#737373]">Model</span>
                  <span className="text-white">{target.model_name || 'qwen-flash'}</span>
                </div>
                <div className="flex justify-between py-1">
                  <span className="text-[#737373]">Mode</span>
                  <span className="text-[#f97316]">{target.target_mode || 'INSTRUMENTED'}</span>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'sandbox' && (
            <div className="space-y-3 flex flex-col h-[420px]">
              <div className="flex-1 bg-black border border-[#262626] rounded p-3 overflow-y-auto space-y-2.5 font-mono text-xs">
                {chatMessages.map((msg, idx) => (
                  <div
                    key={idx}
                    className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
                  >
                    <div
                      className={`max-w-[85%] rounded p-2.5 leading-relaxed whitespace-pre-wrap ${
                        msg.role === 'user'
                          ? 'bg-[#1a1a1a] text-white border border-[#333333]'
                          : 'bg-[#0f0f0f] border border-[#262626] text-[#e5e5e5]'
                      }`}
                    >
                      <div className="text-[10px] text-[#737373] mb-1 flex items-center justify-between space-x-2">
                        <span>{msg.role === 'user' ? 'PROBE' : target.name}</span>
                        <div className="flex items-center space-x-2">
                          {msg.verdict && (
                            <span className={`px-1.5 py-0.2 rounded text-[9px] font-bold ${
                              msg.verdict === 'ERROR'
                                ? 'text-[#737373] border border-[#333333]'
                                : msg.verdict === 'DEFENDED'
                                ? 'text-white border border-[#333333]'
                                : 'text-[#f97316] border border-[#f97316]'
                            }`}>
                              {msg.verdict}
                            </span>
                          )}
                          {msg.latency && <span>{msg.latency}ms</span>}
                        </div>
                      </div>
                      <div>{msg.content}</div>
                    </div>
                  </div>
                ))}
                {isSending && (
                  <div className="text-xs text-[#737373] italic">
                    Waiting for response...
                  </div>
                )}
              </div>

              <form onSubmit={handleSendMessage} className="flex gap-2">
                <input
                  type="text"
                  value={promptInput}
                  onChange={(e) => setPromptInput(e.target.value)}
                  placeholder="Enter probe message..."
                  className="flex-1 bg-[#121212] border border-[#333333] rounded px-3 py-2 text-xs text-white focus:border-[#f97316] outline-none font-mono"
                />
                <button
                  type="submit"
                  disabled={!promptInput.trim() || isSending}
                  className="px-4 py-2 rounded text-xs font-mono font-bold bg-[#f97316] hover:bg-[#ea580c] disabled:opacity-50 text-black transition-colors"
                >
                  Send
                </button>
              </form>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default TargetInspectorModal;
