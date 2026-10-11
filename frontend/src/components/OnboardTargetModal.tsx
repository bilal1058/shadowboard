import React, { useState } from 'react';
import { api } from '@/api/client';
import toast from 'react-hot-toast';

interface OnboardTargetModalProps {
  isOpen: boolean;
  onClose: () => void;
  onTargetCreated: () => void;
}

export const OnboardTargetModal: React.FC<OnboardTargetModalProps> = ({
  isOpen,
  onClose,
  onTargetCreated,
}) => {
  const [targetName, setTargetName] = useState<string>('');
  const [targetUrl, setTargetUrl] = useState<string>('http://127.0.0.1:8000/internal-rag');
  const [authorizedBy, setAuthorizedBy] = useState<string>('lead_security_architect@shadowboard.local');
  const [operatorAuthorized, setOperatorAuthorized] = useState<boolean>(true);
  const [handshakeVerified, setHandshakeVerified] = useState<boolean>(false);
  const [verifyingHandshake, setVerifyingHandshake] = useState<boolean>(false);
  const [submitting, setSubmitting] = useState<boolean>(false);

  if (!isOpen) return null;

  const handleTestHandshake = async () => {
    setVerifyingHandshake(true);
    try {
      const contract = await api.get<any>('/targets/contract');
      if (contract && contract.target_mode === 'INSTRUMENTED') {
        setHandshakeVerified(true);
        toast.success(`Handshake verified (Mode: ${contract.target_mode}, Schema: v${contract.schema_version})`);
      } else {
        toast.error('Handshake failed: Target does not report white-box contract.');
      }
    } catch (err: any) {
      toast.error(err.message || 'Failed to verify handshake');
    } finally {
      setVerifyingHandshake(false);
    }
  };

  const handleConfirmOnboard = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetName.trim() || !targetUrl.trim() || !authorizedBy.trim()) {
      toast.error('Please complete all required fields.');
      return;
    }
    if (!operatorAuthorized) {
      toast.error('Operator authorization is required.');
      return;
    }

    setSubmitting(true);
    try {
      const payload = {
        target_name: targetName.trim(),
        target_url: targetUrl.trim(),
        target_mode: 'INSTRUMENTED',
        operator_authorized: operatorAuthorized,
        authorized_by: authorizedBy.trim(),
        scope_allowed_domains: ['127.0.0.1', 'localhost'],
        max_request_rate_per_sec: 2.0,
        max_test_duration_sec: 300,
        planned_probes: [],
      };

      const res = await api.post<any>('/onboarding/confirm', payload);
      toast.success(`Target "${res.target_name || targetName}" registered`);
      onTargetCreated();
      onClose();
    } catch (err: any) {
      toast.error(err.message || 'Failed to onboard target');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="bg-[#0a0a0a] border border-[#262626] rounded-lg w-full max-w-xl shadow-2xl overflow-hidden flex flex-col">
        {/* Header */}
        <div className="p-4 bg-black border-b border-[#262626] flex items-center justify-between">
          <div>
            <h2 className="text-sm font-bold text-white uppercase tracking-wider">
              Onboard White-Box Target
            </h2>
            <p className="text-xs text-[#737373] mt-0.5">
              Register an AI-agent target with runtime telemetry.
            </p>
          </div>

          <button
            onClick={onClose}
            className="w-7 h-7 rounded border border-[#262626] text-[#a3a3a3] hover:text-white flex items-center justify-center transition-colors text-xs"
          >
            ✕
          </button>
        </div>

        {/* Form */}
        <form onSubmit={handleConfirmOnboard} className="p-5 space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-mono text-[#a3a3a3] mb-1">
                Target Name *
              </label>
              <input
                type="text"
                required
                value={targetName}
                onChange={(e) => setTargetName(e.target.value)}
                placeholder="e.g. Support Assistant"
                className="w-full bg-[#121212] border border-[#333333] rounded px-3 py-2 text-xs text-white focus:border-[#f97316] outline-none"
              />
            </div>

            <div>
              <label className="block text-xs font-mono text-[#a3a3a3] mb-1">
                Operating Mode
              </label>
              <div className="w-full bg-[#121212] border border-[#262626] rounded px-3 py-2 text-xs font-mono text-white flex items-center justify-between">
                <span>INSTRUMENTED</span>
                <span className="text-[10px] text-[#f97316] font-bold">WHITE-BOX</span>
              </div>
            </div>
          </div>

          <div>
            <label className="block text-xs font-mono text-[#a3a3a3] mb-1">
              Base Endpoint URL *
            </label>
            <input
              type="url"
              required
              value={targetUrl}
              onChange={(e) => {
                setTargetUrl(e.target.value);
                setHandshakeVerified(false);
              }}
              placeholder="e.g. http://127.0.0.1:8000/internal-rag"
              className="w-full bg-[#121212] border border-[#333333] rounded px-3 py-2 text-xs text-white focus:border-[#f97316] outline-none font-mono"
            />
          </div>

          {/* Handshake Check */}
          <div className="p-3 rounded bg-[#121212] border border-[#262626] flex items-center justify-between">
            <div>
              <span className="text-xs font-bold text-white block">Pre-Scan Telemetry Handshake</span>
              <span className="text-[11px] text-[#737373]">Verifies target contract</span>
            </div>

            <button
              type="button"
              onClick={handleTestHandshake}
              disabled={verifyingHandshake}
              className={`px-3 py-1 rounded text-xs font-mono font-bold transition-all ${
                handshakeVerified
                  ? 'border border-[#f97316] text-[#f97316] bg-black'
                  : 'bg-[#262626] text-white hover:bg-[#333333]'
              }`}
            >
              {verifyingHandshake ? 'Verifying...' : handshakeVerified ? 'Verified' : 'Verify'}
            </button>
          </div>

          {/* Authorization */}
          <div className="space-y-2">
            <div>
              <label className="block text-xs font-mono text-[#a3a3a3] mb-1">
                Authorized By *
              </label>
              <input
                type="text"
                required
                value={authorizedBy}
                onChange={(e) => setAuthorizedBy(e.target.value)}
                placeholder="operator@company.com"
                className="w-full bg-[#121212] border border-[#333333] rounded px-3 py-2 text-xs text-white focus:border-[#f97316] outline-none font-mono"
              />
            </div>

            <label className="flex items-center space-x-2 cursor-pointer p-2 rounded bg-[#121212] border border-[#262626]">
              <input
                type="checkbox"
                checked={operatorAuthorized}
                onChange={(e) => setOperatorAuthorized(e.target.checked)}
                className="rounded border-[#333333] text-[#f97316] focus:ring-0"
              />
              <span className="text-xs text-[#a3a3a3]">
                I certify that I am authorized to assess this target.
              </span>
            </label>
          </div>

          {/* Actions */}
          <div className="flex justify-end space-x-2 pt-2 border-t border-[#262626]">
            <button
              type="button"
              onClick={onClose}
              className="px-3.5 py-1.5 rounded text-xs text-[#a3a3a3] hover:text-white"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting}
              className="px-4 py-1.5 rounded text-xs font-mono font-bold bg-[#f97316] hover:bg-[#ea580c] disabled:opacity-50 text-black transition-colors"
            >
              {submitting ? 'Registering...' : 'Register Target'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default OnboardTargetModal;
