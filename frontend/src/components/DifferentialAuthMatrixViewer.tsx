import React, { useState, useEffect } from 'react';
import { api } from '@/api/client';
import { DifferentialAuthResponse } from '@/types/api';
import toast from 'react-hot-toast';

export const DifferentialAuthMatrixViewer: React.FC = () => {
  const [data, setData] = useState<DifferentialAuthResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [userA, setUserA] = useState<string>('tenant_alpha');
  const [userB, setUserB] = useState<string>('tenant_beta');

  const runMatrix = async () => {
    setLoading(true);
    try {
      const res = await api.post<DifferentialAuthResponse>('/differential-auth/run', {
        user_a_id: userA.trim() || 'tenant_alpha',
        user_b_id: userB.trim() || 'tenant_beta',
        enforce_mitigation: true,
      });
      setData(res);
    } catch (err: any) {
      toast.error(err.message || 'Failed to execute differential authorization matrix');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    runMatrix();
  }, []);

  return (
    <div className="space-y-4">
      {/* Top Header & Run Control */}
      <div className="bg-[#0a0a0a] border border-[#262626] rounded-lg p-4 flex flex-wrap items-center justify-between gap-4">
        <div>
          <h3 className="text-sm font-bold text-white uppercase tracking-wider">
            Differential Authorization Matrix
          </h3>
          <p className="text-xs text-[#a3a3a3] mt-0.5">
            Evaluates cross-tenant boundaries across Identity, Role, Resource, and Action.
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <div className="flex items-center space-x-2 text-xs font-mono">
            <span className="text-[#a3a3a3]">Caller A:</span>
            <input
              type="text"
              value={userA}
              onChange={(e) => setUserA(e.target.value)}
              className="w-28 bg-[#121212] border border-[#333333] rounded px-2.5 py-1 text-white text-xs focus:border-[#f97316] outline-none"
            />
          </div>
          <div className="flex items-center space-x-2 text-xs font-mono">
            <span className="text-[#a3a3a3]">Caller B:</span>
            <input
              type="text"
              value={userB}
              onChange={(e) => setUserB(e.target.value)}
              className="w-28 bg-[#121212] border border-[#333333] rounded px-2.5 py-1 text-white text-xs focus:border-[#f97316] outline-none"
            />
          </div>

          <button
            onClick={runMatrix}
            disabled={loading}
            className="px-4 py-1.5 rounded text-xs font-mono font-bold bg-[#f97316] hover:bg-[#ea580c] disabled:opacity-50 text-black transition-colors"
          >
            {loading ? 'Evaluating...' : 'Run Matrix'}
          </button>
        </div>
      </div>

      {/* Metrics Bar */}
      {data && (
        <div className="grid grid-cols-3 gap-3 font-mono text-center">
          <div className="p-3 bg-[#0a0a0a] border border-[#262626] rounded-lg">
            <span className="text-[11px] text-[#737373] uppercase tracking-wider block">Total Cases</span>
            <span className="text-lg font-bold text-white mt-0.5 block">{data.total_cases}</span>
          </div>
          <div className="p-3 bg-[#0a0a0a] border border-[#262626] rounded-lg">
            <span className="text-[11px] text-[#737373] uppercase tracking-wider block">Passed</span>
            <span className="text-lg font-bold text-white mt-0.5 block">{data.passed_cases}</span>
          </div>
          <div className="p-3 bg-[#0a0a0a] border border-[#262626] rounded-lg">
            <span className="text-[11px] text-[#737373] uppercase tracking-wider block">Violations</span>
            <span className={`text-lg font-bold mt-0.5 block ${data.violations_detected > 0 ? 'text-[#f97316]' : 'text-white'}`}>
              {data.violations_detected}
            </span>
          </div>
        </div>
      )}

      {/* Results Table */}
      {loading ? (
        <div className="py-12 text-center text-xs font-mono text-[#a3a3a3]">
          Evaluating authorization boundaries across identities...
        </div>
      ) : data?.results ? (
        <div className="bg-[#0a0a0a] border border-[#262626] rounded-lg overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead>
              <tr className="border-b border-[#262626] text-[#737373] text-[11px]">
                <th className="py-2.5 px-3">CASE</th>
                <th className="py-2.5 px-3">DESCRIPTION</th>
                <th className="py-2.5 px-3">CALLER</th>
                <th className="py-2.5 px-3">TARGET OWNER</th>
                <th className="py-2.5 px-3">ACTION</th>
                <th className="py-2.5 px-3">EXPECTED</th>
                <th className="py-2.5 px-3">ACTUAL</th>
                <th className="py-2.5 px-3 text-right">STATUS</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1a1a1a]">
              {data.results.map((res) => (
                <tr key={res.case_id} className="hover:bg-[#121212] transition-colors">
                  <td className="py-2.5 px-3 font-bold text-white">{res.case_id}</td>
                  <td className="py-2.5 px-3 text-[#a3a3a3] font-sans max-w-xs">{res.description}</td>
                  <td className="py-2.5 px-3 text-white">
                    {res.caller} <span className="text-[#737373]">({res.role})</span>
                  </td>
                  <td className="py-2.5 px-3 text-[#a3a3a3]">{res.target_owner}</td>
                  <td className="py-2.5 px-3 text-white">{res.tool_name}</td>
                  <td className="py-2.5 px-3 text-[#737373]">{res.expected_outcome}</td>
                  <td className="py-2.5 px-3 text-white">{res.actual_outcome}</td>
                  <td className="py-2.5 px-3 text-right">
                    {res.passed ? (
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold text-white border border-[#333333] bg-[#121212]">
                        PASS
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold text-[#f97316] border border-[#f97316] bg-black">
                        VIOLATION
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </div>
  );
};

export default DifferentialAuthMatrixViewer;
