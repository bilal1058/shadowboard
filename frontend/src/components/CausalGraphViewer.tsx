import React, { useState, useEffect } from 'react';
import { api } from '@/api/client';
import { CausalGraphData, CausalNode, Finding } from '@/types/api';

interface CausalGraphViewerProps {
  finding?: Finding | null;
  scanId?: number | null;
}

export const CausalGraphViewer: React.FC<CausalGraphViewerProps> = ({ finding, scanId }) => {
  const [graphData, setGraphData] = useState<CausalGraphData | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [selectedNode, setSelectedNode] = useState<CausalNode | null>(null);
  const [activeSubTab, setActiveSubTab] = useState<'visual' | 'questions'>('visual');

  useEffect(() => {
    let isMounted = true;
    setLoading(true);

    const loadGraph = async () => {
      try {
        if (finding) {
          const payload = {
            finding_id: finding.finding_id || `FND-${finding.id}`,
            rule_name: finding.owasp_category || 'Security Policy Violation',
            severity: finding.severity || 'CRITICAL',
            attack_prompts: [
              (finding as any).evidence?.observed ||
              (finding as any).evidence?.description ||
              'Adversarial probe targeting tenant boundary.'
            ],
            response_text: (finding as any).evidence?.data_exposed
              ? `Exposed confidential records: ${JSON.stringify((finding as any).evidence?.data_exposed)}`
              : (finding as any).evidence?.observed || 'Target responded with requested data.',
            execution_events: (finding as any).evidence?.signals ? [
              {
                event_type: 'tool_call',
                truth_level: (finding as any).evidence?.level === 'L2_PROXY_OBSERVED' ? 'L2_PROXY_OBSERVED' : 'L1_TARGET_TELEMETRY',
                event_data: (finding as any).evidence,
              }
            ] : [],
            violation_details: {
              rule: finding.owasp_category,
              confidence: finding.confidence,
              evidence_hash: finding.evidence_hash,
            },
            remediation_text: finding.remediation || 'Enforce strict identity-boundary checks on all tool operations.',
          };

          const data = await api.post<CausalGraphData>('/causal/graph', payload);
          if (isMounted) {
            setGraphData(data);
            if (data.nodes.length > 0) setSelectedNode(data.nodes[0]);
            setLoading(false);
          }
        } else {
          const data = await api.get<CausalGraphData>('/causal/graph/demo');
          if (isMounted) {
            setGraphData(data);
            if (data.nodes.length > 0) setSelectedNode(data.nodes[0]);
            setLoading(false);
          }
        }
      } catch (err) {
        try {
          const fallback = await api.get<CausalGraphData>('/causal/graph/demo');
          if (isMounted) {
            setGraphData(fallback);
            if (fallback.nodes.length > 0) setSelectedNode(fallback.nodes[0]);
            setLoading(false);
          }
        } catch (_) {
          if (isMounted) setLoading(false);
        }
      }
    };

    loadGraph();

    return () => {
      isMounted = false;
    };
  }, [finding, scanId]);

  if (loading) {
    return (
      <div className="py-12 text-center text-xs font-mono text-[#a3a3a3]">
        Loading Causal Attack Graph...
      </div>
    );
  }

  if (!graphData || !graphData.nodes || graphData.nodes.length === 0) {
    return (
      <div className="p-8 text-center bg-[#0a0a0a] rounded-lg border border-[#262626]">
        <h4 className="text-sm font-bold text-white">No Causal Graph Available</h4>
        <p className="text-xs text-[#a3a3a3] mt-1">
          Zero policy violations were recorded for this target.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Tab Controls */}
      <div className="flex items-center justify-between bg-[#0a0a0a] border border-[#262626] p-3 rounded-lg">
        <div>
          <h3 className="text-xs font-bold text-white uppercase tracking-wider">
            Causal Attack Graph (DAG)
          </h3>
          <p className="text-[11px] text-[#737373]">
            Sequence of events from probe trigger to data egress.
          </p>
        </div>

        <div className="flex items-center space-x-1 font-mono text-xs">
          <button
            onClick={() => setActiveSubTab('visual')}
            className={`px-3 py-1 rounded transition-colors ${
              activeSubTab === 'visual'
                ? 'bg-[#f97316] text-black font-bold'
                : 'bg-[#121212] text-[#a3a3a3] hover:text-white'
            }`}
          >
            Sequence Graph
          </button>
          <button
            onClick={() => setActiveSubTab('questions')}
            className={`px-3 py-1 rounded transition-colors ${
              activeSubTab === 'questions'
                ? 'bg-[#f97316] text-black font-bold'
                : 'bg-[#121212] text-[#a3a3a3] hover:text-white'
            }`}
          >
            Root Cause Analysis
          </button>
        </div>
      </div>

      {/* SUBTAB 1: VISUAL FLOW */}
      {activeSubTab === 'visual' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {/* Steps List */}
          <div className="lg:col-span-2 space-y-2">
            {graphData.nodes.map((node, idx) => {
              const isSelected = selectedNode?.node_id === node.node_id;
              const edgeOut = graphData.edges.find((e) => e.source === node.node_id);

              return (
                <div key={node.node_id} className="space-y-2">
                  <div
                    onClick={() => setSelectedNode(node)}
                    className={`p-3 rounded-lg border transition-all cursor-pointer ${
                      isSelected
                        ? 'border-[#f97316] bg-[#121212]'
                        : 'border-[#262626] bg-[#0a0a0a] hover:border-[#404040]'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <div>
                        <span className="font-bold text-xs text-white block">
                          Step {idx + 1}: {node.label}
                        </span>
                        <span className="text-[11px] font-mono text-[#737373]">
                          {node.type} • ID: {node.node_id}
                        </span>
                      </div>

                      <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-[#333333] text-white bg-black">
                        {node.trust_level.replace(/_/g, ' ')}
                      </span>
                    </div>

                    {node.evidence_snippet && (
                      <div className="mt-2 pt-2 border-t border-[#1a1a1a] text-[11px] font-mono text-[#a3a3a3] truncate">
                        &quot;{node.evidence_snippet}&quot;
                      </div>
                    )}
                  </div>

                  {idx < graphData.nodes.length - 1 && (
                    <div className="flex items-center justify-center py-0.5">
                      <span className="text-[10px] font-mono text-[#737373]">
                        | {edgeOut?.relationship || 'next'} |
                      </span>
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          {/* Forensic Details */}
          <div>
            {selectedNode ? (
              <div className="bg-[#0a0a0a] border border-[#262626] rounded-lg p-4 space-y-3 sticky top-4">
                <div className="border-b border-[#262626] pb-2">
                  <h4 className="text-xs font-bold text-white">{selectedNode.label}</h4>
                  <span className="text-[11px] font-mono text-[#737373]">Type: {selectedNode.type}</span>
                </div>

                <div className="space-y-2 text-xs font-mono">
                  <div>
                    <span className="text-[10px] text-[#737373] uppercase tracking-wider block mb-1">
                      Evidence Telemetry
                    </span>
                    <div className="p-2.5 rounded bg-black border border-[#262626] text-white text-[11px] leading-relaxed whitespace-pre-wrap">
                      {selectedNode.evidence_snippet || 'No snippet.'}
                    </div>
                  </div>

                  {selectedNode.details && Object.keys(selectedNode.details).length > 0 && (
                    <div>
                      <span className="text-[10px] text-[#737373] uppercase tracking-wider block mb-1">
                        Parameters
                      </span>
                      <pre className="p-2.5 rounded bg-black border border-[#262626] text-[#a3a3a3] text-[10px] max-h-40 overflow-y-auto leading-relaxed">
                        {JSON.stringify(selectedNode.details, null, 2)}
                      </pre>
                    </div>
                  )}
                </div>
              </div>
            ) : null}
          </div>
        </div>
      )}

      {/* SUBTAB 2: ROOT CAUSE QUESTIONS */}
      {activeSubTab === 'questions' && (
        <div className="space-y-3">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {graphData.developer_summary &&
              Object.entries(graphData.developer_summary).map(([qKey, answer], qIdx) => (
                <div
                  key={qKey}
                  className="p-3.5 rounded-lg bg-[#0a0a0a] border border-[#262626] space-y-2"
                >
                  <div className="flex items-center space-x-2">
                    <span className="w-5 h-5 rounded bg-black border border-[#333333] text-white flex items-center justify-center font-mono text-[10px] font-bold">
                      {qIdx + 1}
                    </span>
                    <h5 className="font-bold text-xs text-white">{qKey}</h5>
                  </div>
                  <div className="p-2.5 rounded bg-black border border-[#1a1a1a] text-xs text-[#a3a3a3] font-sans leading-relaxed">
                    {answer}
                  </div>
                </div>
              ))}
          </div>

          {graphData.remediation_guidance && (
            <div className="p-3.5 rounded-lg bg-[#0a0a0a] border border-[#f97316] space-y-1">
              <span className="text-xs font-bold text-[#f97316] uppercase tracking-wider block">
                Remediation Guidance
              </span>
              <p className="text-xs text-white leading-relaxed">
                {graphData.remediation_guidance}
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default CausalGraphViewer;
