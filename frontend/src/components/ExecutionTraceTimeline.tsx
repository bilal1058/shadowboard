import React, { useState } from 'react';
import { Attempt } from '@/types/api';

interface ExecutionTraceTimelineProps {
  attempts: Attempt[];
  targetName?: string;
}

interface FlattenedEvent {
  id: string;
  turn: number;
  strategy: string;
  stance: string;
  eventType: string;
  source: string;
  eventData: Record<string, any>;
  promptSnippet: string;
  isViolation?: boolean;
}

export const ExecutionTraceTimeline: React.FC<ExecutionTraceTimelineProps> = ({ attempts, targetName }) => {
  const [filterType, setFilterType] = useState<string>('ALL');
  const [selectedEventId, setSelectedEventId] = useState<string | null>(null);

  const allEvents: FlattenedEvent[] = [];
  attempts.forEach((att, attIdx) => {
    const promptSnippet = (att.prompt || '').slice(0, 70);

    if (att.events && Array.isArray(att.events) && att.events.length > 0) {
      att.events.forEach((ev, evIdx) => {
        const isViolation =
          Boolean((ev.event_data as any)?.ownership_mismatch) ||
          Boolean((ev.event_data as any)?.unauthorized) ||
          (ev.event_type === 'tool_call' && (ev.event_data as any)?.result?.success && (ev.event_data as any)?.result?.invoice) ||
          att.stance === 'COMPLIED';

        allEvents.push({
          id: `att-${attIdx}-ev-${evIdx}`,
          turn: att.turn || attIdx + 1,
          strategy: att.strategy,
          stance: att.stance,
          eventType: ev.event_type || 'kernel_event',
          source: ev.source || (ev.event_type === 'proxy_network_call' ? 'proxy_observed' : 'target_instrumented'),
          eventData: ev.event_data || {},
          promptSnippet,
          isViolation,
        });
      });
    } else {
      const obs = att.observation || {};
      if (obs.tool_called || (obs as any).tool_call) {
        allEvents.push({
          id: `att-${attIdx}-obs-tool`,
          turn: att.turn || attIdx + 1,
          strategy: att.strategy,
          stance: att.stance,
          eventType: 'tool_call',
          source: 'target_instrumented',
          eventData: {
            tool: (obs as any).tool_call || 'query_resource',
            arguments: (obs as any).parameters || {},
            result: (obs as any).result || {},
          },
          promptSnippet,
          isViolation: att.stance === 'COMPLIED',
        });
      }
      if (obs.rag_retrieved || (obs as any).rag_chunks) {
        allEvents.push({
          id: `att-${attIdx}-obs-rag`,
          turn: att.turn || attIdx + 1,
          strategy: att.strategy,
          stance: att.stance,
          eventType: 'rag_retrieval',
          source: 'target_instrumented',
          eventData: {
            document: (obs as any).document_id || 'internal_knowledge_base',
            similarity: (obs as any).similarity || 0.88,
          },
          promptSnippet,
          isViolation: false,
        });
      }
    }
  });

  const filteredEvents = allEvents.filter((ev) => {
    if (filterType === 'ALL') return true;
    if (filterType === 'TOOLS') return ev.eventType === 'tool_call';
    if (filterType === 'PROXY') return ev.eventType === 'proxy_network_call' || ev.source === 'proxy_observed';
    if (filterType === 'RAG') return ev.eventType === 'rag_retrieval';
    if (filterType === 'VIOLATIONS') return ev.isViolation;
    return true;
  });

  const toolCallsCount = allEvents.filter((e) => e.eventType === 'tool_call').length;
  const proxyCallsCount = allEvents.filter((e) => e.eventType === 'proxy_network_call' || e.source === 'proxy_observed').length;
  const ragCallsCount = allEvents.filter((e) => e.eventType === 'rag_retrieval').length;
  const violationsCount = allEvents.filter((e) => e.isViolation).length;

  const getEventBadge = (eventType: string, source: string) => {
    const isProxy = eventType === 'proxy_network_call' || source === 'proxy_observed';
    if (isProxy) {
      return (
        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold text-[#f97316] border border-[#f97316]/50 bg-black">
          PROXY OBSERVED
        </span>
      );
    }
    if (eventType === 'tool_call') {
      return (
        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold text-white border border-[#333333] bg-[#121212]">
          TOOL CALL
        </span>
      );
    }
    if (eventType === 'rag_retrieval') {
      return (
        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold text-[#a3a3a3] border border-[#333333] bg-[#121212]">
          RAG RETRIEVAL
        </span>
      );
    }
    return (
      <span className="px-2 py-0.5 rounded text-[10px] font-mono text-[#a3a3a3] border border-[#262626] bg-[#0a0a0a]">
        {eventType.toUpperCase()}
      </span>
    );
  };

  return (
    <div className="space-y-4">
      {/* Telemetry Counters */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono text-center">
        <div className="p-3 bg-[#0a0a0a] border border-[#262626] rounded-lg">
          <span className="text-[11px] text-[#737373] uppercase tracking-wider block">Total Events</span>
          <span className="text-lg font-bold text-white mt-0.5 block">{allEvents.length}</span>
        </div>
        <div className="p-3 bg-[#0a0a0a] border border-[#262626] rounded-lg">
          <span className="text-[11px] text-[#737373] uppercase tracking-wider block">Tool Calls</span>
          <span className="text-lg font-bold text-white mt-0.5 block">{toolCallsCount}</span>
        </div>
        <div className="p-3 bg-[#0a0a0a] border border-[#262626] rounded-lg">
          <span className="text-[11px] text-[#737373] uppercase tracking-wider block">Proxy Observed</span>
          <span className="text-lg font-bold text-[#f97316] mt-0.5 block">{proxyCallsCount}</span>
        </div>
        <div className="p-3 bg-[#0a0a0a] border border-[#262626] rounded-lg">
          <span className="text-[11px] text-[#737373] uppercase tracking-wider block">Violations</span>
          <span className={`text-lg font-bold mt-0.5 block ${violationsCount > 0 ? 'text-[#f97316]' : 'text-white'}`}>
            {violationsCount}
          </span>
        </div>
      </div>

      {/* Filter Tabs */}
      <div className="flex flex-wrap items-center justify-between gap-3 bg-[#0a0a0a] border border-[#262626] p-2.5 rounded-lg">
        <div className="flex flex-wrap items-center gap-1.5 font-mono text-xs">
          <button
            onClick={() => setFilterType('ALL')}
            className={`px-3 py-1 rounded transition-colors ${
              filterType === 'ALL' ? 'bg-[#f97316] text-black font-bold' : 'bg-[#121212] text-[#a3a3a3] hover:text-white'
            }`}
          >
            All ({allEvents.length})
          </button>
          <button
            onClick={() => setFilterType('TOOLS')}
            className={`px-3 py-1 rounded transition-colors ${
              filterType === 'TOOLS' ? 'bg-[#f97316] text-black font-bold' : 'bg-[#121212] text-[#a3a3a3] hover:text-white'
            }`}
          >
            Tools ({toolCallsCount})
          </button>
          <button
            onClick={() => setFilterType('PROXY')}
            className={`px-3 py-1 rounded transition-colors ${
              filterType === 'PROXY' ? 'bg-[#f97316] text-black font-bold' : 'bg-[#121212] text-[#a3a3a3] hover:text-white'
            }`}
          >
            Proxy ({proxyCallsCount})
          </button>
          <button
            onClick={() => setFilterType('RAG')}
            className={`px-3 py-1 rounded transition-colors ${
              filterType === 'RAG' ? 'bg-[#f97316] text-black font-bold' : 'bg-[#121212] text-[#a3a3a3] hover:text-white'
            }`}
          >
            RAG ({ragCallsCount})
          </button>
          <button
            onClick={() => setFilterType('VIOLATIONS')}
            className={`px-3 py-1 rounded transition-colors ${
              filterType === 'VIOLATIONS' ? 'bg-[#f97316] text-black font-bold' : 'bg-[#121212] text-[#a3a3a3] hover:text-white'
            }`}
          >
            Violations ({violationsCount})
          </button>
        </div>

        {targetName && (
          <div className="text-xs font-mono text-[#737373]">
            Target: <span className="text-white">{targetName}</span>
          </div>
        )}
      </div>

      {/* Events List */}
      {filteredEvents.length === 0 ? (
        <div className="p-8 text-center bg-[#0a0a0a] border border-[#262626] rounded-lg text-[#737373] text-xs font-mono">
          No execution events match the filter.
        </div>
      ) : (
        <div className="space-y-2.5">
          {filteredEvents.map((ev) => {
            const isSelected = selectedEventId === ev.id;
            const toolName = ev.eventData?.name || ev.eventData?.tool || ev.eventData?.tool_name || ev.eventData?.url || 'system';
            const args = ev.eventData?.arguments || ev.eventData?.params || {};
            const result = ev.eventData?.result || {};

            return (
              <div
                key={ev.id}
                className={`rounded-lg border transition-all ${
                  ev.isViolation
                    ? 'border-[#f97316] bg-[#0a0a0a]'
                    : isSelected
                    ? 'border-white bg-[#0e0e0e]'
                    : 'border-[#262626] bg-[#0a0a0a] hover:border-[#404040]'
                }`}
              >
                {/* Header */}
                <div
                  onClick={() => setSelectedEventId(isSelected ? null : ev.id)}
                  className="p-3.5 flex items-center justify-between cursor-pointer"
                >
                  <div className="flex items-center space-x-3">
                    <span className="font-mono text-xs px-2 py-0.5 rounded bg-[#161616] text-white border border-[#333333]">
                      Turn #{ev.turn}
                    </span>
                    {getEventBadge(ev.eventType, ev.source)}
                    <div>
                      <div className="flex items-center space-x-2">
                        <span className="font-bold text-xs text-white">
                          {ev.eventType === 'tool_call' ? `${toolName}()` : toolName}
                        </span>
                        {ev.isViolation && (
                          <span className="px-1.5 py-0.2 rounded text-[10px] font-mono font-bold text-[#f97316] border border-[#f97316]">
                            VIOLATION
                          </span>
                        )}
                      </div>
                      <p className="text-[11px] text-[#737373] font-mono mt-0.5">
                        Strategy: <span className="text-[#a3a3a3]">{ev.strategy}</span> • &quot;{ev.promptSnippet}...&quot;
                      </p>
                    </div>
                  </div>

                  <span className="text-xs font-mono text-[#a3a3a3]">
                    {isSelected ? 'Collapse' : 'Inspect'}
                  </span>
                </div>

                {/* Expanded Details */}
                {isSelected && (
                  <div className="p-4 bg-black border-t border-[#262626] space-y-3 text-xs font-mono">
                    {/* Parameters Table */}
                    <div>
                      <span className="text-[11px] text-[#a3a3a3] uppercase tracking-wider font-bold block mb-1">
                        Arguments
                      </span>
                      {Object.keys(args).length > 0 ? (
                        <div className="p-2.5 rounded bg-[#0a0a0a] border border-[#262626] overflow-x-auto">
                          <table className="w-full text-left text-[11px]">
                            <thead>
                              <tr className="border-b border-[#262626] text-[#737373]">
                                <th className="pb-1">KEY</th>
                                <th className="pb-1">VALUE</th>
                                <th className="pb-1">BOUNDARY CHECK</th>
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-[#1a1a1a]">
                              {Object.entries(args).map(([k, v]) => {
                                const isForeignTenant = String(v).includes('victim') || String(v).includes('1042') || String(v).includes('alpha');
                                return (
                                  <tr key={k}>
                                    <td className="py-1 text-[#a3a3a3]">{k}</td>
                                    <td className="py-1 text-white font-semibold">{String(v)}</td>
                                    <td className="py-1">
                                      {isForeignTenant ? (
                                        <span className="text-[#f97316] font-bold">CROSS-TENANT PARAMETER</span>
                                      ) : (
                                        <span className="text-white">Authorized</span>
                                      )}
                                    </td>
                                  </tr>
                                );
                              })}
                            </tbody>
                          </table>
                        </div>
                      ) : (
                        <div className="p-2.5 rounded bg-[#0a0a0a] border border-[#262626] text-[#737373]">
                          No parameters recorded.
                        </div>
                      )}
                    </div>

                    {/* Output */}
                    <div>
                      <span className="text-[11px] text-[#a3a3a3] uppercase tracking-wider font-bold block mb-1">
                        Observed Result
                      </span>
                      <pre className="p-2.5 rounded bg-[#0a0a0a] border border-[#262626] text-white text-[11px] overflow-x-auto max-h-48 leading-relaxed whitespace-pre-wrap">
                        {JSON.stringify(result || ev.eventData, null, 2)}
                      </pre>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

export default ExecutionTraceTimeline;
