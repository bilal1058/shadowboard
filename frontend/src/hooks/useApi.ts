import { useState, useEffect } from 'react';
import { api } from '@/api/client';
import { Target, ScanRun } from '@/types/api';

export function useTargets() {
  const [targets, setTargets] = useState<Target[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadTargets();
  }, []);

  const loadTargets = async () => {
    try {
      setLoading(true);
      const data = await api.get<{ id: number; name: string; base_url: string; target_type: string; capabilities: Record<string, unknown> }[]>('/targets');
      setTargets(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load targets');
    } finally {
      setLoading(false);
    }
  };

  const createTarget = async (target: Omit<Target, 'id'>) => {
    const result = await api.post<{ id: number }>('/targets', target);
    await loadTargets();
    return result;
  };

  const testConnection = async (baseUrl: string) => {
    return api.post<{ connected: boolean }>('/targets/test-connection', { base_url: baseUrl });
  };

  return { targets, loading, error, createTarget, testConnection, refresh: loadTargets };
}

export function useScans() {
  const [scans, setScans] = useState<ScanRun[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadScans();
  }, []);

  const loadScans = async () => {
    try {
      const data = await api.get<ScanRun[]>('/scans');
      setScans(data);
    } catch (err) {
      console.error('Failed to load scans:', err);
    } finally {
      setLoading(false);
    }
  };

  return { scans, loading, refresh: loadScans };
}

export function useScan(scanId: number) {
  const [scan, setScan] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadScan();
  }, [scanId]);

  const loadScan = async () => {
    try {
      const data = await api.get(`/scans/${scanId}`);
      setScan(data);
    } catch (err) {
      console.error('Failed to load scan:', err);
    } finally {
      setLoading(false);
    }
  };

  return { scan, loading, refresh: loadScan };
}

export function useScanStream(scanId: number) {
  const [events, setEvents] = useState<any[]>([]);
  const [isStreaming, setIsStreaming] = useState(false);

  useEffect(() => {
    if (!scanId) return;
    const token = localStorage.getItem('sb_api_key') || 'shadowboard_admin_secret_2026';
    const eventSource = new EventSource(`/api/scans/${scanId}/stream?api_key=${encodeURIComponent(token)}`);

    eventSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        setEvents(prev => [...prev, data]);
        if (data.type === 'scan_complete' || data.type === 'error') {
          eventSource.close();
          setIsStreaming(false);
        }
      } catch (err) {
        console.error('SSE parse error:', err);
      }
    };

    eventSource.onerror = () => {
      eventSource.close();
      setIsStreaming(false);
    };

    return () => eventSource.close();
  }, [scanId]);

  return { events, isStreaming };
}

export function useTriggerScan(targetId: number, mitigationEnabled: boolean = false) {
  const [isScanning, setIsScanning] = useState(false);
  const [scanId, setScanId] = useState<number | null>(null);

  const trigger = async () => {
    setIsScanning(true);
    try {
      const result = await api.post<{ scan_id: number }>('/scans', {
        target_id: targetId,
        scan_mode: 'INSTRUMENTED',
        mitigation_enabled: mitigationEnabled,
      });
      setScanId(result.scan_id);
      return result;
    } catch (err) {
      console.error('Scan failed:', err);
      throw err;
    } finally {
      setIsScanning(false);
    }
  };

  return { trigger, isScanning, scanId };
}
