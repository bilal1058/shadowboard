const BASE_URL = (import.meta as any).env?.VITE_API_URL || '/api';

export class ApiClient {
  private baseUrl: string;
  private hasActiveSession: boolean = false;
  private inMemoryKey: string | null = null;

  constructor(baseUrl: string = BASE_URL) {
    this.baseUrl = baseUrl;
    // Security Hardening: Never store master administrator API key in localStorage.
    // Clean up any legacy persisted keys from older versions.
    if (typeof window !== 'undefined') {
      try {
        localStorage.removeItem('sb_admin_key');
      } catch (_) {}
    }
  }

  isSessionActive(): boolean {
    return this.hasActiveSession;
  }

  getApiKey(): string | null {
    // Only return in-memory transient key if present, never from persistent browser storage
    return this.inMemoryKey;
  }

  setApiKey(key: string) {
    this.inMemoryKey = key;
  }

  clearApiKey() {
    this.inMemoryKey = null;
    this.hasActiveSession = false;
  }

  private async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...((options.headers as Record<string, string>) || {}),
    };

    if (this.inMemoryKey) {
      headers['Authorization'] = `Bearer ${this.inMemoryKey}`;
    }

    const response = await fetch(`${this.baseUrl}${endpoint}`, {
      ...options,
      headers,
      credentials: 'same-origin',
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ error: 'Request failed' }));
      throw new Error(error.detail || error.error || `HTTP ${response.status}`);
    }

    return response.json();
  }

  get<T>(endpoint: string): Promise<T> {
    return this.request<T>(endpoint, { method: 'GET' });
  }

  post<T>(endpoint: string, body: unknown): Promise<T> {
    return this.request<T>(endpoint, {
      method: 'POST',
      body: JSON.stringify(body),
    });
  }

  put<T>(endpoint: string, body: unknown): Promise<T> {
    return this.request<T>(endpoint, {
      method: 'PUT',
      body: JSON.stringify(body),
    });
  }

  async checkSession(): Promise<boolean> {
    try {
      const res = await fetch(`${this.baseUrl}/auth/session`, {
        method: 'GET',
        credentials: 'same-origin',
      });
      if (res.ok) {
        const data = await res.json();
        this.hasActiveSession = Boolean(data.authenticated);
        return this.hasActiveSession;
      }
    } catch (_) {}
    return false;
  }

  async establishBrowserSession(key: string): Promise<void> {
    const response = await fetch(`${this.baseUrl}/auth/session`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${key}` },
      credentials: 'same-origin',
    });
    if (!response.ok) throw new Error('Administrative authentication failed.');
    this.hasActiveSession = true;
    // The cookie is now the credential. Do not retain the master key in page memory.
    this.inMemoryKey = null;
  }

  async destroyBrowserSession(): Promise<void> {
    await fetch(`${this.baseUrl}/auth/session`, { method: 'DELETE', credentials: 'same-origin' }).catch(() => {});
    this.clearApiKey();
  }
}

export const api = new ApiClient();
export default ApiClient;
