const BASE_URL = (import.meta as any).env?.VITE_API_URL || '/api';

export class ApiClient {
  private baseUrl: string;
  private apiKey: string | null = null;

  constructor(baseUrl: string = BASE_URL) {
    this.baseUrl = baseUrl;
    this.apiKey = typeof window !== 'undefined' ? localStorage.getItem('sb_admin_key') : null;
  }

  getApiKey(): string | null {
    return this.apiKey;
  }

  setApiKey(key: string) {
    this.apiKey = key;
    if (typeof window !== 'undefined') {
      localStorage.setItem('sb_admin_key', key);
    }
  }

  clearApiKey() {
    this.apiKey = null;
    if (typeof window !== 'undefined') {
      localStorage.removeItem('sb_admin_key');
    }
  }

  private async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...((options.headers as Record<string, string>) || {}),
    };

    if (this.apiKey) {
      headers['Authorization'] = `Bearer ${this.apiKey}`;
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

  async establishBrowserSession(key: string): Promise<void> {
    const response = await fetch(`${this.baseUrl}/auth/session`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${key}` },
      credentials: 'same-origin',
    });
    if (!response.ok) throw new Error('Administrative authentication failed.');
    this.setApiKey(key);
  }

  async destroyBrowserSession(): Promise<void> {
    await fetch(`${this.baseUrl}/auth/session`, { method: 'DELETE', credentials: 'same-origin' });
    this.clearApiKey();
  }
}

export const api = new ApiClient();
export default ApiClient;
