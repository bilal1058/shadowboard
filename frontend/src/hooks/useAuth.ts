import { ApiClient } from '@/api/client';

const API_URL = (import.meta as any).env?.VITE_API_URL || 'http://localhost:8000/api';

export class AuthService {
  private client: ApiClient;

  constructor() {
    this.client = new ApiClient(API_URL);
  }

  authenticate(apiKey: string): void {
    this.client.setApiKey(apiKey);
  }

  logout(): void {
    this.client.clearApiKey();
  }

  isAuthenticated(): boolean {
    return typeof window !== 'undefined' ? !!localStorage.getItem('sb_api_key') : false;
  }
}

export const auth = new AuthService();
