const API_BASE = import.meta.env.VITE_API_URL || '';

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    credentials: 'include',
    headers: {
      Accept: 'application/json',
      ...(options.body instanceof FormData ? {} : { 'Content-Type': 'application/json' }),
      ...options.headers,
    },
    ...options,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(typeof err.detail === 'string' ? err.detail : JSON.stringify(err.detail));
  }
  return res.json();
}

export interface SessionInfo {
  username: string;
  role: string;
  permissions: string[];
  demo_mode: boolean;
}

export const api = {
  login: (username: string, password: string) => {
    const form = new FormData();
    form.append('username', username);
    form.append('password', password);
    return request<{ success: boolean; error?: string } & Partial<SessionInfo>>('/api/login', {
      method: 'POST',
      body: form,
    });
  },
  logout: () => request<{ success: boolean }>('/api/logout', { method: 'POST' }),
  sessionInfo: () => request<SessionInfo>('/api/session-info'),
  loginHints: () =>
    request<{
      accounts: { username: string; role_label: string; password_hint: string }[];
      env_file?: string | null;
    }>('/api/login-hints'),
  systemMetrics: () => request<Record<string, unknown>>('/api/system-metrics'),
  securityOverview: () => request<Record<string, unknown>>('/api/security-overview'),
  analyticsOverview: () => request<Record<string, unknown>>('/api/analytics-overview'),
  threatOverview: () => request<Record<string, unknown>>('/api/threat-overview'),
  blockedIps: () => request<{ blocked_ips: Record<string, unknown>[] }>('/api/blocked-ips'),
  securityReport: () => request<Record<string, unknown>>('/api/security-report'),
  blockIp: (ip_address: string, reason = 'manual_block') =>
    request('/api/block-ip', {
      method: 'POST',
      body: JSON.stringify({ ip_address, reason }),
    }),
  unblockIp: (ip_address: string) =>
    request('/api/unblock-ip', {
      method: 'POST',
      body: JSON.stringify({ ip_address }),
    }),
  analyzeEntity: (entity_id: string, entity_data: Record<string, unknown>) =>
    request('/api/analyze-entity', {
      method: 'POST',
      body: JSON.stringify({ entity_id, entity_data }),
    }),
};
