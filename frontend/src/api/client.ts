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
  socCommandCenter: () => request<Record<string, unknown>>('/api/soc/command-center'),
  listIncidents: (params?: { status?: string; severity?: string }) => {
    const q = new URLSearchParams();
    if (params?.status) q.set('status', params.status);
    if (params?.severity) q.set('severity', params.severity);
    const qs = q.toString();
    return request<{ incidents: Record<string, unknown>[] }>(`/api/incidents${qs ? `?${qs}` : ''}`);
  },
  getIncident: (id: string) => request<Record<string, unknown>>(`/api/incidents/${id}`),
  createIncidentFromEvent: (eventId: string) =>
    request(`/api/incidents/from-event/${eventId}`, { method: 'POST' }),
  updateIncident: (id: string, body: Record<string, unknown>) =>
    request(`/api/incidents/${id}`, { method: 'PATCH', body: JSON.stringify(body) }),
  listCases: () => request<{ cases: Record<string, unknown>[] }>('/api/cases'),
  getCase: (id: string) => request<Record<string, unknown>>(`/api/cases/${id}`),
  createCase: (body: Record<string, unknown>) =>
    request('/api/cases', { method: 'POST', body: JSON.stringify(body) }),
  mergeCaseIncidents: (caseId: string, incident_ids: string[]) =>
    request(`/api/cases/${caseId}/merge`, {
      method: 'POST',
      body: JSON.stringify({ incident_ids }),
    }),
  addCaseNote: (caseId: string, note: string) =>
    request(`/api/cases/${caseId}/notes`, { method: 'POST', body: JSON.stringify({ note }) }),
  entityTrust: () => request<{ entities: Record<string, unknown>[] }>('/api/entities/trust'),
  replayForensics: (body: Record<string, unknown>) =>
    request('/api/forensics/replay', { method: 'POST', body: JSON.stringify(body) }),
  verifyAudit: () => request<Record<string, unknown>>('/api/audit/verify'),
  listPlaybooks: () => request<{ playbooks: Record<string, unknown>[] }>('/api/playbooks'),
  executePlaybook: (playbook_id: string, context: Record<string, unknown>) =>
    request('/api/playbooks/execute', {
      method: 'POST',
      body: JSON.stringify({ playbook_id, context }),
    }),
  firewallProviders: () => request<{ providers: Record<string, unknown>[] }>('/api/firewall/providers'),
  blockIpOrchestrated: (ip_address: string, reason: string, provider: string, ttl_seconds: number) =>
    request('/api/firewall/block', {
      method: 'POST',
      body: JSON.stringify({ ip_address, reason, provider, ttl_seconds }),
    }),
  listQuarantine: () => request<{ quarantine: Record<string, unknown>[] }>('/api/quarantine'),
  releaseQuarantine: (id: string) => request(`/api/quarantine/${id}/release`, { method: 'POST' }),
  listPendingApprovals: () => request<{ approvals: Record<string, unknown>[] }>('/api/approvals/pending'),
  approvePendingAction: (approval_id: string, is_second = false) =>
    request('/api/approvals/approve', {
      method: 'POST',
      body: JSON.stringify({ approval_id, is_second }),
    }),
  requestSensitiveApproval: (body: Record<string, unknown>) =>
    request('/api/approvals/request', {
      method: 'POST',
      body: JSON.stringify(body),
    }),
  listSessions: () => request<{ sessions: Record<string, unknown>[] }>('/api/sessions'),
  revokeSession: (sessionId: string) =>
    request(`/api/sessions/${sessionId}/revoke`, { method: 'POST' }),
  realtimeEvents: () => request<{ events: Record<string, unknown>[]; alerts: Record<string, unknown>[] }>(
    '/api/soc/realtime-events'
  ),
};
