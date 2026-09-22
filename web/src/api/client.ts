import { Server, BackupItem, AuditLog, IPSetItem, User, UserSession, OIDCConfig, TOTPSetupData, NetworkInterface } from '../types';

const BASE_URL = '/api/v1';

function getToken(): string | null {
  return localStorage.getItem('lfm_token');
}

function setToken(token: string | null) {
  if (token) {
    localStorage.setItem('lfm_token', token);
  } else {
    localStorage.removeItem('lfm_token');
  }
}

async function request(path: string, options: RequestInit = {}): Promise<Response> {
  const token = getToken();
  const headers: Record<string, string> = {
    ...(options.headers as Record<string, string>),
  };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const res = await fetch(`${BASE_URL}${path}`, {
    ...options,
    headers,
    credentials: 'include',
  });

  return res;
}

export const api = {
  getToken,
  setToken,

  async login(username: string, password: string, totpCode?: string): Promise<{ success: boolean; user?: User; token?: string; error?: string }> {
    try {
      const res = await fetch(`${BASE_URL}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ username, password, totp_code: totpCode }),
      });
      const data = await res.json();
      if (res.ok && data.success) {
        if (data.token) {
          setToken(data.token);
        }
        return { success: true, user: data.user, token: data.token };
      }
      return { success: false, error: data.error || 'Credenciais inválidas' };
    } catch (e: any) {
      return { success: false, error: e.message || 'Erro de conexão com o servidor' };
    }
  },

  async logout() {
    try {
      await request('/auth/logout', { method: 'POST' });
    } finally {
      setToken(null);
    }
  },

  async getMe(): Promise<User> {
    const res = await request('/auth/me');
    if (!res.ok) throw new Error('Sessão expirada ou não autenticado');
    return res.json();
  },

  async changePassword(currentPassword: string, newPassword: string): Promise<{ success: boolean; message: string }> {
    const res = await request('/user/password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Falha ao alterar senha');
    return data;
  },

  async setupTOTP(): Promise<TOTPSetupData> {
    const res = await request('/user/totp/setup');
    if (!res.ok) throw new Error('Falha ao iniciar configuração TOTP');
    return res.json();
  },

  async enableTOTP(secret: string, code: string): Promise<{ success: boolean; message: string }> {
    const res = await request('/user/totp/enable', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ secret, code }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Código 2FA incorreto');
    return data;
  },

  async disableTOTP(password: string): Promise<{ success: boolean; message: string }> {
    const res = await request('/user/totp/disable', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Senha incorreta para desativação');
    return data;
  },

  async listSessions(): Promise<UserSession[]> {
    const res = await request('/user/sessions');
    if (!res.ok) throw new Error('Falha ao listar sessões');
    const data = await res.json();
    return Array.isArray(data) ? data : [];
  },

  async revokeSession(sessionId: string): Promise<void> {
    const res = await request(`/user/sessions/${sessionId}`, { method: 'DELETE' });
    if (!res.ok) throw new Error('Falha ao encerrar sessão');
  },

  async getOIDCStatus(): Promise<{ enabled: boolean; provider_name: string }> {
    try {
      const res = await fetch(`${BASE_URL}/auth/oidc/status`);
      if (res.ok) return res.json();
    } catch {}
    return { enabled: false, provider_name: 'OpenID Connect' };
  },

  async getOIDCSettings(): Promise<OIDCConfig> {
    const res = await request('/settings/oidc');
    if (!res.ok) throw new Error('Falha ao carregar configurações OIDC');
    return res.json();
  },

  async saveOIDCSettings(cfg: Partial<OIDCConfig>): Promise<{ success: boolean; message: string }> {
    const res = await request('/settings/oidc', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(cfg),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Falha ao salvar configurações OIDC');
    return data;
  },

  async testOIDCSettings(issuerUrl: string): Promise<any> {
    const res = await request('/settings/oidc/test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ issuer_url: issuerUrl }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Falha no teste de descoberta OIDC');
    return data;
  },

  async getServers(): Promise<Server[]> {
    const res = await request('/servers');
    if (!res.ok) throw new Error('Falha ao listar servidores');
    const data = await res.json();
    return Array.isArray(data) ? data : [];
  },

  async getServer(id: string): Promise<Server> {
    const res = await request(`/servers/${id}`);
    if (!res.ok) throw new Error('Falha ao buscar servidor');
    return res.json();
  },

  async createEnrollmentToken(initialTags: string[] = []): Promise<{ token: string; raw_token?: string }> {
    const res = await request('/enrollment/tokens', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ initial_tags: initialTags, ttl_hours: 24 }),
    });
    if (!res.ok) throw new Error('Falha ao gerar token de enrollment');
    return res.json();
  },

  async getServerRules(id: string) {
    const res = await request(`/servers/${id}/rules`);
    if (!res.ok) throw new Error('Falha ao buscar regras');
    return res.json();
  },

  async getServerInterfaces(id: string): Promise<NetworkInterface[]> {
    const res = await request(`/servers/${id}/interfaces`);
    if (!res.ok) throw new Error('Falha ao buscar interfaces');
    const data = await res.json();
    return Array.isArray(data) ? data : [];
  },

  async previewBatchRules(targetServers: string[], newRulesV4: string) {
    const res = await request('/rules/batch/preview', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target_servers: targetServers, new_rules_v4: newRulesV4 }),
    });
    if (!res.ok) throw new Error('Falha ao gerar preview de diff');
    return res.json();
  },

  async applyBatchRules(targetServers: string[], rulesV4: string, timeoutSeconds: number = 30) {
    const res = await request('/rules/batch/apply', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        target_servers: targetServers,
        rules_v4: rulesV4,
        timeout_seconds: timeoutSeconds,
      }),
    });
    if (!res.ok) throw new Error('Falha ao aplicar regras');
    return res.json();
  },

  async confirmBatchRules(targetServers: string[], changeID: string) {
    const res = await request('/rules/batch/confirm', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target_servers: targetServers, change_id: changeID }),
    });
    if (!res.ok) throw new Error('Falha ao confirmar regras');
    return res.json();
  },

  async getIPSets(serverId: string): Promise<IPSetItem[]> {
    const res = await request(`/servers/${serverId}/ipsets`);
    if (!res.ok) throw new Error('Falha ao listar ipsets');
    const data = await res.json();
    return Array.isArray(data) ? data : [];
  },

  async createIPSet(serverId: string, data: { name: string; type_name: string; family: string }) {
    const res = await request(`/servers/${serverId}/ipsets`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!res.ok) throw new Error('Falha ao criar ipset');
    return res.ok;
  },

  async getIPSetEntries(serverId: string, setName: string): Promise<string[]> {
    const res = await request(`/servers/${serverId}/ipsets/${setName}/entries`);
    if (!res.ok) throw new Error('Falha ao obter entradas do ipset');
    const data = await res.json();
    return Array.isArray(data) ? data : [];
  },

  async saveIPSetEntries(serverId: string, setName: string, entries: string[]) {
    const res = await request(`/servers/${serverId}/ipsets/${setName}/entries`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ entries }),
    });
    if (!res.ok) throw new Error('Falha ao salvar entradas do ipset');
    return res.json();
  },

  async addIPSetEntries(serverId: string, setName: string, entries: string[]) {
    return this.saveIPSetEntries(serverId, setName, entries);
  },

  async getIPSetUsage(serverId: string, setName: string): Promise<{ in_use: boolean; bound_rules: string[] }> {
    const res = await request(`/servers/${serverId}/ipsets/${setName}/usage`);
    if (!res.ok) throw new Error('Falha ao verificar uso do ipset');
    return res.json();
  },

  async deleteIPSet(serverId: string, setName: string): Promise<{ success: boolean; message: string }> {
    const res = await request(`/servers/${serverId}/ipsets/${setName}`, {
      method: 'DELETE',
    });
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.error || 'Falha ao excluir IPSet');
    }
    return data;
  },

  async getBackups(serverId: string): Promise<BackupItem[]> {
    const res = await request(`/servers/${serverId}/backups`);
    if (!res.ok) throw new Error('Falha ao listar backups');
    const data = await res.json();
    return Array.isArray(data) ? data : [];
  },

  async createBackup(serverId: string) {
    const res = await request(`/servers/${serverId}/backups`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    });
    if (!res.ok) throw new Error('Falha ao criar backup');
    return res.json();
  },

  async restoreBackup(serverId: string, backupId: string) {
    const res = await request(`/servers/${serverId}/backups/${backupId}/restore`, {
      method: 'POST',
    });
    if (!res.ok) throw new Error('Falha ao restaurar backup');
    return res.json();
  },

  async getAuditLogs(): Promise<AuditLog[]> {
    const res = await request('/audit/logs?limit=50');
    if (!res.ok) throw new Error('Falha ao listar auditoria');
    const data = await res.json();
    return Array.isArray(data) ? data : [];
  },
};
