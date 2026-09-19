import { Server, BackupItem, AuditLog, IPSetItem } from '../types';

const BASE_URL = '/api/v1';

export const api = {
  async getServers(): Promise<Server[]> {
    const res = await fetch(`${BASE_URL}/servers`);
    if (!res.ok) throw new Error('Falha ao listar servidores');
    return res.json();
  },

  async getServer(id: string): Promise<Server> {
    const res = await fetch(`${BASE_URL}/servers/${id}`);
    if (!res.ok) throw new Error('Falha ao buscar servidor');
    return res.json();
  },

  async createEnrollmentToken(initialTags: string[] = []): Promise<{ token: string; raw_token?: string }> {
    const res = await fetch(`${BASE_URL}/enrollment/tokens`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ initial_tags: initialTags, ttl_hours: 24 }),
    });
    if (!res.ok) throw new Error('Falha ao gerar token de enrollment');
    return res.json();
  },

  async previewBatchRules(targetServers: string[], newRulesV4: string) {
    const res = await fetch(`${BASE_URL}/rules/batch/preview`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target_servers: targetServers, new_rules_v4: newRulesV4 }),
    });
    if (!res.ok) throw new Error('Falha ao gerar preview de diff');
    return res.json();
  },

  async applyBatchRules(targetServers: string[], rulesV4: string, timeoutSeconds: number = 30) {
    const res = await fetch(`${BASE_URL}/rules/batch/apply`, {
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
    const res = await fetch(`${BASE_URL}/rules/batch/confirm`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target_servers: targetServers, change_id: changeID }),
    });
    if (!res.ok) throw new Error('Falha ao confirmar regras');
    return res.json();
  },

  async getIPSets(serverId: string): Promise<IPSetItem[]> {
    const res = await fetch(`${BASE_URL}/servers/${serverId}/ipsets`);
    if (!res.ok) throw new Error('Falha ao listar ipsets');
    return res.json();
  },

  async createIPSet(serverId: string, data: { name: string; type_name: string; family: string }) {
    const res = await fetch(`${BASE_URL}/servers/${serverId}/ipsets`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!res.ok) throw new Error('Falha ao criar ipset');
    return res.ok;
  },

  async addIPSetEntries(serverId: string, setName: string, entries: string[]) {
    const res = await fetch(`${BASE_URL}/servers/${serverId}/ipsets/${setName}/entries`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ entries }),
    });
    if (!res.ok) throw new Error('Falha ao adicionar entradas no ipset');
    return res.json();
  },

  async getBackups(serverId: string): Promise<BackupItem[]> {
    const res = await fetch(`${BASE_URL}/servers/${serverId}/backups`);
    if (!res.ok) throw new Error('Falha ao listar backups');
    return res.json();
  },

  async createBackup(serverId: string) {
    const res = await fetch(`${BASE_URL}/servers/${serverId}/backups`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    });
    if (!res.ok) throw new Error('Falha ao criar backup');
    return res.json();
  },

  async restoreBackup(serverId: string, backupId: string) {
    const res = await fetch(`${BASE_URL}/servers/${serverId}/backups/${backupId}/restore`, {
      method: 'POST',
    });
    if (!res.ok) throw new Error('Falha ao restaurar backup');
    return res.json();
  },

  async getAuditLogs(): Promise<AuditLog[]> {
    const res = await fetch(`${BASE_URL}/audit/logs?limit=50`);
    if (!res.ok) throw new Error('Falha ao listar auditoria');
    return res.json();
  },
};
