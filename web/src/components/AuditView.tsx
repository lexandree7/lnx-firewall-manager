import React, { useState, useEffect } from 'react';
import { AuditLog } from '../types';
import { Shield, FileText, CheckCircle, XCircle, AlertTriangle, Download } from 'lucide-react';
import { api } from '../api/client';

interface AuditViewProps {
  lang: 'pt' | 'en';
}

export const AuditView: React.FC<AuditViewProps> = ({ lang }) => {
  const [logs, setLogs] = useState<AuditLog[]>([
    {
      id: 'aud_1',
      timestamp: new Date().toISOString(),
      actor_username: 'root',
      ip_address: '127.0.0.1',
      action: 'RULES_BATCH_APPLY_INITIATED',
      target_servers: ['srv_prod_01', 'srv_prod_02'],
      result: 'SUCCESS',
      details: 'Regra de bloqueio de scanners aplicada com timer de 30s',
    },
    {
      id: 'aud_2',
      timestamp: new Date(Date.now() - 1200000).toISOString(),
      actor_username: 'AgentAutoRollback',
      ip_address: 'local',
      action: 'ROLLBACK_AUTO',
      target_servers: ['srv_edge_03'],
      result: 'REVERTED',
      details: 'Rollback executado: tempo de confirmação expirou sem commit do operador',
    },
  ]);

  useEffect(() => {
    api.getAuditLogs().then((res) => {
      if (res && res.length > 0) {
        setLogs(res);
      }
    }).catch(() => {});
  }, []);

  const handleExport = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(logs, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `lfm_audit_logs_${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-xl font-bold text-zinc-100 flex items-center gap-2">
            <FileText className="w-5 h-5 text-amber-400" />
            <span>{lang === 'pt' ? 'Trilha de Auditoria Imutável' : 'Immutable Audit Logs'}</span>
          </h1>
          <p className="text-xs text-zinc-400 mt-0.5">
            {lang === 'pt'
              ? 'Registro append-only de todas as alterações de regras, autenticações e reversões de segurança'
              : 'Append-only logs of all firewall modifications, logins, and automated rollback triggers'}
          </p>
        </div>

        <button
          onClick={handleExport}
          className="bg-zinc-900 hover:bg-zinc-800 text-zinc-200 font-medium px-3.5 py-2 rounded-lg text-sm flex items-center gap-2 border border-zinc-800 transition"
        >
          <Download className="w-4 h-4 text-amber-400" />
          <span>{lang === 'pt' ? 'Exportar JSON' : 'Export JSON'}</span>
        </button>
      </div>

      <div className="bg-zinc-950 border border-zinc-800 rounded-xl overflow-hidden shadow-xl">
        <table className="w-full text-left text-sm text-zinc-300">
          <thead className="bg-zinc-900/80 text-xs text-zinc-400 uppercase font-mono border-b border-zinc-800">
            <tr>
              <th className="px-4 py-3">{lang === 'pt' ? 'Data / Hora' : 'Timestamp'}</th>
              <th className="px-4 py-3">{lang === 'pt' ? 'Operador' : 'Actor'}</th>
              <th className="px-4 py-3">{lang === 'pt' ? 'IP Origem' : 'Source IP'}</th>
              <th className="px-4 py-3">{lang === 'pt' ? 'Ação' : 'Action'}</th>
              <th className="px-4 py-3">{lang === 'pt' ? 'Alvo(s)' : 'Targets'}</th>
              <th className="px-4 py-3">{lang === 'pt' ? 'Resultado' : 'Result'}</th>
              <th className="px-4 py-3">{lang === 'pt' ? 'Detalhes' : 'Details'}</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-800/60 font-mono text-xs">
            {logs.map((log) => (
              <tr key={log.id} className="hover:bg-zinc-900/40 transition">
                <td className="px-4 py-3.5 text-zinc-400">{new Date(log.timestamp).toLocaleString()}</td>
                <td className="px-4 py-3.5 font-bold text-zinc-200">{log.actor_username}</td>
                <td className="px-4 py-3.5 text-zinc-400">{log.ip_address}</td>
                <td className="px-4 py-3.5 text-amber-400">{log.action}</td>
                <td className="px-4 py-3.5 text-zinc-300">
                  {Array.isArray(log.target_servers) ? log.target_servers.join(', ') : log.target_servers}
                </td>
                <td className="px-4 py-3.5">
                  <span
                    className={`px-2 py-0.5 rounded text-[11px] font-bold ${
                      log.result === 'SUCCESS'
                        ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                        : log.result === 'REVERTED'
                        ? 'bg-orange-500/20 text-orange-300 border border-orange-500/30'
                        : 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                    }`}
                  >
                    {log.result}
                  </span>
                </td>
                <td className="px-4 py-3.5 font-sans text-zinc-400 text-xs">{log.details || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
