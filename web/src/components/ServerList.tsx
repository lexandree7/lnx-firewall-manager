import React, { useState } from 'react';
import { Server } from '../types';
import { Server as ServerIcon, Plus, Copy, Check, Terminal, Cpu, HardDrive, RefreshCw } from 'lucide-react';
import { api } from '../api/client';

interface ServerListProps {
  servers: Server[];
  onRefresh: () => void;
  lang: 'pt' | 'en';
}

export const ServerList: React.FC<ServerListProps> = ({ servers, onRefresh, lang }) => {
  const [showEnrollModal, setShowEnrollModal] = useState(false);
  const [enrollToken, setEnrollToken] = useState('');
  const [copied, setCopied] = useState(false);
  const [loadingToken, setLoadingToken] = useState(false);

  const handleGenerateToken = async () => {
    setLoadingToken(true);
    try {
      const res = await api.createEnrollmentToken(['production']);
      setEnrollToken(res.raw_token || res.token);
      setShowEnrollModal(true);
    } catch (e) {
      alert('Erro ao gerar token: ' + e);
    } finally {
      setLoadingToken(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const onlineCount = servers.filter((s) => s.status === 'online').length;
  const driftCount = servers.filter((s) => s.drift_detected).length;

  return (
    <div className="space-y-6">
      {/* Header com Estatísticas e Botão de Ação */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <ServerIcon className="w-5 h-5 text-emerald-400" />
            <span>{lang === 'pt' ? 'Servidores Gerenciados' : 'Managed Servers'}</span>
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            {lang === 'pt'
              ? 'Nós com daemons fw-agent ativos monitorando políticas e telemetria'
              : 'Nodes with active fw-agent daemons monitoring firewall policies'}
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={onRefresh}
            className="p-2 text-slate-400 hover:text-white rounded-lg bg-slate-900 border border-slate-800 transition"
            title={lang === 'pt' ? 'Atualizar' : 'Refresh'}
          >
            <RefreshCw className="w-4 h-4" />
          </button>

          <button
            onClick={handleGenerateToken}
            disabled={loadingToken}
            className="bg-emerald-600 hover:bg-emerald-500 text-white font-medium px-3.5 py-2 rounded-lg text-sm flex items-center gap-2 shadow-lg shadow-emerald-900/20 transition disabled:opacity-50"
          >
            <Plus className="w-4 h-4" />
            <span>{lang === 'pt' ? 'Adicionar Servidor' : 'Add Server'}</span>
          </button>
        </div>
      </div>

      {/* Cards de Métricas */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="bg-slate-900/60 border border-slate-800/80 rounded-xl p-4">
          <div className="text-xs font-mono text-slate-400 uppercase">{lang === 'pt' ? 'Total' : 'Total'}</div>
          <div className="text-2xl font-bold text-slate-100 mt-1">{servers.length}</div>
        </div>
        <div className="bg-slate-900/60 border border-slate-800/80 rounded-xl p-4">
          <div className="text-xs font-mono text-emerald-400 uppercase">{lang === 'pt' ? 'Online' : 'Online'}</div>
          <div className="text-2xl font-bold text-emerald-400 mt-1">{onlineCount}</div>
        </div>
        <div className="bg-slate-900/60 border border-slate-800/80 rounded-xl p-4">
          <div className="text-xs font-mono text-rose-400 uppercase">{lang === 'pt' ? 'Offline' : 'Offline'}</div>
          <div className="text-2xl font-bold text-rose-400 mt-1">{servers.length - onlineCount}</div>
        </div>
        <div className="bg-slate-900/60 border border-slate-800/80 rounded-xl p-4">
          <div className="text-xs font-mono text-amber-400 uppercase">
            {lang === 'pt' ? 'Divergência (Drift)' : 'Drift'}
          </div>
          <div className="text-2xl font-bold text-amber-400 mt-1">{driftCount}</div>
        </div>
      </div>

      {/* Tabela de Servidores */}
      <div className="bg-slate-900/40 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm text-slate-300">
            <thead className="bg-slate-900/80 text-xs text-slate-400 uppercase font-mono border-b border-slate-800">
              <tr>
                <th className="px-4 py-3">{lang === 'pt' ? 'Status' : 'Status'}</th>
                <th className="px-4 py-3">{lang === 'pt' ? 'Hostname / ID' : 'Hostname / ID'}</th>
                <th className="px-4 py-3">IP</th>
                <th className="px-4 py-3">Backend iptables</th>
                <th className="px-4 py-3">SO & Kernel</th>
                <th className="px-4 py-3">Tags</th>
                <th className="px-4 py-3">{lang === 'pt' ? 'Última Conexão' : 'Last Seen'}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {servers.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-4 py-12 text-center text-slate-500">
                    <ServerIcon className="w-8 h-8 mx-auto mb-2 opacity-40" />
                    {lang === 'pt'
                      ? 'Nenhum servidor conectado. Clique em "Adicionar Servidor" para provisionar o primeiro host.'
                      : 'No servers connected. Click "Add Server" to enroll your first host.'}
                  </td>
                </tr>
              ) : (
                servers.map((s) => (
                  <tr key={s.id} className="hover:bg-slate-800/30 transition">
                    <td className="px-4 py-3.5">
                      <div className="flex items-center gap-2">
                        <span
                          className={`w-2.5 h-2.5 rounded-full ${
                            s.status === 'online' ? 'bg-emerald-400 shadow-sm shadow-emerald-400' : 'bg-rose-500'
                          }`}
                        />
                        <span className="capitalize font-mono text-xs text-slate-200">{s.status}</span>
                        {s.drift_detected && (
                          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30">
                            DRIFT
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-4 py-3.5">
                      <div className="font-semibold text-slate-100">{s.hostname}</div>
                      <div className="text-xs font-mono text-slate-500 truncate max-w-[140px]">{s.id}</div>
                    </td>
                    <td className="px-4 py-3.5 font-mono text-xs text-slate-300">{s.ip_address}</td>
                    <td className="px-4 py-3.5">
                      <span className="inline-flex items-center gap-1 font-mono text-xs px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300">
                        <HardDrive className="w-3 h-3 text-slate-400" />
                        {s.iptables_backend || 'iptables-nft'}
                      </span>
                    </td>
                    <td className="px-4 py-3.5">
                      <div className="flex items-center gap-1.5 text-xs text-slate-300">
                        <Cpu className="w-3.5 h-3.5 text-slate-400" />
                        <span>{s.os_distro || 'Linux'}</span>
                      </div>
                      <div className="text-[11px] font-mono text-slate-500">{s.kernel_version}</div>
                    </td>
                    <td className="px-4 py-3.5">
                      <div className="flex flex-wrap gap-1">
                        {s.tags?.map((t) => (
                          <span
                            key={t}
                            className="text-[11px] font-mono px-2 py-0.5 rounded-full bg-slate-800 text-slate-300"
                          >
                            {t}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="px-4 py-3.5 font-mono text-xs text-slate-400">
                      {s.last_seen_at ? new Date(s.last_seen_at).toLocaleTimeString() : '—'}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Modal de Adicionar Servidor (Enrollment) */}
      {showEnrollModal && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-lg w-full p-6 shadow-2xl space-y-4">
            <div className="flex justify-between items-center">
              <h3 className="font-bold text-slate-100 flex items-center gap-2">
                <Terminal className="w-5 h-5 text-emerald-400" />
                <span>{lang === 'pt' ? 'Provisionar Novo Agente' : 'Enroll New Agent'}</span>
              </h3>
              <button onClick={() => setShowEnrollModal(false)} className="text-slate-400 hover:text-white">
                ✕
              </button>
            </div>

            <p className="text-sm text-slate-300">
              {lang === 'pt'
                ? 'Execute o comando abaixo como root no servidor gerenciado para associá-lo ao painel com certificado mTLS de uso exclusivo:'
                : 'Run the command below as root on the managed server to enroll it via client mTLS certificate:'}
            </p>

            <div className="bg-slate-950 border border-slate-800 rounded-xl p-3 font-mono text-xs text-emerald-400 flex items-center justify-between gap-2 overflow-x-auto">
              <span>{`fw-agent enroll --server ${window.location.origin} --token ${enrollToken}`}</span>
              <button
                onClick={() =>
                  copyToClipboard(`fw-agent enroll --server ${window.location.origin} --token ${enrollToken}`)
                }
                className="p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded transition shrink-0"
              >
                {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
              </button>
            </div>

            <div className="text-xs text-slate-400 space-y-1">
              <div>• Token de uso único, com expiração automática em 24 horas.</div>
              <div>• A conexão subsequente utilizará mTLS estrito com autoridade certificadora interna.</div>
            </div>

            <div className="pt-2 flex justify-end">
              <button
                onClick={() => setShowEnrollModal(false)}
                className="bg-slate-800 hover:bg-slate-700 text-slate-200 px-4 py-2 rounded-lg text-sm transition"
              >
                {lang === 'pt' ? 'Fechar' : 'Close'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
