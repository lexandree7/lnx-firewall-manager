import React from 'react';
import { Shield, Server as ServerIcon, Globe, AlertTriangle, CheckCircle2 } from 'lucide-react';
import { Server } from '../types';

interface NavbarProps {
  servers: Server[];
  selectedServerId: string;
  onSelectServer: (id: string) => void;
  lang: 'pt' | 'en';
  onToggleLang: () => void;
  activeTab: string;
  onSelectTab: (tab: string) => void;
  pendingRollback: { changeId: string; secondsRemaining: number } | null;
  onConfirmRollback: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  servers,
  selectedServerId,
  onSelectServer,
  lang,
  onToggleLang,
  activeTab,
  onSelectTab,
  pendingRollback,
  onConfirmRollback,
}) => {
  const onlineCount = servers.filter((s) => s.status === 'online').length;

  return (
    <header className="border-b border-slate-800 bg-slate-900/90 backdrop-blur sticky top-0 z-40">
      {/* Banner de Proteção Contra Lockout se houver confirmação pendente */}
      {pendingRollback && (
        <div className="bg-amber-500/20 border-b border-amber-500/40 px-4 py-2 flex items-center justify-between text-amber-200 text-sm animate-pulse">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-amber-400" />
            <span>
              <strong>{lang === 'pt' ? 'Proteção Contra Lockout Ativa:' : 'Active Lockout Protection:'}</strong>{' '}
              {lang === 'pt'
                ? `Regras em teste! Reversão automática em ${pendingRollback.secondsRemaining}s se não confirmado.`
                : `Rules under test! Auto-reverting in ${pendingRollback.secondsRemaining}s if not confirmed.`}
            </span>
          </div>
          <button
            onClick={onConfirmRollback}
            className="bg-amber-500 hover:bg-amber-600 text-slate-950 font-bold px-3 py-1 rounded text-xs transition"
          >
            {lang === 'pt' ? 'Confirmar Permanência Agora' : 'Confirm Changes Now'}
          </button>
        </div>
      )}

      <div className="max-w-7xl mx-auto px-4 h-16 flex items-center justify-between">
        {/* Logo & Marca */}
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 shadow-lg shadow-emerald-500/10">
            <Shield className="w-6 h-6" />
          </div>
          <div>
            <div className="font-bold text-slate-100 tracking-tight flex items-center gap-2">
              <span>Linux Firewall Manager</span>
              <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                v1.0
              </span>
            </div>
            <div className="text-xs text-slate-400 font-mono">iptables & ipset control plane</div>
          </div>
        </div>

        {/* Seletor Global de Servidor */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5">
            <ServerIcon className="w-4 h-4 text-slate-400" />
            <select
              value={selectedServerId}
              onChange={(e) => onSelectServer(e.target.value)}
              className="bg-transparent text-sm text-slate-200 outline-none cursor-pointer font-mono"
            >
              <option value="ALL">
                {lang === 'pt' ? '⚡ Todos os Servidores (Lote)' : '⚡ All Servers (Batch)'} ({servers.length})
              </option>
              {servers.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.status === 'online' ? '🟢' : '🔴'} {s.hostname} ({s.ip_address})
                </option>
              ))}
            </select>
          </div>

          <div className="hidden sm:flex items-center gap-1.5 text-xs font-mono px-2.5 py-1 rounded bg-slate-800/60 border border-slate-700/60 text-slate-300">
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
            <span>
              {onlineCount}/{servers.length} online
            </span>
          </div>
        </div>

        {/* Ações e Idioma */}
        <div className="flex items-center gap-3">
          <button
            onClick={onToggleLang}
            className="flex items-center gap-1.5 text-xs font-medium text-slate-300 hover:text-white px-2.5 py-1.5 rounded-lg border border-slate-800 hover:border-slate-700 bg-slate-950 transition"
          >
            <Globe className="w-3.5 h-3.5 text-slate-400" />
            <span>{lang.toUpperCase()}</span>
          </button>
        </div>
      </div>

      {/* Navegação de Abas */}
      <div className="max-w-7xl mx-auto px-4 flex gap-1 border-t border-slate-800/60 text-sm overflow-x-auto">
        {[
          { id: 'servers', label: lang === 'pt' ? 'Servidores' : 'Servers' },
          { id: 'rules', label: lang === 'pt' ? 'Regras & Chains' : 'Rules & Chains' },
          { id: 'ipsets', label: 'IPSets' },
          { id: 'backups', label: 'Backups' },
          { id: 'audit', label: lang === 'pt' ? 'Auditoria' : 'Audit Logs' },
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => onSelectTab(tab.id)}
            className={`px-4 py-2.5 font-medium border-b-2 transition whitespace-nowrap ${
              activeTab === tab.id
                ? 'border-emerald-500 text-emerald-400 bg-emerald-500/5'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>
    </header>
  );
};
