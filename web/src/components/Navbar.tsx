import React from 'react';
import { Shield, Server as ServerIcon, Globe, AlertTriangle, CheckCircle2, User as UserIcon, LogOut, KeyRound, Palette } from 'lucide-react';
import { Server, User, ThemeId, AVAILABLE_THEMES } from '../types';

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
  currentUser: User | null;
  onOpenUserManagement: () => void;
  onLogout: () => void;
  currentTheme?: ThemeId;
  onSelectTheme?: (theme: ThemeId) => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  servers = [],
  selectedServerId,
  onSelectServer,
  lang,
  onToggleLang,
  activeTab,
  onSelectTab,
  pendingRollback,
  onConfirmRollback,
  currentUser,
  onOpenUserManagement,
  onLogout,
  currentTheme = 'slate',
  onSelectTheme,
}) => {
  const safeServers = Array.isArray(servers) ? servers : [];
  const onlineCount = safeServers.filter((s) => s && s.status === 'online').length;

  return (
    <header className="border-b border-zinc-800 bg-black/95 backdrop-blur sticky top-0 z-40">
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
            className="bg-amber-500 hover:bg-amber-600 text-themebtn font-semibold px-3 py-1 rounded text-xs transition"
          >
            {lang === 'pt' ? 'Confirmar Permanência Agora' : 'Confirm Changes Now'}
          </button>
        </div>
      )}

      <div className="max-w-7xl mx-auto px-4 h-16 flex items-center justify-between">
        {/* Logo & Marca com tema escuro e detalhes em amarelo escuro */}
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-amber-500/10 border border-amber-500/30 flex items-center justify-center text-amber-400 shadow-lg shadow-amber-500/10">
            <Shield className="w-6 h-6" />
          </div>
          <div>
            <div className="font-bold text-zinc-100 tracking-tight flex items-center gap-2">
              <span>Linux Firewall Manager</span>
              <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30 font-bold">
                v1.0
              </span>
            </div>
            <div className="text-xs text-zinc-400 font-mono">iptables & ipset control plane</div>
          </div>
        </div>

        {/* Seletor Global de Servidor */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-1.5">
            <ServerIcon className="w-4 h-4 text-amber-500/80" />
            <select
              value={selectedServerId}
              onChange={(e) => onSelectServer(e.target.value)}
              className="bg-transparent text-sm text-zinc-200 outline-none cursor-pointer font-mono"
            >
              <option value="ALL" className="bg-zinc-900 text-zinc-200">
                {lang === 'pt' ? '⚡ Todos os Servidores (Lote)' : '⚡ All Servers (Batch)'} ({safeServers.length})
              </option>
              {safeServers.map((s) => (
                <option key={s.id} value={s.id} className="bg-zinc-900 text-zinc-200">
                  {s.status === 'online' ? '🟡' : '🔴'} {s.hostname} ({s.ip_address})
                </option>
              ))}
            </select>
          </div>

          <div className="hidden sm:flex items-center gap-1.5 text-xs font-mono px-2.5 py-1 rounded bg-zinc-950 border border-zinc-800 text-zinc-300">
            <CheckCircle2 className="w-3.5 h-3.5 text-amber-400" />
            <span>
              {onlineCount}/{safeServers.length} online
            </span>
          </div>
        </div>

        {/* Ações, Usuário e Idioma */}
        <div className="flex items-center gap-3">
          {/* User Profile Badge & Security Trigger */}
          {currentUser && (
            <div className="flex items-center gap-2 bg-zinc-950 border border-zinc-800 rounded-lg p-1">
              <button
                onClick={onOpenUserManagement}
                className="flex items-center gap-2 px-2.5 py-1 rounded hover:bg-zinc-900 transition text-xs font-mono text-zinc-200 hover:text-white"
                title={lang === 'pt' ? 'Configurações de Segurança e Conta' : 'Security and Account Settings'}
              >
                <div className="w-5 h-5 rounded-full bg-amber-500/20 text-amber-400 flex items-center justify-center">
                  <UserIcon className="w-3.5 h-3.5" />
                </div>
                <span className="font-bold">{currentUser.username}</span>
                <span
                  className={`text-[9px] uppercase px-1.5 py-0.5 rounded font-bold border ${
                    currentUser.role === 'admin'
                      ? 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                      : 'bg-zinc-800 text-zinc-300 border-zinc-700'
                  }`}
                >
                  {currentUser.role}
                </span>
                <KeyRound className="w-3.5 h-3.5 text-zinc-500 hover:text-amber-400 ml-1" />
              </button>

              <button
                onClick={onLogout}
                className="p-1.5 rounded hover:bg-red-950/60 text-zinc-400 hover:text-red-400 transition"
                title={lang === 'pt' ? 'Encerrar Sessão (Logout)' : 'Log Out'}
              >
                <LogOut className="w-3.5 h-3.5" />
              </button>
            </div>
          )}

          {/* Quick Theme Switcher */}
          {onSelectTheme && (
            <div
              className="flex items-center bg-zinc-950 border border-zinc-800 rounded-lg p-1 gap-1"
              title={lang === 'pt' ? 'Tema de Cores' : 'Color Theme'}
            >
              <Palette className="w-3.5 h-3.5 text-zinc-400 ml-1 mr-0.5 shrink-0 hidden sm:block" />
              {AVAILABLE_THEMES.map((th) => {
                const isActive = (currentTheme || 'slate') === th.id;
                return (
                  <button
                    key={th.id}
                    type="button"
                    onClick={() => onSelectTheme(th.id)}
                    className={`w-5 h-5 rounded-md flex items-center justify-center transition-all ${
                      isActive
                        ? 'ring-1.5 ring-amber-400 bg-zinc-800 shadow-sm scale-110'
                        : 'hover:bg-zinc-900 opacity-60 hover:opacity-100'
                    }`}
                    title={`${lang === 'pt' ? th.namePt : th.nameEn}${isActive ? (lang === 'pt' ? ' (Ativo)' : ' (Active)') : ''}`}
                  >
                    <span
                      className="w-2.5 h-2.5 rounded-full border border-black/40 shadow-inner"
                      style={{ backgroundColor: th.previewColor }}
                    />
                  </button>
                );
              })}
            </div>
          )}

          {/* Language Switcher */}
          <button
            onClick={onToggleLang}
            className="flex items-center gap-1.5 text-xs font-medium text-zinc-300 hover:text-white px-2.5 py-1.5 rounded-lg border border-zinc-800 hover:border-zinc-700 bg-zinc-950 transition"
          >
            <Globe className="w-3.5 h-3.5 text-amber-400" />
            <span>{lang.toUpperCase()}</span>
          </button>
        </div>
      </div>

      {/* Navegação de Abas com Contador Destacado */}
      <div className="max-w-7xl mx-auto px-4 flex gap-1 border-t border-zinc-800/80 text-sm overflow-x-auto">
        {[
          { id: 'servers', label: lang === 'pt' ? 'Servidores' : 'Servers', count: safeServers.length },
          { id: 'rules', label: lang === 'pt' ? 'Regras & Chains' : 'Rules & Chains' },
          { id: 'ipsets', label: 'IPSets' },
          { id: 'backups', label: 'Backups' },
          { id: 'audit', label: lang === 'pt' ? 'Auditoria' : 'Audit Logs' },
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => onSelectTab(tab.id)}
            className={`px-4 py-2.5 font-medium border-b-2 transition whitespace-nowrap flex items-center gap-2 ${
              activeTab === tab.id
                ? 'border-amber-500 text-amber-400 bg-amber-500/10'
                : 'border-transparent text-zinc-400 hover:text-zinc-200'
            }`}
          >
            <span>{tab.label}</span>
            {tab.count !== undefined && (
              <span
                className={`text-[11px] font-mono px-2 py-0.5 rounded-full font-bold ${
                  activeTab === tab.id
                    ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                    : 'bg-zinc-900 text-zinc-400 border border-zinc-800'
                }`}
              >
                {tab.count}
              </span>
            )}
          </button>
        ))}
      </div>
    </header>
  );
};
