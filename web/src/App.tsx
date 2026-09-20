import React, { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { ServerList } from './components/ServerList';
import { RuleManager } from './components/RuleManager';
import { IPSetManager } from './components/IPSetManager';
import { BackupManager } from './components/BackupManager';
import { AuditView } from './components/AuditView';
import { Login } from './components/Login';
import { UserManagement } from './components/UserManagement';
import { Server, RuleCounterSample, User } from './types';
import { api } from './api/client';
import { Shield } from 'lucide-react';

export const App: React.FC = () => {
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [isCheckingAuth, setIsCheckingAuth] = useState<boolean>(true);
  const [loginError, setLoginError] = useState<string | null>(null);
  const [showUserModal, setShowUserModal] = useState<boolean>(false);

  const [servers, setServers] = useState<Server[]>([]);
  const [selectedServerId, setSelectedServerId] = useState<string>('ALL');
  const [hasSetInitialServer, setHasSetInitialServer] = useState<boolean>(false);
  const [rulesUpdateKey, setRulesUpdateKey] = useState<number>(0);
  const [activeTab, setActiveTab] = useState<string>('servers');
  const [lang, setLang] = useState<'pt' | 'en'>('pt');
  const [pendingRollback, setPendingRollback] = useState<{ changeId: string; secondsRemaining: number } | null>(null);
  const [telemetrySamples, setTelemetrySamples] = useState<Record<string, RuleCounterSample>>({});

  // Checagem de parâmetros de redirecionamento SSO e autenticação inicial
  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const ssoToken = urlParams.get('token');
    const ssoError = urlParams.get('error');

    if (ssoToken) {
      api.setToken(ssoToken);
      window.history.replaceState({}, document.title, window.location.pathname);
    }

    if (ssoError) {
      setLoginError(decodeURIComponent(ssoError));
      window.history.replaceState({}, document.title, window.location.pathname);
    }

    const checkAuth = async () => {
      try {
        const me = await api.getMe();
        setCurrentUser(me);
      } catch {
        api.setToken(null);
        setCurrentUser(null);
      } finally {
        setIsCheckingAuth(false);
      }
    };

    checkAuth();
  }, []);

  const handleLogout = async () => {
    try {
      await api.logout();
    } finally {
      setCurrentUser(null);
      setShowUserModal(false);
    }
  };

  const loadServers = async () => {
    if (!currentUser) return;
    try {
      const list = await api.getServers();
      setServers(list);
      if (!hasSetInitialServer && list.length > 0) {
        setSelectedServerId(list[0].id);
        setHasSetInitialServer(true);
      }
    } catch (e) {
      console.error('Falha ao carregar servidores:', e);
    }
  };

  useEffect(() => {
    if (!currentUser) return;
    loadServers();
    const interval = setInterval(loadServers, 10000);
    return () => clearInterval(interval);
  }, [currentUser]);

  // Timer de Lockout countdown
  useEffect(() => {
    if (!pendingRollback) return;
    if (pendingRollback.secondsRemaining <= 0) {
      setPendingRollback(null);
      alert(lang === 'pt' ? 'Tempo de confirmação expirado! O agente efetuou o auto-rollback preventivo.' : 'Confirmation timed out! Safety rollback triggered.');
      return;
    }

    const timer = setInterval(() => {
      setPendingRollback((prev) =>
        prev ? { ...prev, secondsRemaining: prev.secondsRemaining - 1 } : null
      );
    }, 1000);

    return () => clearInterval(timer);
  }, [pendingRollback, lang]);

  // Conexão WebSocket em tempo real com o Hub
  useEffect(() => {
    if (!currentUser) return;
    const wsProto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${wsProto}//${window.location.host}/api/v1/ui/ws`);

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.event === 'server_online' || data.event === 'server_offline') {
          loadServers();
        } else if (data.event === 'rules_updated') {
          setRulesUpdateKey((prev) => prev + 1);
        } else if (data.event === 'telemetry_update' && data.samples) {
          const map: Record<string, RuleCounterSample> = {};
          data.samples.forEach((s: RuleCounterSample) => {
            map[`${s.table_name}:${s.chain_name}:${s.rule_position}`] = s;
          });
          setTelemetrySamples((prev) => ({ ...prev, ...map }));
        } else if (data.event === 'safety_rollback_triggered') {
          setPendingRollback(null);
          setRulesUpdateKey((prev) => prev + 1);
          alert(`ALERTA: Rollback automático disparado no host ${data.hostname}! Motivo: ${data.reason}`);
          loadServers();
        }
      } catch (err) {
        console.error('Erro ao processar mensagem do WebSocket:', err);
      }
    };

    return () => ws.close();
  }, [currentUser]);

  const handleTriggerLockout = (changeId: string, timeoutSec: number) => {
    setPendingRollback({ changeId, secondsRemaining: timeoutSec });
  };

  const handleConfirmCommit = async () => {
    if (!pendingRollback) return;
    const targets = selectedServerId === 'ALL' ? servers.map((s) => s.id) : [selectedServerId];
    try {
      await api.confirmBatchRules(targets, pendingRollback.changeId);
      setPendingRollback(null);
      setRulesUpdateKey((prev) => prev + 1);
      alert(lang === 'pt' ? 'Sucesso! Regras confirmadas permanentemente nos servidores.' : 'Success! Rules permanently committed on servers.');
    } catch (e) {
      alert('Erro ao confirmar regras: ' + e);
    }
  };

  // Carregamento inicial de autenticação
  if (isCheckingAuth) {
    return (
      <div className="min-h-screen bg-black text-zinc-100 flex flex-col items-center justify-center">
        <div className="w-12 h-12 rounded-2xl bg-amber-500/10 border border-amber-500/30 flex items-center justify-center text-amber-400 mb-4 animate-pulse">
          <Shield className="w-6 h-6" />
        </div>
        <div className="text-xs font-mono text-zinc-400">Verificando credenciais e sessão segura...</div>
      </div>
    );
  }

  // Tela de Login caso não esteja autenticado
  if (!currentUser) {
    return (
      <Login
        onLoginSuccess={(user) => {
          setCurrentUser(user);
          setLoginError(null);
        }}
        lang={lang}
        onToggleLang={() => setLang((l) => (l === 'pt' ? 'en' : 'pt'))}
        errorMessage={loginError || undefined}
      />
    );
  }

  return (
    <div className="min-h-screen bg-black text-zinc-100 flex flex-col selection:bg-amber-500/30 selection:text-amber-200">
      <Navbar
        servers={servers}
        selectedServerId={selectedServerId}
        onSelectServer={setSelectedServerId}
        lang={lang}
        onToggleLang={() => setLang(lang === 'pt' ? 'en' : 'pt')}
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        pendingRollback={pendingRollback}
        onConfirmRollback={handleConfirmCommit}
        currentUser={currentUser}
        onOpenUserManagement={() => setShowUserModal(true)}
        onLogout={handleLogout}
      />

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 py-6">
        {activeTab === 'servers' && (
          <ServerList servers={servers} onRefresh={loadServers} lang={lang} />
        )}
        {activeTab === 'rules' && (
          <RuleManager
            servers={servers}
            selectedServerId={selectedServerId}
            onSelectServer={setSelectedServerId}
            lang={lang}
            onTriggerLockout={handleTriggerLockout}
            telemetrySamples={telemetrySamples}
            userRole={currentUser.role}
            rulesUpdateKey={rulesUpdateKey}
          />
        )}
        {activeTab === 'ipsets' && (
          <IPSetManager
            servers={servers}
            selectedServerId={selectedServerId}
            lang={lang}
            userRole={currentUser.role}
          />
        )}
        {activeTab === 'backups' && (
          <BackupManager
            servers={servers}
            selectedServerId={selectedServerId}
            lang={lang}
            onTriggerLockout={handleTriggerLockout}
            userRole={currentUser.role}
          />
        )}
        {activeTab === 'audit' && <AuditView lang={lang} />}
      </main>

      {/* Modal de Gerenciamento de Usuário, Senha, 2FA e OIDC */}
      {showUserModal && (
        <UserManagement
          currentUser={currentUser}
          onUpdateUser={(updated) => setCurrentUser(updated)}
          lang={lang}
          onClose={() => setShowUserModal(false)}
        />
      )}

      <footer className="border-t border-zinc-900 py-4 text-center text-xs text-zinc-600 font-mono">
        Linux Firewall Manager (LFM) • Centralized Netfilter Control Plane • Zero-Shell Architecture • RBAC: <span className="text-amber-400 font-bold uppercase">{currentUser.role}</span>
      </footer>
    </div>
  );
};
