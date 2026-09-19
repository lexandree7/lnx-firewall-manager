import React, { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { ServerList } from './components/ServerList';
import { RuleManager } from './components/RuleManager';
import { IPSetManager } from './components/IPSetManager';
import { BackupManager } from './components/BackupManager';
import { AuditView } from './components/AuditView';
import { Server, RuleCounterSample } from './types';
import { api } from './api/client';

export const App: React.FC = () => {
  const [servers, setServers] = useState<Server[]>([]);
  const [selectedServerId, setSelectedServerId] = useState<string>('ALL');
  const [activeTab, setActiveTab] = useState<string>('servers');
  const [lang, setLang] = useState<'pt' | 'en'>('pt');
  const [pendingRollback, setPendingRollback] = useState<{ changeId: string; secondsRemaining: number } | null>(null);
  const [telemetrySamples, setTelemetrySamples] = useState<Record<string, RuleCounterSample>>({});

  const loadServers = async () => {
    try {
      const list = await api.getServers();
      setServers(list);
      if (list.length > 0 && selectedServerId === 'ALL') {
        // Mantém 'ALL' ou seleciona primeiro se desejado
      }
    } catch (e) {
      console.error('Falha ao carregar servidores:', e);
    }
  };

  useEffect(() => {
    loadServers();
    const interval = setInterval(loadServers, 10000);
    return () => clearInterval(interval);
  }, []);

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
    const wsProto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${wsProto}//${window.location.host}/api/v1/ui/ws`);

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.event === 'server_online' || data.event === 'server_offline') {
          loadServers();
        } else if (data.event === 'telemetry_update' && data.samples) {
          const map: Record<string, RuleCounterSample> = {};
          data.samples.forEach((s: RuleCounterSample) => {
            map[`${s.table_name}:${s.chain_name}:${s.rule_position}`] = s;
          });
          setTelemetrySamples((prev) => ({ ...prev, ...map }));
        } else if (data.event === 'safety_rollback_triggered') {
          setPendingRollback(null);
          alert(`ALERTA: Rollback automático disparado no host ${data.hostname}! Motivo: ${data.reason}`);
          loadServers();
        }
      } catch (err) {
        console.error('Erro ao processar mensagem do WebSocket:', err);
      }
    };

    return () => ws.close();
  }, []);

  const handleTriggerLockout = (changeId: string, timeoutSec: number) => {
    setPendingRollback({ changeId, secondsRemaining: timeoutSec });
  };

  const handleConfirmCommit = async () => {
    if (!pendingRollback) return;
    const targets = selectedServerId === 'ALL' ? servers.map((s) => s.id) : [selectedServerId];
    try {
      await api.confirmBatchRules(targets, pendingRollback.changeId);
      setPendingRollback(null);
      alert(lang === 'pt' ? 'Sucesso! Regras confirmadas permanentemente nos servidores.' : 'Success! Rules permanently committed on servers.');
    } catch (e) {
      alert('Erro ao confirmar regras: ' + e);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col">
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
      />

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 py-6">
        {activeTab === 'servers' && (
          <ServerList servers={servers} onRefresh={loadServers} lang={lang} />
        )}
        {activeTab === 'rules' && (
          <RuleManager
            servers={servers}
            selectedServerId={selectedServerId}
            lang={lang}
            onTriggerLockout={handleTriggerLockout}
            telemetrySamples={telemetrySamples}
          />
        )}
        {activeTab === 'ipsets' && (
          <IPSetManager
            servers={servers}
            selectedServerId={selectedServerId}
            lang={lang}
          />
        )}
        {activeTab === 'backups' && (
          <BackupManager
            servers={servers}
            selectedServerId={selectedServerId}
            lang={lang}
            onTriggerLockout={handleTriggerLockout}
          />
        )}
        {activeTab === 'audit' && <AuditView lang={lang} />}
      </main>

      <footer className="border-t border-slate-800/80 py-4 text-center text-xs text-slate-500 font-mono">
        Linux Firewall Manager (LFM) • Centralized Netfilter Control Plane • Zero-Shell Architecture
      </footer>
    </div>
  );
};
