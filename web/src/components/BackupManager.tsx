import React, { useState } from 'react';
import { BackupItem, Server } from '../types';
import { Archive, Plus, RotateCcw, ShieldCheck, FileText, CheckCircle2 } from 'lucide-react';
import { api } from '../api/client';

interface BackupManagerProps {
  servers: Server[];
  selectedServerId: string;
  lang: 'pt' | 'en';
  onTriggerLockout: (changeId: string, timeoutSec: number) => void;
}

export const BackupManager: React.FC<BackupManagerProps> = ({
  servers,
  selectedServerId,
  lang,
  onTriggerLockout,
}) => {
  const [backups, setBackups] = useState<BackupItem[]>([
    {
      id: 'bak_1720000001',
      server_id: selectedServerId,
      backup_type: 'pre_apply_snapshot',
      description: 'Snapshot automático pré-aplicação de regras SSH',
      checksum_sha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
      created_by: 'system_auto',
      created_at: new Date(Date.now() - 3600000).toISOString(),
    },
    {
      id: 'bak_1720000002',
      server_id: selectedServerId,
      backup_type: 'manual',
      description: 'Estado estável de produção antes de manutenção',
      checksum_sha256: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
      created_by: 'admin',
      created_at: new Date(Date.now() - 86400000).toISOString(),
    },
  ]);

  const handleCreateSnapshot = () => {
    const newBak: BackupItem = {
      id: `bak_${Date.now()}`,
      server_id: selectedServerId,
      backup_type: 'manual',
      description: `Backup pontual criado manualmente (${new Date().toLocaleTimeString()})`,
      checksum_sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      created_by: 'operator',
      created_at: new Date().toISOString(),
    };
    setBackups([newBak, ...backups]);
    alert('Backup pontual gerado com sucesso contendo iptables, ip6tables e ipsets!');
  };

  const handleRestore = (bak: BackupItem) => {
    if (confirm(`Deseja restaurar o backup ${bak.id}? A proteção contra lockout de 30s será ativada automaticamente.`)) {
      onTriggerLockout(`rst_${bak.id}`, 30);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Archive className="w-5 h-5 text-emerald-400" />
            <span>{lang === 'pt' ? 'Backups & Snapshots de Segurança' : 'Backups & Snapshots'}</span>
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            {lang === 'pt'
              ? 'Snapshots pré-aplicação atômicos, backups agendados e restauração cross-server'
              : 'Pre-apply snapshots, scheduled backups, and cross-server disaster recovery'}
          </p>
        </div>

        <button
          onClick={handleCreateSnapshot}
          className="bg-emerald-600 hover:bg-emerald-500 text-white font-medium px-3.5 py-2 rounded-lg text-sm flex items-center gap-2 transition"
        >
          <Plus className="w-4 h-4" />
          <span>{lang === 'pt' ? 'Criar Backup Agora' : 'Create Backup Now'}</span>
        </button>
      </div>

      <div className="bg-slate-900/40 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        <table className="w-full text-left text-sm text-slate-300">
          <thead className="bg-slate-900/80 text-xs text-slate-400 uppercase font-mono border-b border-slate-800">
            <tr>
              <th className="px-4 py-3">{lang === 'pt' ? 'Tipo' : 'Type'}</th>
              <th className="px-4 py-3">{lang === 'pt' ? 'Descrição' : 'Description'}</th>
              <th className="px-4 py-3">SHA-256 Checksum</th>
              <th className="px-4 py-3">{lang === 'pt' ? 'Autor' : 'Author'}</th>
              <th className="px-4 py-3">{lang === 'pt' ? 'Data / Hora' : 'Date / Time'}</th>
              <th className="px-4 py-3 text-right">{lang === 'pt' ? 'Ações' : 'Actions'}</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 font-mono text-xs">
            {backups.map((b) => (
              <tr key={b.id} className="hover:bg-slate-800/30 transition">
                <td className="px-4 py-3.5">
                  <span
                    className={`px-2 py-0.5 rounded text-[11px] font-bold ${
                      b.backup_type === 'pre_apply_snapshot'
                        ? 'bg-blue-500/20 text-blue-300 border border-blue-500/30'
                        : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                    }`}
                  >
                    {b.backup_type}
                  </span>
                </td>
                <td className="px-4 py-3.5 font-sans text-xs text-slate-200">{b.description}</td>
                <td className="px-4 py-3.5 text-slate-500 text-[11px] truncate max-w-xs">{b.checksum_sha256}</td>
                <td className="px-4 py-3.5 text-slate-400">{b.created_by}</td>
                <td className="px-4 py-3.5 text-slate-400">{new Date(b.created_at).toLocaleString()}</td>
                <td className="px-4 py-3.5 text-right">
                  <button
                    onClick={() => handleRestore(b)}
                    className="bg-slate-800 hover:bg-slate-700 text-amber-400 px-2.5 py-1 rounded text-xs transition inline-flex items-center gap-1 font-sans"
                  >
                    <RotateCcw className="w-3.5 h-3.5" />
                    <span>{lang === 'pt' ? 'Restaurar' : 'Restore'}</span>
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
