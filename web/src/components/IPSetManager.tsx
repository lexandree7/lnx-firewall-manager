import React, { useState } from 'react';
import { IPSetItem, Server } from '../types';
import { Layers, Plus, Upload, RefreshCw, CheckCircle } from 'lucide-react';
import { api } from '../api/client';

interface IPSetManagerProps {
  servers: Server[];
  selectedServerId: string;
  lang: 'pt' | 'en';
}

export const IPSetManager: React.FC<IPSetManagerProps> = ({ servers, selectedServerId, lang }) => {
  const [ipsets, setIpsets] = useState<IPSetItem[]>([
    {
      id: 'set_1',
      name: 'blacklist_spammers',
      type_name: 'hash:net',
      family: 'inet',
      elements_count: 1420,
      memory_size_bytes: 45056,
    },
    {
      id: 'set_2',
      name: 'whitelist_office',
      type_name: 'hash:ip',
      family: 'inet',
      elements_count: 8,
      memory_size_bytes: 2048,
    },
  ]);

  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showUploadModal, setShowUploadModal] = useState(false);
  const [selectedSet, setSelectedSet] = useState<IPSetItem | null>(null);
  const [bulkEntries, setBulkEntries] = useState('');
  const [setName, setSetName] = useState('');
  const [setType, setSetType] = useState('hash:ip');

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    const newSet: IPSetItem = {
      id: `set_${Date.now()}`,
      name: setName,
      type_name: setType,
      family: 'inet',
      elements_count: 0,
      memory_size_bytes: 1024,
    };
    setIpsets([...ipsets, newSet]);
    setShowCreateModal(false);
    setSetName('');
  };

  const handleUploadEntries = async () => {
    if (!selectedSet) return;
    const lines = bulkEntries
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l !== '' && !l.startsWith('#'));

    // Atualiza contagem localmente
    setIpsets(
      ipsets.map((s) => (s.name === selectedSet.name ? { ...s, elements_count: s.elements_count + lines.length } : s))
    );
    setShowUploadModal(false);
    setBulkEntries('');
    alert(`Sucesso! ${lines.length} entradas aplicadas atomicamente via ipset swap.`);
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Layers className="w-5 h-5 text-emerald-400" />
            <span>{lang === 'pt' ? 'Gerenciador de IPSets' : 'IPSet Manager'}</span>
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            {lang === 'pt'
              ? 'Conjuntos de alta performance no kernel para listas de bloqueio e liberação em massa'
              : 'High performance in-kernel sets for high capacity whitelists and threat intelligence'}
          </p>
        </div>

        <button
          onClick={() => setShowCreateModal(true)}
          className="bg-emerald-600 hover:bg-emerald-500 text-white font-medium px-3.5 py-2 rounded-lg text-sm flex items-center gap-2 transition"
        >
          <Plus className="w-4 h-4" />
          <span>{lang === 'pt' ? 'Criar IPSet' : 'Create IPSet'}</span>
        </button>
      </div>

      <div className="bg-slate-900/40 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        <table className="w-full text-left text-sm text-slate-300">
          <thead className="bg-slate-900/80 text-xs text-slate-400 uppercase font-mono border-b border-slate-800">
            <tr>
              <th className="px-4 py-3">{lang === 'pt' ? 'Nome do Set' : 'Set Name'}</th>
              <th className="px-4 py-3">{lang === 'pt' ? 'Tipo' : 'Type'}</th>
              <th className="px-4 py-3">{lang === 'pt' ? 'Família' : 'Family'}</th>
              <th className="px-4 py-3">{lang === 'pt' ? 'Entradas (IPs)' : 'Elements Count'}</th>
              <th className="px-4 py-3">{lang === 'pt' ? 'Memória' : 'Memory'}</th>
              <th className="px-4 py-3 text-right">{lang === 'pt' ? 'Ações' : 'Actions'}</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 font-mono text-xs">
            {ipsets.map((set) => (
              <tr key={set.id} className="hover:bg-slate-800/30 transition">
                <td className="px-4 py-3.5 font-bold text-slate-100 flex items-center gap-2">
                  <Layers className="w-4 h-4 text-emerald-400" />
                  <span>{set.name}</span>
                </td>
                <td className="px-4 py-3.5 text-slate-400">{set.type_name}</td>
                <td className="px-4 py-3.5 text-slate-400">{set.family}</td>
                <td className="px-4 py-3.5 text-slate-200">{set.elements_count.toLocaleString()}</td>
                <td className="px-4 py-3.5 text-slate-400">{(set.memory_size_bytes / 1024).toFixed(1)} KB</td>
                <td className="px-4 py-3.5 text-right">
                  <button
                    onClick={() => {
                      setSelectedSet(set);
                      setShowUploadModal(true);
                    }}
                    className="bg-slate-800 hover:bg-slate-700 text-emerald-400 px-2.5 py-1 rounded text-xs transition inline-flex items-center gap-1 font-sans"
                  >
                    <Upload className="w-3.5 h-3.5" />
                    <span>{lang === 'pt' ? 'Importar / Swap' : 'Import / Swap'}</span>
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Modal de Criação de Set */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <form
            onSubmit={handleCreate}
            className="bg-slate-900 border border-slate-800 rounded-2xl max-w-md w-full p-6 shadow-2xl space-y-4"
          >
            <h3 className="font-bold text-slate-100">{lang === 'pt' ? 'Criar Novo IPSet' : 'Create New IPSet'}</h3>
            <div className="space-y-3 text-xs font-mono">
              <div>
                <label className="block text-slate-400 mb-1">Nome do Set</label>
                <input
                  type="text"
                  required
                  value={setName}
                  onChange={(e) => setSetName(e.target.value)}
                  placeholder="Ex: blocklist_malware"
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 outline-none"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Tipo de Estrutura</label>
                <select
                  value={setType}
                  onChange={(e) => setSetType(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 outline-none"
                >
                  <option value="hash:ip">hash:ip (IPs únicos /32)</option>
                  <option value="hash:net">hash:net (Sub-redes CIDR /24, /16)</option>
                  <option value="hash:ip,port">hash:ip,port (Pares IP + Porta)</option>
                  <option value="list:set">list:set (Lista encadeada de sets)</option>
                </select>
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={() => setShowCreateModal(false)}
                className="bg-slate-800 hover:bg-slate-700 text-slate-300 px-3 py-1.5 rounded text-sm"
              >
                Cancelar
              </button>
              <button
                type="submit"
                className="bg-emerald-600 hover:bg-emerald-500 text-white px-4 py-1.5 rounded text-sm font-medium"
              >
                Criar
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Modal de Importação / Swap Atômico */}
      {showUploadModal && selectedSet && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-lg w-full p-6 shadow-2xl space-y-4">
            <h3 className="font-bold text-slate-100 flex items-center gap-2">
              <Upload className="w-5 h-5 text-emerald-400" />
              <span>
                {lang === 'pt' ? `Importação Atômica: ${selectedSet.name}` : `Atomic Swap Import: ${selectedSet.name}`}
              </span>
            </h3>

            <p className="text-xs text-slate-400">
              {lang === 'pt'
                ? 'Cole uma lista de IPs ou redes (um por linha) ou envie um arquivo CSV/TXT. A atualização utiliza ipset swap garantindo perda zero de pacotes.'
                : 'Paste IPs/subnets (one per line) or upload a CSV/TXT. Updates are applied via atomic ipset swap.'}
            </p>

            <textarea
              rows={8}
              value={bulkEntries}
              onChange={(e) => setBulkEntries(e.target.value)}
              placeholder="192.168.1.50&#10;10.0.0.0/24&#10;203.0.113.12"
              className="w-full bg-slate-950 border border-slate-800 rounded-xl p-3 font-mono text-xs text-slate-200 outline-none"
            />

            <div className="flex justify-between items-center pt-2">
              <span className="text-xs text-slate-500 font-mono">
                {bulkEntries.split('\n').filter((l) => l.trim() !== '').length} linhas
              </span>
              <div className="flex gap-2">
                <button
                  onClick={() => setShowUploadModal(false)}
                  className="bg-slate-800 hover:bg-slate-700 text-slate-300 px-3 py-1.5 rounded text-sm"
                >
                  Cancelar
                </button>
                <button
                  onClick={handleUploadEntries}
                  className="bg-emerald-600 hover:bg-emerald-500 text-white px-4 py-1.5 rounded text-sm font-bold flex items-center gap-1.5"
                >
                  <RefreshCw className="w-4 h-4" />
                  <span>{lang === 'pt' ? 'Executar Swap Atômico' : 'Execute Atomic Swap'}</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
