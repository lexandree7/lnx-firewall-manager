import React, { useState, useEffect, useMemo } from 'react';
import { IPSetItem, Server } from '../types';
import {
  Layers,
  Plus,
  Trash2,
  Edit2,
  Check,
  X,
  Copy,
  Download,
  Upload,
  Search,
  RefreshCw,
  AlertCircle,
  CheckCircle2,
  Lock,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Info,
} from 'lucide-react';
import { api } from '../api/client';

interface IPSetManagerProps {
  servers: Server[];
  selectedServerId: string;
  lang: 'pt' | 'en';
  userRole?: 'admin' | 'viewer';
}

export const IPSetManager: React.FC<IPSetManagerProps> = ({
  servers,
  selectedServerId,
  lang,
  userRole = 'admin',
}) => {
  const isAdmin = userRole === 'admin';
  const effectiveServerId = selectedServerId === 'ALL' ? (servers[0]?.id || 'global') : selectedServerId;

  const [ipsets, setIpsets] = useState<IPSetItem[]>([
    {
      id: 'set_1',
      name: 'blacklist_spammers',
      type_name: 'hash:net',
      family: 'inet',
      elements_count: 5,
      memory_size_bytes: 45056,
    },
    {
      id: 'set_2',
      name: 'whitelist_office',
      type_name: 'hash:ip',
      family: 'inet',
      elements_count: 5,
      memory_size_bytes: 2048,
    },
  ]);

  const [selectedSet, setSelectedSet] = useState<IPSetItem>(ipsets[0]);
  const [entries, setEntries] = useState<string[]>([]);
  const [originalEntries, setOriginalEntries] = useState<string[]>([]);
  const [loadingEntries, setLoadingEntries] = useState(false);
  const [savingEntries, setSavingEntries] = useState(false);

  // Vínculo com regras ativas (Regra de integridade)
  const [usageInfo, setUsageInfo] = useState<{ in_use: boolean; bound_rules: string[] }>({
    in_use: false,
    bound_rules: [],
  });
  const [loadingUsage, setLoadingUsage] = useState(false);

  // List search & pagination
  const [searchQuery, setSearchQuery] = useState('');
  const [newEntryInput, setNewEntryInput] = useState('');
  const [editingIndex, setEditingIndex] = useState<number | null>(null);
  const [editingValue, setEditingValue] = useState('');

  // Modais
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showBulkModal, setShowBulkModal] = useState(false);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [showBlockedModal, setShowBlockedModal] = useState(false);
  const [deletingSet, setDeletingSet] = useState(false);

  const [bulkText, setBulkText] = useState('');
  const [setName, setSetName] = useState('');
  const [setType, setSetType] = useState('hash:ip');
  const [notification, setNotification] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Carregar lista de ipsets do servidor
  const loadIPSets = async () => {
    try {
      const list = await api.getIPSets(effectiveServerId);
      if (list && list.length > 0) {
        setIpsets(list);
        if (!list.find((s) => s.name === selectedSet?.name)) {
          setSelectedSet(list[0]);
        }
      }
    } catch (err) {
      console.warn('Usando conjuntos locais de fallback:', err);
    }
  };

  useEffect(() => {
    loadIPSets();
  }, [effectiveServerId]);

  // Carregar uso / regras vinculadas ao IPSet selecionado
  const loadUsage = async (setNameToCheck: string) => {
    setLoadingUsage(true);
    try {
      const usage = await api.getIPSetUsage(effectiveServerId, setNameToCheck);
      setUsageInfo(usage);
    } catch {
      setUsageInfo({ in_use: false, bound_rules: [] });
    } finally {
      setLoadingUsage(false);
    }
  };

  // Carregar entradas do IPSet selecionado
  const loadEntries = async (setNameToLoad: string) => {
    setLoadingEntries(true);
    try {
      const data = await api.getIPSetEntries(effectiveServerId, setNameToLoad);
      const list = Array.isArray(data) ? data : [];
      setEntries(list);
      setOriginalEntries(list);
    } catch {
      let mock: string[] = [];
      if (setNameToLoad === 'whitelist_office') {
        mock = ['192.168.1.10', '192.168.1.11', '10.0.0.5', '10.0.0.6', '172.16.0.2'];
      } else {
        mock = ['198.51.100.1', '203.0.113.5', '192.0.2.45', '10.200.0.0/24', '185.220.101.5'];
      }
      setEntries(mock);
      setOriginalEntries(mock);
    } finally {
      setLoadingEntries(false);
    }
  };

  useEffect(() => {
    if (selectedSet) {
      loadEntries(selectedSet.name);
      loadUsage(selectedSet.name);
      setSearchQuery('');
      setEditingIndex(null);
    }
  }, [selectedSet?.name, effectiveServerId]);

  // Verifica se há alterações pendentes
  const hasUnsavedChanges = useMemo(() => {
    if (entries.length !== originalEntries.length) return true;
    for (let i = 0; i < entries.length; i++) {
      if (entries[i] !== originalEntries[i]) return true;
    }
    return false;
  }, [entries, originalEntries]);

  // Itens filtrados pela busca
  const filteredEntries = useMemo(() => {
    if (!searchQuery.trim()) return entries;
    const q = searchQuery.toLowerCase().trim();
    return entries.filter((item) => item.toLowerCase().includes(q));
  }, [entries, searchQuery]);

  // Ações na lista
  const handleAddEntry = (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    const val = newEntryInput.trim();
    if (!val) return;

    if (entries.includes(val)) {
      setNotification({
        type: 'error',
        text: lang === 'pt' ? `O item "${val}" já está presente nesta lista.` : `"${val}" is already in the list.`,
      });
      return;
    }

    setEntries([val, ...entries]);
    setNewEntryInput('');
    setNotification(null);
  };

  const handleStartEdit = (indexInFiltered: number, val: string) => {
    const originalIdx = entries.indexOf(val);
    setEditingIndex(originalIdx);
    setEditingValue(val);
  };

  const handleSaveEdit = (originalIdx: number) => {
    const trimmed = editingValue.trim();
    if (!trimmed) return;
    const updated = [...entries];
    updated[originalIdx] = trimmed;
    setEntries(updated);
    setEditingIndex(null);
  };

  const handleDeleteEntry = (val: string) => {
    setEntries(entries.filter((item) => item !== val));
  };

  const handleClearAll = () => {
    if (confirm(lang === 'pt' ? 'Deseja limpar todos os itens desta lista?' : 'Clear all items in this list?')) {
      setEntries([]);
    }
  };

  const handleRevert = () => {
    setEntries([...originalEntries]);
    setNotification(null);
  };

  // Salvar lista no Firewall via Swap Atômico
  const handleSaveAndSwap = async () => {
    if (!selectedSet) return;
    setSavingEntries(true);
    setNotification(null);

    try {
      await api.saveIPSetEntries(effectiveServerId, selectedSet.name, entries);
      setOriginalEntries([...entries]);

      setIpsets((prev) =>
        prev.map((s) => (s.name === selectedSet.name ? { ...s, elements_count: entries.length } : s))
      );

      setNotification({
        type: 'success',
        text:
          lang === 'pt'
            ? `Lista atualizada com sucesso! ${entries.length} itens sincronizados atomicamente via ipset swap.`
            : `List updated! ${entries.length} entries atomically synchronized via ipset swap.`,
      });
    } catch (err: any) {
      setNotification({
        type: 'error',
        text: err.message || 'Falha ao sincronizar lista no kernel',
      });
    } finally {
      setSavingEntries(false);
    }
  };

  // Exclusão de IPSet com verificação de regra ativa
  const handleDeleteClick = () => {
    if (usageInfo.in_use) {
      // Bloqueado: exibe modal detalhando as regras ativas que impedem a remoção
      setShowBlockedModal(true);
    } else {
      // Permitido: abre confirmação de exclusão
      setShowDeleteModal(true);
    }
  };

  const handleConfirmDelete = async () => {
    if (!selectedSet) return;
    setDeletingSet(true);
    setNotification(null);

    try {
      const res = await api.deleteIPSet(effectiveServerId, selectedSet.name);
      setShowDeleteModal(false);

      const remaining = ipsets.filter((s) => s.name !== selectedSet.name);
      setIpsets(remaining);
      if (remaining.length > 0) {
        setSelectedSet(remaining[0]);
      }

      setNotification({
        type: 'success',
        text: res.message || (lang === 'pt' ? `IPSet '${selectedSet.name}' excluído com sucesso.` : `IPSet '${selectedSet.name}' deleted.`),
      });
    } catch (err: any) {
      setShowDeleteModal(false);
      setNotification({
        type: 'error',
        text: err.message || 'Erro ao excluir IPSet',
      });
      // Se o erro foi por vínculo detectado no backend, recarrega o usage
      loadUsage(selectedSet.name);
    } finally {
      setDeletingSet(false);
    }
  };

  // Importação em massa para a lista
  const handleApplyBulk = () => {
    const lines = bulkText
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l !== '' && !l.startsWith('#'));

    if (lines.length === 0) {
      setShowBulkModal(false);
      return;
    }

    const setCombined = new Set([...entries, ...lines]);
    const newList = Array.from(setCombined);
    setEntries(newList);
    setShowBulkModal(false);
    setBulkText('');
    setNotification({
      type: 'success',
      text:
        lang === 'pt'
          ? `${lines.length} itens adicionados à lista de edição. Clique em Salvar para aplicar.`
          : `${lines.length} items added to edit list. Click Save to commit.`,
    });
  };

  // Exportar lista para área de transferência
  const handleExportClipboard = () => {
    navigator.clipboard.writeText(entries.join('\n'));
    setNotification({
      type: 'success',
      text:
        lang === 'pt'
          ? `${entries.length} itens copiados para a área de transferência!`
          : `${entries.length} items copied to clipboard!`,
    });
  };

  // Criação de novo conjunto IPSet
  const handleCreateSet = async (e: React.FormEvent) => {
    e.preventDefault();
    const cleanName = setName.trim().toLowerCase().replace(/[^a-z0-9_]/g, '_');
    if (!cleanName) return;

    const newSet: IPSetItem = {
      id: `set_${Date.now()}`,
      name: cleanName,
      type_name: setType,
      family: 'inet',
      elements_count: 0,
      memory_size_bytes: 1024,
    };

    try {
      await api.createIPSet(effectiveServerId, { name: cleanName, type_name: setType, family: 'inet' });
    } catch {
      // continua localmente
    }

    setIpsets([...ipsets, newSet]);
    setSelectedSet(newSet);
    setEntries([]);
    setOriginalEntries([]);
    setShowCreateModal(false);
    setSetName('');
  };

  const copySingleItem = (val: string) => {
    navigator.clipboard.writeText(val);
    setCopiedId(val);
    setTimeout(() => setCopiedId(null), 1500);
  };

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-xl font-bold text-zinc-100 flex items-center gap-2">
            <Layers className="w-5 h-5 text-amber-400" />
            <span>{lang === 'pt' ? 'Gerenciador de IPSets (Edição em Lista)' : 'IPSet Manager (List Editor)'}</span>
          </h1>
          <p className="text-xs text-zinc-400 mt-0.5">
            {lang === 'pt'
              ? 'Edite, consulte e sincronize coleções de IPs e sub-redes em tempo real com swap atômico no kernel'
              : 'Edit, query, and synchronize IP collections in real time with kernel-level zero-downtime swap'}
          </p>
        </div>

        <div className="flex items-center gap-2">
          {isAdmin ? (
            <button
              onClick={() => setShowCreateModal(true)}
              className="bg-zinc-900 hover:bg-zinc-800 text-amber-400 border border-zinc-800 hover:border-amber-500/50 px-3.5 py-2 rounded-lg text-xs font-mono font-medium flex items-center gap-2 transition"
            >
              <Plus className="w-4 h-4 stroke-[2.5]" />
              <span>{lang === 'pt' ? 'Novo Conjunto IPSet' : 'New IPSet'}</span>
            </button>
          ) : (
            <span className="text-xs font-mono px-3 py-1.5 rounded-lg bg-zinc-900 border border-zinc-800 text-zinc-400 flex items-center gap-1.5">
              <Lock className="w-3.5 h-3.5 text-amber-400" />
              <span>{lang === 'pt' ? 'Somente Leitura (Viewer)' : 'Read-Only (Viewer)'}</span>
            </span>
          )}
        </div>
      </div>

      {/* Alerta de Notificação */}
      {notification && (
        <div
          className={`p-3 rounded-xl text-xs flex items-center justify-between gap-2 animate-fadeIn ${
            notification.type === 'success'
              ? 'bg-amber-950/40 border border-amber-800/60 text-amber-200'
              : 'bg-red-950/40 border border-red-800/60 text-red-300'
          }`}
        >
          <div className="flex items-center gap-2">
            {notification.type === 'success' ? (
              <CheckCircle2 className="w-4 h-4 text-amber-400 shrink-0" />
            ) : (
              <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
            )}
            <span>{notification.text}</span>
          </div>
          <button onClick={() => setNotification(null)} className="text-zinc-500 hover:text-zinc-300">
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* Main Layout: Master (Sets List) & Detail (Items List Editor) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Painel Esquerdo: Seletor de Conjuntos IPSet */}
        <div className="lg:col-span-4 space-y-3">
          <div className="flex items-center justify-between px-1">
            <span className="text-xs font-mono text-zinc-400 uppercase font-bold tracking-wider">
              {lang === 'pt' ? 'Conjuntos Disponíveis' : 'Available Sets'} ({ipsets.length})
            </span>
          </div>

          <div className="space-y-2">
            {ipsets.map((set) => {
              const isSelected = selectedSet?.name === set.name;
              return (
                <div
                  key={set.id || set.name}
                  onClick={() => setSelectedSet(set)}
                  className={`p-3.5 rounded-xl border transition cursor-pointer relative overflow-hidden group ${
                    isSelected
                      ? 'bg-amber-500/10 border-amber-500/80 shadow-lg shadow-amber-950/30'
                      : 'bg-zinc-950/90 border-zinc-800/80 hover:border-zinc-700 hover:bg-zinc-900/60'
                  }`}
                >
                  {isSelected && (
                    <div className="absolute left-0 top-0 bottom-0 w-1 bg-amber-500" />
                  )}
                  <div className="flex items-center justify-between">
                    <div className="font-mono font-bold text-sm text-zinc-100 flex items-center gap-2">
                      <Layers className={`w-4 h-4 ${isSelected ? 'text-amber-400' : 'text-zinc-500'}`} />
                      <span>{set.name}</span>
                    </div>
                    <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-zinc-900 border border-zinc-800 text-zinc-300">
                      {set.type_name}
                    </span>
                  </div>

                  <div className="flex items-center justify-between mt-2 pt-2 border-t border-zinc-900 text-xs font-mono text-zinc-500">
                    <span>
                      {lang === 'pt' ? 'Itens:' : 'Entries:'}{' '}
                      <strong className={isSelected ? 'text-amber-300 font-bold' : 'text-zinc-300'}>
                        {isSelected ? entries.length : set.elements_count}
                      </strong>
                    </span>
                    <span>{(set.memory_size_bytes / 1024).toFixed(1)} KB</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Painel Direito: O Editor da Lista de IPs */}
        <div className="lg:col-span-8 bg-zinc-950 border border-zinc-800 rounded-2xl p-5 shadow-2xl flex flex-col space-y-4">
          {/* Header do Editor de Lista */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-zinc-800/80">
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-lg font-bold text-white font-mono">{selectedSet.name}</span>
                <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/40 font-bold">
                  {selectedSet.type_name}
                </span>
                <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-zinc-900 text-zinc-400 border border-zinc-800">
                  {selectedSet.family}
                </span>

                {/* Badge de integridade de regras */}
                {usageInfo.in_use ? (
                  <span
                    onClick={() => setShowBlockedModal(true)}
                    className="cursor-pointer text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-amber-500/10 border border-amber-500/40 text-amber-300 flex items-center gap-1 font-bold hover:bg-amber-500/20 transition"
                    title={lang === 'pt' ? 'Clique para ver regras vinculadas' : 'Click to inspect bound rules'}
                  >
                    <Lock className="w-3 h-3 text-amber-400" />
                    <span>
                      {lang === 'pt'
                        ? `Vinculado (${usageInfo.bound_rules.length} regras)`
                        : `Bound (${usageInfo.bound_rules.length} rules)`}
                    </span>
                  </span>
                ) : (
                  <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-zinc-900 border border-zinc-800 text-zinc-400 flex items-center gap-1">
                    <ShieldCheck className="w-3 h-3 text-amber-500" />
                    <span>{lang === 'pt' ? 'Sem regras vinculadas' : 'No active rules'}</span>
                  </span>
                )}
              </div>
              <div className="text-xs text-zinc-500 font-mono mt-1">
                {entries.length} {lang === 'pt' ? 'elementos cadastrados na lista' : 'elements registered in list'}
              </div>
            </div>

            {/* Ações Globais da Lista e Botão de Deletar IPSet */}
            <div className="flex items-center gap-2">
              {hasUnsavedChanges && (
                <button
                  onClick={handleRevert}
                  disabled={savingEntries}
                  className="px-2.5 py-1.5 rounded-lg border border-zinc-800 hover:border-zinc-700 bg-zinc-900 text-zinc-400 hover:text-zinc-200 text-xs font-mono transition"
                >
                  {lang === 'pt' ? 'Descartar' : 'Revert'}
                </button>
              )}

              {isAdmin && (
                <>
                  <button
                    onClick={handleSaveAndSwap}
                    disabled={savingEntries || !hasUnsavedChanges}
                    className={`px-3.5 py-1.5 rounded-lg text-xs font-bold font-mono flex items-center gap-1.5 transition ${
                      hasUnsavedChanges
                        ? 'bg-amber-600 hover:bg-amber-500 text-black shadow-lg shadow-amber-950/50 animate-pulse'
                        : 'bg-zinc-900 border border-zinc-800 text-zinc-500 cursor-not-allowed'
                    }`}
                  >
                    <RefreshCw className={`w-3.5 h-3.5 ${savingEntries ? 'animate-spin' : ''}`} />
                    <span>
                      {savingEntries
                        ? lang === 'pt'
                          ? 'Salvando...'
                          : 'Saving...'
                        : lang === 'pt'
                        ? 'Salvar Lista (Swap)'
                        : 'Save List (Swap)'}
                    </span>
                  </button>

                  {/* Botão de Excluir IPSet protegido por verificação de vínculo */}
                  <button
                    onClick={handleDeleteClick}
                    className={`px-2.5 py-1.5 rounded-lg text-xs font-mono flex items-center gap-1.5 transition border ${
                      usageInfo.in_use
                        ? 'bg-zinc-900/80 border-zinc-800 text-zinc-400 hover:border-amber-500/50 hover:text-amber-300'
                        : 'bg-zinc-900 hover:bg-red-950/40 border-zinc-800 hover:border-red-800 text-zinc-300 hover:text-red-300'
                    }`}
                    title={
                      usageInfo.in_use
                        ? lang === 'pt'
                          ? 'Exclusão bloqueada: IPSet vinculado a regras ativas'
                          : 'Delete blocked: IPSet linked to active rules'
                        : lang === 'pt'
                        ? 'Excluir este IPSet (Livre de vínculos)'
                        : 'Delete this IPSet'
                    }
                  >
                    {usageInfo.in_use ? (
                      <Lock className="w-3.5 h-3.5 text-amber-500" />
                    ) : (
                      <Trash2 className="w-3.5 h-3.5 text-red-400" />
                    )}
                    <span>{lang === 'pt' ? 'Excluir IPSet' : 'Delete Set'}</span>
                  </button>
                </>
              )}
            </div>
          </div>

          {/* Barra de Busca e Ferramentas da Lista */}
          <div className="flex flex-col sm:flex-row gap-2 items-center justify-between">
            {/* Input de Filtro de Busca */}
            <div className="relative w-full sm:w-72">
              <div className="absolute inset-y-0 left-0 pl-2.5 flex items-center pointer-events-none text-zinc-500">
                <Search className="w-3.5 h-3.5" />
              </div>
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder={lang === 'pt' ? 'Buscar IP ou CIDR na lista...' : 'Search IP or CIDR in list...'}
                className="w-full bg-black/60 border border-zinc-800 rounded-lg pl-8 pr-3 py-1.5 text-xs text-zinc-100 placeholder-zinc-600 focus:outline-none focus:border-amber-500 font-mono"
              />
              {searchQuery && (
                <button
                  onClick={() => setSearchQuery('')}
                  className="absolute inset-y-0 right-0 pr-2 flex items-center text-zinc-500 hover:text-zinc-300"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              )}
            </div>

            {/* Botões de Ações em Massa */}
            <div className="flex items-center gap-2 w-full sm:w-auto justify-end">
              {isAdmin && (
                <button
                  onClick={() => setShowBulkModal(true)}
                  className="px-2.5 py-1.5 rounded-lg border border-zinc-800 hover:border-zinc-700 bg-zinc-900 text-zinc-300 hover:text-white text-xs font-mono flex items-center gap-1.5 transition"
                  title={lang === 'pt' ? 'Colar múltiplos IPs em lote' : 'Paste bulk IPs'}
                >
                  <Upload className="w-3.5 h-3.5 text-amber-500" />
                  <span>{lang === 'pt' ? 'Importar Lote' : 'Bulk Paste'}</span>
                </button>
              )}

              <button
                onClick={handleExportClipboard}
                disabled={entries.length === 0}
                className="px-2.5 py-1.5 rounded-lg border border-zinc-800 hover:border-zinc-700 bg-zinc-900 text-zinc-300 hover:text-white text-xs font-mono flex items-center gap-1.5 transition disabled:opacity-40"
                title={lang === 'pt' ? 'Copiar todos os IPs da lista' : 'Copy all items to clipboard'}
              >
                <Download className="w-3.5 h-3.5 text-amber-500" />
                <span>{lang === 'pt' ? 'Exportar' : 'Export'}</span>
              </button>

              {isAdmin && entries.length > 0 && (
                <button
                  onClick={handleClearAll}
                  className="px-2.5 py-1.5 rounded-lg border border-zinc-800 hover:border-red-900/60 bg-zinc-900 hover:bg-red-950/40 text-zinc-400 hover:text-red-300 text-xs font-mono transition"
                  title={lang === 'pt' ? 'Limpar todos os elementos' : 'Clear all elements'}
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              )}
            </div>
          </div>

          {/* Quick Add Row (Input de Inclusão Rápida na Lista) */}
          {isAdmin && (
            <form onSubmit={handleAddEntry} className="flex gap-2">
              <input
                type="text"
                value={newEntryInput}
                onChange={(e) => setNewEntryInput(e.target.value)}
                placeholder={
                  selectedSet.type_name === 'hash:net'
                    ? lang === 'pt'
                      ? 'Adicionar rede (ex: 10.0.0.0/24 ou 192.168.5.0/24)...'
                      : 'Add subnet (e.g. 10.0.0.0/24)...'
                    : lang === 'pt'
                    ? 'Adicionar IP (ex: 192.168.1.50 ou 203.0.113.12)...'
                    : 'Add IP (e.g. 192.168.1.50)...'
                }
                className="flex-1 bg-black border border-zinc-800 rounded-lg px-3 py-2 text-xs text-zinc-100 placeholder-zinc-600 focus:outline-none focus:border-amber-500 font-mono"
              />
              <button
                type="submit"
                disabled={!newEntryInput.trim()}
                className="bg-amber-600 hover:bg-amber-500 text-black font-bold px-4 py-2 rounded-lg text-xs font-mono flex items-center gap-1.5 transition disabled:opacity-40 shadow-md shadow-amber-950/30 shrink-0"
              >
                <Plus className="w-4 h-4 stroke-[2.5]" />
                <span>{lang === 'pt' ? 'Adicionar à Lista' : 'Add to List'}</span>
              </button>
            </form>
          )}

          {/* Contêiner da Lista de Itens */}
          <div className="flex-1 min-h-[300px] max-h-[520px] overflow-y-auto border border-zinc-800/80 rounded-xl bg-black/40 p-2 space-y-1.5 font-mono text-xs">
            {loadingEntries ? (
              <div className="py-16 text-center text-zinc-500 flex flex-col items-center justify-center gap-2">
                <RefreshCw className="w-5 h-5 text-amber-500 animate-spin" />
                <span>{lang === 'pt' ? 'Carregando lista de IPs...' : 'Loading IP list...'}</span>
              </div>
            ) : filteredEntries.length === 0 ? (
              <div className="py-16 text-center text-zinc-500 flex flex-col items-center justify-center space-y-2">
                <Layers className="w-8 h-8 text-zinc-700" />
                <div className="text-zinc-400 font-semibold">
                  {searchQuery
                    ? lang === 'pt'
                      ? 'Nenhum item corresponde à busca.'
                      : 'No items match your search.'
                    : lang === 'pt'
                    ? 'Lista de IPSet vazia.'
                    : 'IPSet list is empty.'}
                </div>
                {isAdmin && !searchQuery && (
                  <div className="text-zinc-600 text-[11px]">
                    {lang === 'pt'
                      ? 'Digite um IP ou CIDR no campo acima e pressione Enter para adicionar.'
                      : 'Enter an IP or CIDR in the field above and press Enter to add.'}
                  </div>
                )}
              </div>
            ) : (
              filteredEntries.map((val, idx) => {
                const originalIdx = entries.indexOf(val);
                const isEditing = editingIndex === originalIdx;
                const isSubnet = val.includes('/');

                return (
                  <div
                    key={`${val}_${idx}`}
                    className="p-2.5 rounded-lg border border-zinc-800/80 bg-zinc-950 hover:bg-zinc-900/60 transition flex items-center justify-between gap-2 group"
                  >
                    {/* Index & Valor */}
                    <div className="flex items-center gap-3 flex-1 min-w-0">
                      <span className="text-[11px] text-zinc-600 font-bold w-7 shrink-0 text-right select-none">
                        #{idx + 1}
                      </span>

                      {isEditing ? (
                        <div className="flex items-center gap-2 flex-1">
                          <input
                            type="text"
                            autoFocus
                            value={editingValue}
                            onChange={(e) => setEditingValue(e.target.value)}
                            onKeyDown={(e) => {
                              if (e.key === 'Enter') handleSaveEdit(originalIdx);
                              if (e.key === 'Escape') setEditingIndex(null);
                            }}
                            className="flex-1 bg-black border border-amber-500 rounded px-2 py-1 text-xs text-amber-200 font-mono outline-none"
                          />
                          <button
                            type="button"
                            onClick={() => handleSaveEdit(originalIdx)}
                            className="p-1 rounded bg-amber-600 hover:bg-amber-500 text-black"
                            title="Salvar"
                          >
                            <Check className="w-3.5 h-3.5 stroke-[2.5]" />
                          </button>
                          <button
                            type="button"
                            onClick={() => setEditingIndex(null)}
                            className="p-1 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300"
                            title="Cancelar"
                          >
                            <X className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      ) : (
                        <div className="flex items-center gap-2 truncate">
                          <span className="font-bold text-zinc-100 font-mono tracking-wide select-all">
                            {val}
                          </span>
                          <span
                            className={`text-[9px] uppercase px-1.5 py-0.2 rounded border font-semibold ${
                              isSubnet
                                ? 'bg-purple-950/40 text-purple-300 border-purple-800/50'
                                : 'bg-zinc-900 text-zinc-400 border-zinc-800'
                            }`}
                          >
                            {isSubnet ? 'CIDR' : 'IP'}
                          </span>
                        </div>
                      )}
                    </div>

                    {/* Ações no Item da Lista */}
                    {!isEditing && (
                      <div className="flex items-center gap-1 shrink-0 opacity-80 group-hover:opacity-100 transition">
                        <button
                          type="button"
                          onClick={() => copySingleItem(val)}
                          className="p-1.5 rounded hover:bg-zinc-900 text-zinc-400 hover:text-zinc-200 transition"
                          title={lang === 'pt' ? 'Copiar IP' : 'Copy IP'}
                        >
                          {copiedId === val ? (
                            <Check className="w-3.5 h-3.5 text-amber-400" />
                          ) : (
                            <Copy className="w-3.5 h-3.5" />
                          )}
                        </button>

                        {isAdmin && (
                          <>
                            <button
                              type="button"
                              onClick={() => handleStartEdit(idx, val)}
                              className="p-1.5 rounded hover:bg-zinc-900 text-zinc-400 hover:text-amber-400 transition"
                              title={lang === 'pt' ? 'Editar este item' : 'Edit this item'}
                            >
                              <Edit2 className="w-3.5 h-3.5" />
                            </button>
                            <button
                              type="button"
                              onClick={() => handleDeleteEntry(val)}
                              className="p-1.5 rounded hover:bg-red-950/60 text-zinc-500 hover:text-red-400 transition"
                              title={lang === 'pt' ? 'Remover da lista' : 'Delete from list'}
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          </>
                        )}
                      </div>
                    )}
                  </div>
                );
              })
            )}
          </div>

          {/* Rodapé do Editor */}
          <div className="flex items-center justify-between text-xs font-mono text-zinc-500 pt-1">
            <span>
              {lang === 'pt' ? 'Exibindo:' : 'Showing:'} {filteredEntries.length} / {entries.length} {lang === 'pt' ? 'elementos' : 'elements'}
            </span>
            {hasUnsavedChanges && (
              <span className="text-amber-400 font-bold animate-pulse flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-amber-400" />
                <span>{lang === 'pt' ? 'Alterações locais pendentes de sincronização' : 'Pending unsaved changes'}</span>
              </span>
            )}
          </div>
        </div>
      </div>

      {/* MODAL 1: Exclusão Bloqueada (IPSet vinculado a regra ativa) */}
      {showBlockedModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 animate-fadeIn">
          <div className="bg-zinc-950 border border-amber-500/50 rounded-2xl max-w-lg w-full p-6 shadow-2xl space-y-4">
            <div className="flex items-start gap-3">
              <div className="w-10 h-10 rounded-xl bg-amber-500/10 border border-amber-500/30 flex items-center justify-center text-amber-400 shrink-0">
                <Lock className="w-6 h-6" />
              </div>
              <div className="flex-1">
                <h3 className="text-base font-bold text-white font-mono">
                  {lang === 'pt' ? 'Exclusão Bloqueada: IPSet em Uso' : 'Deletion Blocked: IPSet In Use'}
                </h3>
                <p className="text-xs text-zinc-400 mt-1">
                  {lang === 'pt'
                    ? `O conjunto '${selectedSet.name}' não pode ser excluído porque está ativamente vinculado a regra(s) de firewall no kernel:`
                    : `The set '${selectedSet.name}' cannot be deleted because it is actively referenced by firewall rule(s):`}
                </p>
              </div>
            </div>

            {/* Lista de regras vinculadas */}
            <div className="bg-black/60 border border-zinc-800 rounded-xl p-3 max-h-48 overflow-y-auto space-y-2">
              {usageInfo.bound_rules.map((ruleDesc, idx) => (
                <div
                  key={idx}
                  className="bg-zinc-900/80 border border-zinc-800/80 rounded-lg p-2 text-xs font-mono text-amber-300 flex items-center gap-2"
                >
                  <ShieldAlert className="w-4 h-4 text-amber-400 shrink-0" />
                  <span className="break-all">{ruleDesc}</span>
                </div>
              ))}
            </div>

            <div className="p-3 bg-amber-950/20 border border-amber-500/20 rounded-xl text-xs text-zinc-400 flex items-start gap-2">
              <Info className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
              <div>
                {lang === 'pt'
                  ? 'Para excluir este IPSet com segurança e sem quebrar as políticas de proteção, remova ou edite as regras vinculadas na guia "Regras & Chains" antes da exclusão.'
                  : 'To safely delete this IPSet without breaking firewall security policies, remove or edit the referencing rules in "Rules & Chains" first.'}
              </div>
            </div>

            <div className="flex justify-end pt-2">
              <button
                type="button"
                onClick={() => setShowBlockedModal(false)}
                className="bg-amber-600 hover:bg-amber-500 text-black font-bold px-4 py-2 rounded-lg text-xs font-mono transition"
              >
                {lang === 'pt' ? 'Compreendi' : 'Understood'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* MODAL 2: Confirmação de Exclusão Segura (IPSet livre de vínculos) */}
      {showDeleteModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 animate-fadeIn">
          <div className="bg-zinc-950 border border-red-900/60 rounded-2xl max-w-md w-full p-6 shadow-2xl space-y-4">
            <div className="flex items-start gap-3">
              <div className="w-10 h-10 rounded-xl bg-red-950/40 border border-red-800/60 flex items-center justify-center text-red-400 shrink-0">
                <Trash2 className="w-6 h-6" />
              </div>
              <div className="flex-1">
                <h3 className="text-base font-bold text-white font-mono">
                  {lang === 'pt' ? 'Confirmar Exclusão do IPSet' : 'Confirm IPSet Deletion'}
                </h3>
                <p className="text-xs text-zinc-400 mt-1">
                  {lang === 'pt'
                    ? `Nenhuma regra ativa está vinculada a este conjunto. A exclusão é segura no kernel.`
                    : `No active rules are linked to this set. Kernel deletion is safe.`}
                </p>
              </div>
            </div>

            <div className="p-3 bg-red-950/20 border border-red-800/30 rounded-xl text-xs text-red-300 font-mono">
              <strong>{lang === 'pt' ? 'Conjunto:' : 'Set:'}</strong> {selectedSet.name} ({entries.length}{' '}
              {lang === 'pt' ? 'elementos' : 'elements'})
              <div className="text-[11px] text-zinc-400 mt-1">
                {lang === 'pt'
                  ? 'Esta ação executará "ipset destroy" no servidor gerenciado e removerá todos os dados do banco.'
                  : 'This will execute "ipset destroy" on the managed node and remove all database records.'}
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-2">
              <button
                type="button"
                disabled={deletingSet}
                onClick={() => setShowDeleteModal(false)}
                className="bg-zinc-900 hover:bg-zinc-800 text-zinc-300 border border-zinc-800 px-3.5 py-1.5 rounded-lg text-xs font-mono transition"
              >
                {lang === 'pt' ? 'Cancelar' : 'Cancel'}
              </button>
              <button
                type="button"
                disabled={deletingSet}
                onClick={handleConfirmDelete}
                className="bg-red-900 hover:bg-red-800 text-white font-bold px-4 py-1.5 rounded-lg text-xs font-mono shadow-md shadow-red-950/50 transition flex items-center gap-1.5"
              >
                {deletingSet ? (
                  <span className="inline-block w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                ) : (
                  <Trash2 className="w-3.5 h-3.5" />
                )}
                <span>{lang === 'pt' ? 'Confirmar e Excluir' : 'Confirm Delete'}</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* MODAL 3: Criação de Novo Set */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 animate-fadeIn">
          <form
            onSubmit={handleCreateSet}
            className="bg-zinc-950 border border-zinc-800 rounded-2xl max-w-md w-full p-6 shadow-2xl space-y-4"
          >
            <h3 className="font-bold text-zinc-100 flex items-center gap-2">
              <Layers className="w-5 h-5 text-amber-400" />
              <span>{lang === 'pt' ? 'Criar Novo Conjunto IPSet' : 'Create New IPSet Collection'}</span>
            </h3>

            <div className="space-y-3 text-xs font-mono">
              <div>
                <label className="block text-zinc-400 mb-1">
                  {lang === 'pt' ? 'Nome do Set (minúsculas e sublinhados)' : 'Set Name (lowercase, underscores)'}
                </label>
                <input
                  type="text"
                  required
                  value={setName}
                  onChange={(e) => setSetName(e.target.value)}
                  placeholder="ex: blocklist_bots"
                  className="w-full bg-black border border-zinc-800 rounded-lg p-2 text-zinc-200 outline-none focus:border-amber-500"
                />
              </div>

              <div>
                <label className="block text-zinc-400 mb-1">
                  {lang === 'pt' ? 'Tipo de Estrutura no Kernel' : 'Kernel Data Structure'}
                </label>
                <select
                  value={setType}
                  onChange={(e) => setSetType(e.target.value)}
                  className="w-full bg-black border border-zinc-800 rounded-lg p-2 text-zinc-200 outline-none focus:border-amber-500"
                >
                  <option value="hash:ip">hash:ip (IPs únicos de host /32)</option>
                  <option value="hash:net">hash:net (Sub-redes CIDR /24, /16, /8)</option>
                  <option value="hash:ip,port">hash:ip,port (Pares IP + Porta TCP/UDP)</option>
                  <option value="list:set">list:set (Lista encadeada de múltiplos sets)</option>
                </select>
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={() => setShowCreateModal(false)}
                className="bg-zinc-900 hover:bg-zinc-800 text-zinc-300 border border-zinc-800 px-3.5 py-1.5 rounded-lg text-xs font-mono transition"
              >
                {lang === 'pt' ? 'Cancelar' : 'Cancel'}
              </button>
              <button
                type="submit"
                className="bg-amber-600 hover:bg-amber-500 text-black font-bold px-4 py-1.5 rounded-lg text-xs font-mono shadow-md shadow-amber-950/40 transition"
              >
                {lang === 'pt' ? 'Criar IPSet' : 'Create IPSet'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* MODAL 4: Importação em Massa (Bulk Paste) */}
      {showBulkModal && selectedSet && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 animate-fadeIn">
          <div className="bg-zinc-950 border border-zinc-800 rounded-2xl max-w-lg w-full p-6 shadow-2xl space-y-4">
            <h3 className="font-bold text-zinc-100 flex items-center gap-2">
              <Upload className="w-5 h-5 text-amber-400" />
              <span>
                {lang === 'pt'
                  ? `Colar em Lote na Lista: ${selectedSet.name}`
                  : `Bulk Paste into List: ${selectedSet.name}`}
              </span>
            </h3>

            <p className="text-xs text-zinc-400">
              {lang === 'pt'
                ? 'Cole uma lista de IPs ou sub-redes (um por linha). Os itens serão adicionados à lista de edição.'
                : 'Paste IPs or subnets (one per line). Items will be appended to the list editor.'}
            </p>

            <textarea
              rows={8}
              value={bulkText}
              onChange={(e) => setBulkText(e.target.value)}
              placeholder={'192.168.1.50\n10.0.0.0/24\n203.0.113.12\n198.51.100.88'}
              className="w-full bg-black border border-zinc-800 rounded-xl p-3 font-mono text-xs text-zinc-200 outline-none focus:border-amber-500"
            />

            <div className="flex justify-between items-center pt-2">
              <span className="text-xs text-zinc-500 font-mono">
                {bulkText.split('\n').filter((l) => l.trim() !== '').length}{' '}
                {lang === 'pt' ? 'linhas identificadas' : 'lines detected'}
              </span>
              <div className="flex gap-2">
                <button
                  onClick={() => setShowBulkModal(false)}
                  className="bg-zinc-900 hover:bg-zinc-800 text-zinc-300 border border-zinc-800 px-3 py-1.5 rounded-lg text-xs font-mono transition"
                >
                  {lang === 'pt' ? 'Cancelar' : 'Cancel'}
                </button>
                <button
                  onClick={handleApplyBulk}
                  className="bg-amber-600 hover:bg-amber-500 text-black font-bold px-4 py-1.5 rounded-lg text-xs font-mono flex items-center gap-1.5 shadow-md shadow-amber-950/40 transition"
                >
                  <Plus className="w-4 h-4 stroke-[2.5]" />
                  <span>{lang === 'pt' ? 'Adicionar Itens à Lista' : 'Add to List'}</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
