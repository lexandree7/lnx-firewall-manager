import React, { useState, useEffect } from 'react';
import { Rule, Server, RuleCounterSample, IPSetItem } from '../types';
import {
  ShieldAlert,
  Plus,
  Play,
  ArrowUp,
  ArrowDown,
  Trash2,
  Copy,
  Eye,
  AlertTriangle,
  Flame,
  Zap,
  Layers,
  RefreshCw,
  X,
  Check,
  CheckCircle2,
  Sliders,
  Hash,
  Globe,
  Lock,
  ShieldCheck,
  Tag,
  ArrowRightLeft,
  ChevronDown,
} from 'lucide-react';
import { api } from '../api/client';

interface RuleManagerProps {
  servers: Server[];
  selectedServerId: string;
  onSelectServer?: (id: string) => void;
  lang: 'pt' | 'en';
  onTriggerLockout: (changeId: string, timeoutSec: number) => void;
  telemetrySamples: Record<string, RuleCounterSample>;
  userRole?: 'admin' | 'viewer';
  rulesUpdateKey?: number;
}

type TableType = 'filter' | 'nat' | 'mangle' | 'raw' | 'security';

const DEFAULT_CHAINS_BY_TABLE: Record<TableType, string[]> = {
  filter: ['INPUT', 'FORWARD', 'OUTPUT'],
  nat: ['PREROUTING', 'INPUT', 'OUTPUT', 'POSTROUTING'],
  mangle: ['PREROUTING', 'INPUT', 'FORWARD', 'OUTPUT', 'POSTROUTING'],
  raw: ['PREROUTING', 'OUTPUT'],
  security: ['INPUT', 'FORWARD', 'OUTPUT'],
};

export const RuleManager: React.FC<RuleManagerProps> = ({
  servers = [],
  selectedServerId,
  onSelectServer,
  lang,
  onTriggerLockout,
  telemetrySamples,
  userRole = 'admin',
  rulesUpdateKey = 0,
}) => {
  const safeServers = Array.isArray(servers) ? servers : [];
  const isAdmin = userRole === 'admin';
  const [selectedTable, setSelectedTable] = useState<TableType>('filter');
  const [selectedChain, setSelectedChain] = useState<string>('INPUT');
  const [chainsByTable, setChainsByTable] = useState<Record<TableType, string[]>>(DEFAULT_CHAINS_BY_TABLE);
  const [chainPolicies, setChainPolicies] = useState<Record<string, 'ACCEPT' | 'DROP'>>({
    'filter:INPUT': 'ACCEPT',
    'filter:FORWARD': 'DROP',
    'filter:OUTPUT': 'ACCEPT',
    'nat:PREROUTING': 'ACCEPT',
    'nat:INPUT': 'ACCEPT',
    'nat:OUTPUT': 'ACCEPT',
    'nat:POSTROUTING': 'ACCEPT',
    'mangle:PREROUTING': 'ACCEPT',
    'mangle:INPUT': 'ACCEPT',
    'mangle:FORWARD': 'ACCEPT',
    'mangle:OUTPUT': 'ACCEPT',
    'mangle:POSTROUTING': 'ACCEPT',
    'raw:PREROUTING': 'ACCEPT',
    'raw:OUTPUT': 'ACCEPT',
    'security:INPUT': 'ACCEPT',
    'security:FORWARD': 'ACCEPT',
    'security:OUTPUT': 'ACCEPT',
  });

  const [showAddModal, setShowAddModal] = useState(false);
  const [showAddChainModal, setShowAddChainModal] = useState(false);
  const [newChainName, setNewChainName] = useState('');
  const [showDiffModal, setShowDiffModal] = useState(false);
  const [diffContent, setDiffContent] = useState('');
  const [diffWarnings, setDiffWarnings] = useState<any[]>([]);
  const [isApplying, setIsApplying] = useState(false);
  const [isLoadingLiveRules, setIsLoadingLiveRules] = useState(false);
  const [isLiveSynced, setIsLiveSynced] = useState(false);
  const [lastSyncTime, setLastSyncTime] = useState<Date | null>(null);
  const [isModifiedLocally, setIsModifiedLocally] = useState(false);

  // Lista de IPSets disponíveis para vinculação
  const [availableIPSets, setAvailableIPSets] = useState<IPSetItem[]>([
    {
      id: 'set_default_1',
      name: 'blacklist_spammers',
      type_name: 'hash:net',
      family: 'inet',
      elements_count: 1420,
      memory_size_bytes: 45056,
    },
    {
      id: 'set_default_2',
      name: 'whitelist_office',
      type_name: 'hash:ip',
      family: 'inet',
      elements_count: 8,
      memory_size_bytes: 2048,
    },
  ]);

  // Carrega IPSets do servidor selecionado
  useEffect(() => {
    const loadSets = async () => {
      if (selectedServerId && selectedServerId !== 'ALL') {
        try {
          const sets = await api.getIPSets(selectedServerId);
          if (sets && sets.length > 0) {
            setAvailableIPSets(sets);
          }
        } catch (e) {
          console.warn('Não foi possível carregar IPSets do servidor:', e);
        }
      }
    };
    loadSets();
  }, [selectedServerId]);

  // Form state para nova regra com suporte integral a dst_ip, src_ports e IPSet
  const [ruleForm, setRuleForm] = useState({
    protocol: 'tcp',
    src_ip: '',
    dst_ip: '',
    src_ports: '',
    dst_ports: '22',
    in_interface: '',
    out_interface: '',
    state_match: 'NEW,ESTABLISHED',
    tcp_flags: '',
    limit_rate: '',
    limit_burst: 0,
    enable_ipset: false,
    match_set_name: '',
    match_set_direction: 'src',
    target: 'ACCEPT',
    target_options: '',
    comment: 'Allow SSH from management',
  });

  // Base inicial rica cobrindo múltiplas tabelas e chains
  const [rules, setRules] = useState<Rule[]>([
    // filter INPUT
    {
      id: 'r_f_in_1',
      chain_id: 'c_input',
      server_id: selectedServerId,
      table_name: 'filter',
      chain_name: 'INPUT',
      ip_version: 'v4',
      position: 1,
      protocol: 'all',
      in_interface: 'lo',
      target: 'ACCEPT',
      comment: 'Aceitar tráfego de loopback local',
      packet_counter: 124500,
      byte_counter: 9840200,
    },
    {
      id: 'r_f_in_2',
      chain_id: 'c_input',
      server_id: selectedServerId,
      table_name: 'filter',
      chain_name: 'INPUT',
      ip_version: 'v4',
      position: 2,
      protocol: 'all',
      state_match: 'RELATED,ESTABLISHED',
      target: 'ACCEPT',
      comment: 'Permitir conexões estabelecidas e relacionadas',
      packet_counter: 450210,
      byte_counter: 48920100,
    },
    {
      id: 'r_f_in_3',
      chain_id: 'c_input',
      server_id: selectedServerId,
      table_name: 'filter',
      chain_name: 'INPUT',
      ip_version: 'v4',
      position: 3,
      protocol: 'tcp',
      src_ip: '192.168.1.0/24',
      dst_ports: '22',
      target: 'ACCEPT',
      comment: 'Acesso SSH exclusivo da sub-rede administrativa',
      packet_counter: 320,
      byte_counter: 28400,
    },
    {
      id: 'r_f_in_4',
      chain_id: 'c_input',
      server_id: selectedServerId,
      table_name: 'filter',
      chain_name: 'INPUT',
      ip_version: 'v4',
      position: 4,
      protocol: 'tcp',
      dst_ports: '8443',
      target: 'ACCEPT',
      comment: 'LFM Control Plane Agent Port (mTLS/WSS)',
      packet_counter: 1240,
      byte_counter: 98000,
    },
    {
      id: 'r_f_in_5',
      chain_id: 'c_input',
      server_id: selectedServerId,
      table_name: 'filter',
      chain_name: 'INPUT',
      ip_version: 'v4',
      position: 5,
      protocol: 'all',
      match_set_name: 'blacklist_spammers',
      match_set_direction: 'src',
      target: 'DROP',
      comment: 'Bloqueio em massa via IPSet blacklist_spammers',
      packet_counter: 8420,
      byte_counter: 538880,
    },
    {
      id: 'r_f_in_6',
      chain_id: 'c_input',
      server_id: selectedServerId,
      table_name: 'filter',
      chain_name: 'INPUT',
      ip_version: 'v4',
      position: 6,
      protocol: 'all',
      target: 'DROP',
      comment: 'Drop padrão de tráfego não categorizado',
      packet_counter: 0,
      byte_counter: 0,
    },
    // filter FORWARD
    {
      id: 'r_f_fwd_1',
      chain_id: 'c_forward',
      server_id: selectedServerId,
      table_name: 'filter',
      chain_name: 'FORWARD',
      ip_version: 'v4',
      position: 1,
      protocol: 'all',
      state_match: 'RELATED,ESTABLISHED',
      target: 'ACCEPT',
      comment: 'Roteamento de conexões ativas',
      packet_counter: 34100,
      byte_counter: 15400000,
    },
    // filter OUTPUT
    {
      id: 'r_f_out_1',
      chain_id: 'c_output',
      server_id: selectedServerId,
      table_name: 'filter',
      chain_name: 'OUTPUT',
      ip_version: 'v4',
      position: 1,
      protocol: 'all',
      target: 'ACCEPT',
      comment: 'Permitir todo tráfego de saída originado localmente',
      packet_counter: 512000,
      byte_counter: 64200000,
    },
    // nat PREROUTING
    {
      id: 'r_nat_pre_1',
      chain_id: 'c_nat_pre',
      server_id: selectedServerId,
      table_name: 'nat',
      chain_name: 'PREROUTING',
      ip_version: 'v4',
      position: 1,
      protocol: 'tcp',
      dst_ports: '80',
      target: 'REDIRECT',
      target_options: '--to-ports 8080',
      comment: 'Redirecionamento HTTP para proxy reverso interno',
      packet_counter: 1200,
      byte_counter: 76800,
    },
    // nat POSTROUTING
    {
      id: 'r_nat_post_1',
      chain_id: 'c_nat_post',
      server_id: selectedServerId,
      table_name: 'nat',
      chain_name: 'POSTROUTING',
      ip_version: 'v4',
      position: 1,
      protocol: 'all',
      out_interface: 'eth0',
      src_ip: '10.0.0.0/24',
      target: 'MASQUERADE',
      comment: 'NAT Masquerade para saída WAN via eth0',
      packet_counter: 89000,
      byte_counter: 11200000,
    },
  ]);

  // Ao alternar tabela, se a chain atual não existir na nova tabela, seleciona a primeira da nova tabela
  const handleSelectTable = (tbl: TableType) => {
    setSelectedTable(tbl);
    const availableChains = chainsByTable[tbl] || DEFAULT_CHAINS_BY_TABLE[tbl];
    if (!availableChains.includes(selectedChain)) {
      setSelectedChain(availableChains[0]);
    }
  };

  // Criação de Custom Chain
  const handleAddCustomChain = (e: React.FormEvent) => {
    e.preventDefault();
    const cleanName = newChainName.trim().toUpperCase().replace(/[^A-Z0-9_-]/g, '');
    if (!cleanName) return;

    const currentChains = chainsByTable[selectedTable] || [];
    if (!currentChains.includes(cleanName)) {
      setChainsByTable({
        ...chainsByTable,
        [selectedTable]: [...currentChains, cleanName],
      });
    }
    setSelectedChain(cleanName);
    setNewChainName('');
    setShowAddChainModal(false);
  };

  // Alterna política padrão para built-in chain
  const handleTogglePolicy = () => {
    const key = `${selectedTable}:${selectedChain}`;
    const current = chainPolicies[key] || 'ACCEPT';
    const next = current === 'ACCEPT' ? 'DROP' : 'ACCEPT';
    setChainPolicies({
      ...chainPolicies,
      [key]: next,
    });
  };

  // Filtra regras estritamente para a tabela e chain selecionadas
  const visibleRules = rules.filter(
    (r) => (r.table_name || 'filter') === selectedTable && (r.chain_name || 'INPUT') === selectedChain
  );

  // Calcula a quantidade de regras por chain para exibição de badges
  const getChainRuleCount = (tbl: TableType, ch: string) => {
    return rules.filter((r) => (r.table_name || 'filter') === tbl && (r.chain_name || 'INPUT') === ch).length;
  };

  // Ordenação de regras dentro da chain atual
  const handleMove = (ruleId: string, direction: 'up' | 'down') => {
    const idx = visibleRules.findIndex((r) => r.id === ruleId);
    if (idx === -1) return;
    const targetIdx = direction === 'up' ? idx - 1 : idx + 1;
    if (targetIdx < 0 || targetIdx >= visibleRules.length) return;

    const newVisible = [...visibleRules];
    const temp = newVisible[idx];
    newVisible[idx] = newVisible[targetIdx];
    newVisible[targetIdx] = temp;

    // Atualiza posições na chain
    newVisible.forEach((r, i) => (r.position = i + 1));

    // Mescla de volta no estado geral de regras
    const otherRules = rules.filter(
      (r) => !((r.table_name || 'filter') === selectedTable && (r.chain_name || 'INPUT') === selectedChain)
    );
    setRules([...otherRules, ...newVisible]);
    setIsModifiedLocally(true);
  };

  const handleDelete = (id: string) => {
    const newRules = rules.filter((r) => r.id !== id);
    // Recalcula posições para esta chain
    const chainRules = newRules.filter(
      (r) => (r.table_name || 'filter') === selectedTable && (r.chain_name || 'INPUT') === selectedChain
    );
    chainRules.forEach((r, i) => (r.position = i + 1));
    setRules(newRules);
    setIsModifiedLocally(true);
  };

  const handleDuplicate = (rule: Rule) => {
    const copy: Rule = {
      ...rule,
      id: `r_${Date.now()}`,
      comment: `${rule.comment || ''} (Cópia)`,
      raw_rule_text: undefined,
      position: visibleRules.length + 1,
      packet_counter: 0,
      byte_counter: 0,
    };
    setRules([...rules, copy]);
    setIsModifiedLocally(true);
  };

  const handleAddRuleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const newRule: Rule = {
      id: `r_${Date.now()}`,
      chain_id: `c_${selectedChain.toLowerCase()}`,
      server_id: selectedServerId,
      table_name: selectedTable,
      chain_name: selectedChain,
      ip_version: 'v4',
      position: visibleRules.length + 1,
      protocol: ruleForm.protocol,
      src_ip: ruleForm.src_ip.trim() || undefined,
      dst_ip: ruleForm.dst_ip.trim() || undefined,
      src_ports: ruleForm.src_ports.trim() || undefined,
      dst_ports: ruleForm.dst_ports.trim() || undefined,
      in_interface: ruleForm.in_interface.trim() || undefined,
      out_interface: ruleForm.out_interface.trim() || undefined,
      state_match: ruleForm.state_match.trim() || undefined,
      tcp_flags: ruleForm.tcp_flags.trim() || undefined,
      limit_rate: ruleForm.limit_rate.trim() || undefined,
      limit_burst: ruleForm.limit_burst || undefined,
      match_set_name: ruleForm.enable_ipset && ruleForm.match_set_name ? ruleForm.match_set_name.trim() : undefined,
      match_set_direction: ruleForm.enable_ipset ? ruleForm.match_set_direction : undefined,
      target: ruleForm.target,
      target_options: ruleForm.target_options.trim() || undefined,
      comment: ruleForm.comment.trim() || undefined,
      packet_counter: 0,
      byte_counter: 0,
    };

    setRules([...rules, newRule]);
    setIsModifiedLocally(true);
    setShowAddModal(false);
  };

  // Geração completa e canônica de iptables-save cobrindo tabelas, chains e regras configuradas
  const generateIptablesSaveText = () => {
    let sb = '';
    const tablesInUse: TableType[] = ['filter', 'nat', 'mangle', 'raw', 'security'];

    for (const tbl of tablesInUse) {
      const tableRules = rules.filter((r) => (r.table_name || 'filter') === tbl);
      const tableChains = chainsByTable[tbl] || DEFAULT_CHAINS_BY_TABLE[tbl];

      // Só inclui tabelas que possuem regras ou são a tabela ativa
      if (tableRules.length === 0 && tbl !== selectedTable) {
        continue;
      }

      sb += `*${tbl}\n`;

      // Declaração de chains e políticas padrão
      for (const ch of tableChains) {
        const isBuiltin = DEFAULT_CHAINS_BY_TABLE[tbl].includes(ch);
        const policyKey = `${tbl}:${ch}`;
        const policy = isBuiltin ? chainPolicies[policyKey] || 'ACCEPT' : '-';
        sb += `:${ch} ${policy} [0:0]\n`;
      }

      // Regras ordenadas por chain e position
      for (const r of tableRules) {
        if (r.raw_rule_text) {
          sb += `-A ${r.chain_name} ${r.raw_rule_text}\n`;
          continue;
        }

        let args = `-A ${r.chain_name}`;
        if (r.protocol && r.protocol !== 'all') args += ` -p ${r.protocol}`;
        if (r.in_interface) args += ` -i ${r.in_interface}`;
        if (r.out_interface) args += ` -o ${r.out_interface}`;
        if (r.src_ip) args += ` -s ${r.src_ip}`;
        if (r.dst_ip) args += ` -d ${r.dst_ip}`;

        // Portas de Origem e Destino com suporte a multiport
        if (r.src_ports) {
          if (r.src_ports.includes(',')) {
            args += ` -m multiport --sports ${r.src_ports}`;
          } else {
            args += ` --sport ${r.src_ports}`;
          }
        }
        if (r.dst_ports) {
          if (r.dst_ports.includes(',')) {
            args += ` -m multiport --dports ${r.dst_ports}`;
          } else {
            args += ` --dport ${r.dst_ports}`;
          }
        }

        if (r.state_match) args += ` -m conntrack --ctstate ${r.state_match}`;
        if (r.match_set_name) {
          args += ` -m set --match-set ${r.match_set_name} ${r.match_set_direction || 'src'}`;
        }
        if (r.tcp_flags) args += ` --tcp-flags ${r.tcp_flags}`;
        if (r.limit_rate) {
          args += ` -m limit --limit ${r.limit_rate}`;
          if (r.limit_burst) args += ` --limit-burst ${r.limit_burst}`;
        }
        if (r.comment) args += ` -m comment --comment "${r.comment}"`;
        if (r.target) args += ` -j ${r.target}`;
        if (r.target_options) args += ` ${r.target_options}`;

        sb += `${args}\n`;
      }

      sb += 'COMMIT\n';
    }

    return sb;
  };

  const handleOpenPreview = async () => {
    const raw = generateIptablesSaveText();
    const targets = selectedServerId === 'ALL' ? safeServers.map((s) => s.id) : [selectedServerId];

    try {
      const res = await api.previewBatchRules(targets, raw);
      setDiffWarnings(res.warnings || []);
      const sampleDiff = res.diffs?.[0]?.diff || 'Nenhuma alteração detectada.';
      setDiffContent(sampleDiff);
      setShowDiffModal(true);
    } catch (err) {
      alert('Erro no preview de diff: ' + err);
    }
  };

  const handleApplyCommit = async () => {
    setIsApplying(true);
    const raw = generateIptablesSaveText();
    const targets = selectedServerId === 'ALL' ? safeServers.map((s) => s.id) : [selectedServerId];

    try {
      const res = await api.applyBatchRules(targets, raw, 30);
      setShowDiffModal(false);
      onTriggerLockout(res.change_id, 30);
      if (selectedServerId && selectedServerId !== 'ALL') {
        setTimeout(() => loadLiveRules(selectedServerId, true), 800);
      }
    } catch (err) {
      alert('Falha ao aplicar regras: ' + err);
    } finally {
      setIsApplying(false);
    }
  };

  // Carregar regras reais ativas do servidor via API
  const loadLiveRules = async (targetId: string, silent: boolean = false) => {
    if (!targetId || targetId === 'ALL') {
      if (!silent) {
        alert(lang === 'pt' ? 'Selecione um servidor específico para carregar suas regras ativas.' : 'Select a specific server to load live rules.');
      }
      setIsLiveSynced(false);
      return;
    }
    setIsLoadingLiveRules(true);
    try {
      const data = await api.getServerRules(targetId);
      if (data && data.parsed_v4 && data.parsed_v4.Tables) {
        const loadedRules: Rule[] = [];
        const loadedChains: Record<TableType, string[]> = { ...DEFAULT_CHAINS_BY_TABLE };
        const loadedPolicies: Record<string, 'ACCEPT' | 'DROP'> = { ...chainPolicies };

        Object.entries(data.parsed_v4.Tables).forEach(([tblName, tblObj]: [string, any]) => {
          const tName = tblName as TableType;
          if (tblObj.Chains) {
            const chList = Object.keys(tblObj.Chains);
            if (chList.length > 0) {
              loadedChains[tName] = Array.from(new Set([...(loadedChains[tName] || []), ...chList]));
            }
            Object.entries(tblObj.Chains).forEach(([chName, chObj]: [string, any]) => {
              if (chObj && chObj.Policy && (chObj.Policy === 'ACCEPT' || chObj.Policy === 'DROP')) {
                loadedPolicies[`${tName}:${chName}`] = chObj.Policy;
              }
            });
          }
          if (tblObj.Rules) {
            tblObj.Rules.forEach((r: any, idx: number) => {
              loadedRules.push({
                id: `r_live_${tName}_${r.Chain}_${idx}_${Date.now()}`,
                chain_id: `c_${r.Chain.toLowerCase()}`,
                server_id: targetId,
                table_name: tName,
                chain_name: r.Chain,
                ip_version: 'v4',
                position: idx + 1,
                protocol: r.Protocol || 'all',
                src_ip: r.SrcIP || undefined,
                dst_ip: r.DstIP || undefined,
                src_ports: r.SrcPorts || undefined,
                dst_ports: r.DstPorts || undefined,
                in_interface: r.InInterface || undefined,
                out_interface: r.OutInterface || undefined,
                state_match: r.StateMatch || undefined,
                tcp_flags: r.TCPFlags || undefined,
                limit_rate: r.LimitRate || undefined,
                limit_burst: r.LimitBurst || undefined,
                match_set_name: r.MatchSetName || undefined,
                match_set_direction: r.MatchSetDirection || undefined,
                target: r.Target || 'ACCEPT',
                target_options: r.TargetOptions || undefined,
                comment: r.Comment || undefined,
                raw_rule_text: r.RawText || undefined,
                packet_counter: r.PacketCounter || 0,
                byte_counter: r.ByteCounter || 0,
              });
            });
          }
        });

        setRules(loadedRules);
        setChainsByTable(loadedChains);
        setChainPolicies(loadedPolicies);
        setIsLiveSynced(true);
        setLastSyncTime(new Date());
        setIsModifiedLocally(false);

        const availableChains = loadedChains[selectedTable] || DEFAULT_CHAINS_BY_TABLE[selectedTable];
        if (!availableChains.includes(selectedChain)) {
          setSelectedChain(availableChains[0] || 'INPUT');
        }

        if (!silent) {
          alert(
            lang === 'pt'
              ? `Sucesso! ${loadedRules.length} regras sincronizadas do nó ${data.hostname || targetId}.`
              : `Success! ${loadedRules.length} rules loaded from host ${data.hostname || targetId}.`
          );
        }
      } else if (!silent) {
        alert(
          lang === 'pt'
            ? 'Não foi possível ler as regras do kernel do servidor selecionado.'
            : 'Could not fetch live kernel rules.'
        );
      }
    } catch (e) {
      if (!silent) {
        alert('Erro ao carregar regras ativas: ' + e);
      }
      console.error('Erro ao sincronizar regras:', e);
    } finally {
      setIsLoadingLiveRules(false);
    }
  };

  // Sincroniza automaticamente com o nó sempre que o servidor for selecionado ou ocorrer commit/evento
  useEffect(() => {
    if (selectedServerId && selectedServerId !== 'ALL') {
      loadLiveRules(selectedServerId, true);
    } else {
      setIsLiveSynced(false);
    }
  }, [selectedServerId, rulesUpdateKey]);

  const targetLabel =
    selectedServerId === 'ALL'
      ? `${lang === 'pt' ? 'Todos os Servidores' : 'All Servers'} (${safeServers.length})`
      : safeServers.find((s) => s.id === selectedServerId)?.hostname || selectedServerId;

  const activeChains = chainsByTable[selectedTable] || DEFAULT_CHAINS_BY_TABLE[selectedTable];
  const isCurrentChainBuiltin = DEFAULT_CHAINS_BY_TABLE[selectedTable].includes(selectedChain);
  const currentChainPolicy = chainPolicies[`${selectedTable}:${selectedChain}`] || 'ACCEPT';

  return (
    <div className="space-y-6">
      {/* Header com Alvo, Ações de Aplicação e Carregamento */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 bg-zinc-950 p-4 rounded-2xl border border-zinc-800">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono text-amber-400">
            <span>{lang === 'pt' ? 'ALVO ATUAL:' : 'CURRENT TARGET:'}</span>
            <span className="px-2 py-0.5 rounded bg-amber-500/10 border border-amber-500/30 text-amber-300 font-bold">
              {targetLabel}
            </span>
            {isLiveSynced && (
              <span className="hidden sm:inline-flex items-center gap-1 px-2 py-0.5 rounded bg-amber-500/10 border border-amber-500/30 text-amber-300 text-[11px]">
                <CheckCircle2 className="w-3 h-3 text-amber-400" />
                <span>{lang === 'pt' ? `Kernel Sincronizado (${rules.length})` : `Kernel Synced (${rules.length})`}</span>
              </span>
            )}
            {isModifiedLocally && (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-amber-500/20 border border-amber-500/40 text-amber-400 text-[11px] animate-pulse">
                <AlertTriangle className="w-3 h-3 text-amber-400" />
                <span>{lang === 'pt' ? 'Modificado Localmente' : 'Modified Locally'}</span>
              </span>
            )}
          </div>
          <h1 className="text-xl font-bold text-zinc-100 mt-1 flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-amber-400" />
            <span>{lang === 'pt' ? 'Editor Centralizado de Regras e Políticas' : 'Centralized Rules & Policy Editor'}</span>
          </h1>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {selectedServerId !== 'ALL' && (
            <button
              onClick={() => loadLiveRules(selectedServerId, false)}
              disabled={isLoadingLiveRules}
              className="bg-zinc-900 hover:bg-zinc-800 text-zinc-200 px-3.5 py-2 rounded-lg text-sm flex items-center gap-2 border border-zinc-800 transition disabled:opacity-50"
              title={lang === 'pt' ? 'Recarregar regras ativas diretamente do kernel do agente' : 'Reload live rules directly from agent kernel'}
            >
              <RefreshCw className={`w-4 h-4 text-amber-400 ${isLoadingLiveRules ? 'animate-spin' : ''}`} />
              <span>{lang === 'pt' ? 'Sincronizar Kernel' : 'Sync Live'}</span>
            </button>
          )}

          {isAdmin ? (
            <>
              <button
                onClick={() => {
                  setRuleForm({
                    protocol: 'tcp',
                    src_ip: '',
                    dst_ip: '',
                    src_ports: '',
                    dst_ports: '22',
                    in_interface: '',
                    out_interface: '',
                    state_match: 'NEW,ESTABLISHED',
                    tcp_flags: '',
                    limit_rate: '',
                    limit_burst: 0,
                    enable_ipset: false,
                    match_set_name: availableIPSets[0]?.name || '',
                    match_set_direction: 'src',
                    target: 'ACCEPT',
                    target_options: '',
                    comment: '',
                  });
                  setShowAddModal(true);
                }}
                className="bg-zinc-900 hover:bg-zinc-800 text-zinc-100 px-3.5 py-2 rounded-lg text-sm flex items-center gap-2 border border-zinc-800 transition"
              >
                <Plus className="w-4 h-4 text-amber-400" />
                <span>{lang === 'pt' ? 'Nova Regra' : 'New Rule'}</span>
              </button>

              <button
                onClick={handleOpenPreview}
                className="bg-amber-600 hover:bg-amber-500 text-black font-bold px-4 py-2 rounded-lg text-sm flex items-center gap-2 shadow-lg shadow-amber-950/40 transition"
              >
                <Play className="w-4 h-4 fill-black" />
                <span>{lang === 'pt' ? 'Revisar & Aplicar' : 'Review & Apply'}</span>
              </button>
            </>
          ) : (
            <div className="text-xs font-mono px-3 py-2 rounded-lg bg-zinc-900 border border-zinc-800 text-zinc-400 flex items-center gap-1.5">
              <Lock className="w-3.5 h-3.5 text-amber-400" />
              <span>{lang === 'pt' ? 'Somente Leitura (Viewer)' : 'Read-Only (Viewer)'}</span>
            </div>
          )}
        </div>
      </div>

      {/* Banner de Orientação para Modo 'Todos os Servidores' */}
      {selectedServerId === 'ALL' && safeServers.length > 0 && (
        <div className="bg-amber-500/10 border border-amber-500/30 p-3.5 rounded-2xl flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs font-mono">
          <div className="flex items-center gap-2 text-amber-200">
            <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
            <span>
              {lang === 'pt'
                ? 'Você está no modo Todos os Servidores (Lote). Para inspecionar e sincronizar as regras reais ativas do kernel de um firewall, selecione-o:'
                : 'You are in All Servers (Batch) mode. To inspect and sync live kernel rules from a specific firewall, select it:'}
            </span>
          </div>
          {onSelectServer && (
            <div className="flex flex-wrap items-center gap-1.5 shrink-0">
              {safeServers.map((s) => (
                <button
                  key={s.id}
                  onClick={() => onSelectServer(s.id)}
                  className="px-2.5 py-1 rounded-lg bg-zinc-900 hover:bg-zinc-800 text-zinc-200 border border-zinc-700 hover:border-amber-500/50 text-[11px] font-bold transition flex items-center gap-1"
                >
                  <span className={s.status === 'online' ? 'text-amber-400' : 'text-zinc-500'}>●</span>
                  <span>{s.hostname}</span>
                </button>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Seletores Responsivos de Tabela e Chain */}
      <div className="bg-zinc-950 border border-zinc-800 rounded-2xl p-4 shadow-xl space-y-4">
        {/* Linha 1: Seleção de Tabela */}
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-3 pb-3 border-b border-zinc-800/80">
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono text-zinc-400 uppercase tracking-wider flex items-center gap-1.5 font-bold">
              <Sliders className="w-3.5 h-3.5 text-amber-400" />
              {lang === 'pt' ? 'Tabela:' : 'Table:'}
            </span>
            <div className="flex flex-wrap gap-1.5">
              {(['filter', 'nat', 'mangle', 'raw', 'security'] as const).map((tbl) => {
                const isSelected = selectedTable === tbl;
                const totalInTbl = rules.filter((r) => (r.table_name || 'filter') === tbl).length;
                return (
                  <button
                    key={tbl}
                    onClick={() => handleSelectTable(tbl)}
                    className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition flex items-center gap-1.5 ${
                      isSelected
                        ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40 shadow-sm shadow-amber-950'
                        : 'bg-zinc-900/80 text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900 border border-transparent'
                    }`}
                  >
                    <span>*{tbl}</span>
                    <span
                      className={`text-[10px] px-1.5 py-0.2 rounded-full ${
                        isSelected ? 'bg-amber-500/30 text-amber-200' : 'bg-zinc-800 text-zinc-400'
                      }`}
                    >
                      {totalInTbl}
                    </span>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Indicador e Controle de Política da Chain Ativa */}
          <div className="flex items-center gap-2 text-xs">
            {isCurrentChainBuiltin ? (
              <div className="flex items-center gap-2 bg-black px-3 py-1.5 rounded-lg border border-zinc-800">
                <span className="text-zinc-400 font-mono">
                  {lang === 'pt' ? 'Política Padrão:' : 'Default Policy:'}
                </span>
                <span
                  className={`font-mono font-bold px-2 py-0.5 rounded text-[11px] ${
                    currentChainPolicy === 'ACCEPT'
                      ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                      : 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                  }`}
                >
                  {currentChainPolicy}
                </span>
                <button
                  onClick={handleTogglePolicy}
                  className="ml-1 text-[11px] text-zinc-400 hover:text-zinc-100 underline underline-offset-2 transition"
                >
                  {lang === 'pt' ? 'Alternar' : 'Toggle'}
                </button>
              </div>
            ) : (
              <div className="flex items-center gap-1.5 text-amber-400 bg-amber-500/10 px-3 py-1.5 rounded-lg border border-amber-500/30 text-xs">
                <Tag className="w-3.5 h-3.5" />
                <span>{lang === 'pt' ? 'Chain Personalizada' : 'User-defined Chain'}</span>
              </div>
            )}
          </div>
        </div>

        {/* Linha 2: Seleção Dinâmica de Chain e Criação de Custom Chains */}
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-1.5 w-full sm:w-auto">
            <span className="text-xs font-mono text-zinc-400 uppercase tracking-wider mr-1 font-bold">
              {lang === 'pt' ? 'Chains:' : 'Chains:'}
            </span>
            {activeChains.map((ch) => {
              const isSelected = selectedChain === ch;
              const ruleCount = getChainRuleCount(selectedTable, ch);
              return (
                <button
                  key={ch}
                  onClick={() => setSelectedChain(ch)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition flex items-center gap-1.5 ${
                    isSelected
                      ? 'bg-amber-600 text-black shadow-md shadow-amber-950/40 font-bold'
                      : 'bg-zinc-900 text-zinc-300 hover:bg-zinc-800'
                  }`}
                >
                  <span>:{ch}</span>
                  <span
                    className={`text-[10px] px-1.5 py-0.2 rounded-full font-sans ${
                      isSelected ? 'bg-black/30 text-black font-bold' : 'bg-zinc-800 text-zinc-400'
                    }`}
                  >
                    {ruleCount}
                  </span>
                </button>
              );
            })}

            {/* Botão para Adicionar Nova Chain */}
            <button
              onClick={() => setShowAddChainModal(true)}
              className="px-2.5 py-1.5 rounded-lg text-xs font-medium text-amber-400 hover:text-amber-300 hover:bg-amber-500/10 border border-amber-500/30 flex items-center gap-1 transition"
              title={lang === 'pt' ? 'Adicionar nova chain nesta tabela' : 'Add custom chain in this table'}
            >
              <Plus className="w-3.5 h-3.5" />
              <span>{lang === 'pt' ? 'Nova Chain' : 'New Chain'}</span>
            </button>
          </div>

          <div className="text-xs text-zinc-400 font-mono">
            {lang === 'pt' ? 'Visualizando:' : 'Viewing:'}{' '}
            <span className="text-amber-400 font-bold">*{selectedTable}</span>
            <span className="text-zinc-600"> / </span>
            <span className="text-amber-300 font-bold">:{selectedChain}</span>{' '}
            <span className="text-zinc-400">({visibleRules.length} {visibleRules.length === 1 ? 'regra' : 'regras'})</span>
          </div>
        </div>
      </div>

      {/* Tabela de Regras Dinâmica e Filtrada Estritamente */}
      <div className="bg-zinc-950 border border-zinc-800 rounded-2xl overflow-hidden shadow-2xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm text-zinc-300">
            <thead className="bg-zinc-900/90 text-xs text-zinc-400 uppercase font-mono border-b border-zinc-800">
              <tr>
                <th className="px-3 py-3 w-12 text-center">#</th>
                <th className="px-3 py-3">{lang === 'pt' ? 'Ação (Target)' : 'Target'}</th>
                <th className="px-3 py-3">{lang === 'pt' ? 'Proto' : 'Proto'}</th>
                <th className="px-3 py-3">{lang === 'pt' ? 'Origem / Destino' : 'Src / Dst'}</th>
                <th className="px-3 py-3">{lang === 'pt' ? 'Portas (Src / Dst)' : 'Ports (Src / Dst)'}</th>
                <th className="px-3 py-3">{lang === 'pt' ? 'Matches & IPSet' : 'Matches & IPSet'}</th>
                <th className="px-3 py-3">{lang === 'pt' ? 'Comentário' : 'Comment'}</th>
                <th className="px-3 py-3">{lang === 'pt' ? 'Contadores & Taxa' : 'Counters'}</th>
                <th className="px-3 py-3 text-right">{lang === 'pt' ? 'Ações' : 'Actions'}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/60 font-mono text-xs">
              {visibleRules.length === 0 ? (
                <tr>
                  <td colSpan={9} className="px-4 py-12 text-center">
                    <div className="flex flex-col items-center justify-center space-y-2">
                      <ShieldAlert className="w-10 h-10 text-zinc-600 mb-1" />
                      <div className="text-sm font-semibold text-zinc-300">
                        {lang === 'pt'
                          ? `Nenhuma regra configurada na chain :${selectedChain} da tabela *${selectedTable}`
                          : `No rules defined in chain :${selectedChain} of *${selectedTable}`}
                      </div>
                      <p className="text-xs text-zinc-500 max-w-md">
                        {lang === 'pt'
                          ? 'O tráfego nesta chain seguirá a política padrão da chain ou será retornado à chain chamadora.'
                          : 'Traffic in this chain will follow the default policy or return to the calling chain.'}
                      </p>
                      <button
                        onClick={() => {
                          setRuleForm({
                            protocol: 'tcp',
                            src_ip: '',
                            dst_ip: '',
                            src_ports: '',
                            dst_ports: '',
                            in_interface: '',
                            out_interface: '',
                            state_match: '',
                            tcp_flags: '',
                            limit_rate: '',
                            limit_burst: 0,
                            enable_ipset: false,
                            match_set_name: availableIPSets[0]?.name || '',
                            match_set_direction: 'src',
                            target: 'ACCEPT',
                            target_options: '',
                            comment: '',
                          });
                          setShowAddModal(true);
                        }}
                        className="mt-3 bg-amber-600/20 hover:bg-amber-600/30 text-amber-400 border border-amber-500/30 px-3.5 py-1.5 rounded-lg text-xs font-medium transition flex items-center gap-1.5"
                      >
                        <Plus className="w-3.5 h-3.5" />
                        <span>{lang === 'pt' ? 'Adicionar Regra nesta Chain' : 'Add Rule in this Chain'}</span>
                      </button>
                    </div>
                  </td>
                </tr>
              ) : (
                visibleRules.map((r, idx) => {
                  const sampleKey = `${r.table_name || 'filter'}:${r.chain_name || 'INPUT'}:${r.position}`;
                  const liveSample = telemetrySamples[sampleKey];
                  const packets = liveSample ? liveSample.packets : r.packet_counter;
                  const bytes = liveSample ? liveSample.bytes : r.byte_counter;
                  const pps = liveSample ? liveSample.rate_pps : 0;
                  const isZeroHits = packets === 0;

                  return (
                    <tr key={r.id} className="hover:bg-zinc-900/40 transition">
                      <td className="px-3 py-3 text-center text-zinc-500 font-bold">{r.position}</td>
                      <td className="px-3 py-3">
                        <span
                          className={`inline-block px-2 py-0.5 rounded text-[11px] font-bold ${
                            r.target === 'ACCEPT'
                              ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                              : r.target === 'DROP' || r.target === 'REJECT'
                              ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                              : r.target === 'MASQUERADE' || r.target === 'DNAT' || r.target === 'SNAT'
                              ? 'bg-purple-500/20 text-purple-400 border border-purple-500/30'
                              : 'bg-zinc-800 text-zinc-300 border border-zinc-700'
                          }`}
                        >
                          {r.target}
                        </span>
                        {r.target_options && (
                          <div className="text-[10px] text-zinc-400 mt-0.5 font-mono">{r.target_options}</div>
                        )}
                      </td>
                      <td className="px-3 py-3 text-zinc-300 uppercase font-semibold">{r.protocol || 'all'}</td>
                      
                      {/* Origem e Destino com suporte explícito a dst_ip */}
                      <td className="px-3 py-3 text-zinc-300">
                        <div className="flex items-center gap-1">
                          <span className="text-[10px] text-zinc-500 uppercase font-bold">src:</span>
                          <span className={r.src_ip ? 'text-zinc-100 font-semibold' : 'text-zinc-500'}>
                            {r.src_ip || 'any'}
                          </span>
                        </div>
                        <div className="flex items-center gap-1 mt-0.5">
                          <span className="text-[10px] text-zinc-500 uppercase font-bold">dst:</span>
                          <span className={r.dst_ip ? 'text-amber-300 font-semibold' : 'text-zinc-500'}>
                            {r.dst_ip || 'any'}
                          </span>
                        </div>
                      </td>

                      {/* Portas de Origem e Destino */}
                      <td className="px-3 py-3 text-zinc-300">
                        {r.src_ports && (
                          <div className="flex items-center gap-1">
                            <span className="text-[10px] text-zinc-500 font-bold">spt:</span>
                            <span className="text-amber-400">{r.src_ports}</span>
                          </div>
                        )}
                        {r.dst_ports && (
                          <div className="flex items-center gap-1 mt-0.5">
                            <span className="text-[10px] text-zinc-500 font-bold">dpt:</span>
                            <span className="text-amber-300">{r.dst_ports}</span>
                          </div>
                        )}
                        {!r.src_ports && !r.dst_ports && <span className="text-zinc-500">any</span>}
                      </td>

                      {/* Matches Avançados e IPSet Badge destacado */}
                      <td className="px-3 py-3 text-zinc-400 space-y-1">
                        {r.match_set_name && (
                          <div className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-300 border border-amber-500/30 text-[10px] font-mono shadow-sm">
                            <Layers className="w-3 h-3 text-amber-400" />
                            <span>set: <strong>{r.match_set_name}</strong> [{r.match_set_direction || 'src'}]</span>
                          </div>
                        )}
                        {r.state_match && <div className="text-[11px]">ctstate: {r.state_match}</div>}
                        {r.in_interface && <div className="text-[11px] text-zinc-300">in: {r.in_interface}</div>}
                        {r.out_interface && <div className="text-[11px] text-zinc-300">out: {r.out_interface}</div>}
                        {r.tcp_flags && <div className="text-[10px] text-amber-400/80">tcp-flags: {r.tcp_flags}</div>}
                        {r.limit_rate && <div className="text-[10px] text-sky-300">limit: {r.limit_rate}</div>}
                      </td>

                      {/* Comentário */}
                      <td className="px-3 py-3 text-zinc-400 font-sans text-xs max-w-xs truncate">
                        {r.comment || '—'}
                      </td>

                      {/* Contadores e Métricas */}
                      <td className="px-3 py-3">
                        <div className="flex items-center gap-1 text-zinc-200">
                          <span>{packets.toLocaleString()} pkts</span>
                          {pps > 0 && (
                            <span className="text-[10px] text-amber-400 font-bold flex items-center">
                              <Zap className="w-3 h-3 inline" />
                              {pps.toFixed(1)}/s
                            </span>
                          )}
                        </div>
                        <div className="text-zinc-500 text-[11px]">{(bytes / 1024).toFixed(1)} KB</div>
                        {isZeroHits && (
                          <span className="text-[9px] text-zinc-500 uppercase px-1 py-0.2 rounded bg-zinc-900 border border-zinc-800">
                            {lang === 'pt' ? 'Sem hits' : '0 hits'}
                          </span>
                        )}
                      </td>

                      {/* Ações */}
                      <td className="px-3 py-3 text-right space-x-1">
                        {isAdmin ? (
                          <>
                            <button
                              onClick={() => handleMove(r.id, 'up')}
                              disabled={idx === 0}
                              className="p-1 text-zinc-400 hover:text-white disabled:opacity-30 rounded hover:bg-zinc-900"
                              title={lang === 'pt' ? 'Mover Acima' : 'Move Up'}
                            >
                              <ArrowUp className="w-3.5 h-3.5" />
                            </button>
                            <button
                              onClick={() => handleMove(r.id, 'down')}
                              disabled={idx === visibleRules.length - 1}
                              className="p-1 text-zinc-400 hover:text-white disabled:opacity-30 rounded hover:bg-zinc-900"
                              title={lang === 'pt' ? 'Mover Abaixo' : 'Move Down'}
                            >
                              <ArrowDown className="w-3.5 h-3.5" />
                            </button>
                            <button
                              onClick={() => handleDuplicate(r)}
                              className="p-1 text-zinc-400 hover:text-white rounded hover:bg-zinc-900"
                              title={lang === 'pt' ? 'Duplicar' : 'Duplicate'}
                            >
                              <Copy className="w-3.5 h-3.5" />
                            </button>
                            <button
                              onClick={() => handleDelete(r.id)}
                              className="p-1 text-rose-400 hover:text-rose-300 rounded hover:bg-zinc-900"
                              title={lang === 'pt' ? 'Remover' : 'Delete'}
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          </>
                        ) : (
                          <span className="text-zinc-600 text-xs font-mono">--</span>
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Modal de Criação de Custom Chain */}
      {showAddChainModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <form
            onSubmit={handleAddCustomChain}
            className="bg-zinc-950 border border-zinc-800 rounded-2xl max-w-sm w-full p-6 shadow-2xl space-y-4"
          >
            <div className="flex justify-between items-center">
              <h3 className="font-bold text-zinc-100 flex items-center gap-2">
                <Tag className="w-4 h-4 text-amber-400" />
                <span>{lang === 'pt' ? 'Criar Custom Chain' : 'Create Custom Chain'}</span>
              </h3>
              <button
                type="button"
                onClick={() => setShowAddChainModal(false)}
                className="text-zinc-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="text-xs text-zinc-400">
              {lang === 'pt'
                ? `A chain será criada na tabela ativa *${selectedTable}.`
                : `Chain will be created in table *${selectedTable}.`}
            </div>

            <div>
              <label className="block text-zinc-400 text-xs mb-1 font-mono">
                {lang === 'pt' ? 'Nome da Chain (A-Z, 0-9, _, -):' : 'Chain Name:'}
              </label>
              <input
                type="text"
                required
                value={newChainName}
                onChange={(e) => setNewChainName(e.target.value)}
                placeholder="Ex: DOCKER-USER ou MY_CHAIN"
                maxLength={29}
                className="w-full bg-black border border-zinc-800 rounded-lg p-2.5 text-xs text-zinc-200 outline-none uppercase font-mono focus:border-amber-500"
              />
            </div>

            <div className="flex justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={() => setShowAddChainModal(false)}
                className="bg-zinc-900 hover:bg-zinc-800 text-zinc-300 border border-zinc-800 px-3.5 py-1.5 rounded-lg text-xs transition"
              >
                {lang === 'pt' ? 'Cancelar' : 'Cancel'}
              </button>
              <button
                type="submit"
                className="bg-amber-600 hover:bg-amber-500 text-black font-bold px-4 py-1.5 rounded-lg text-xs shadow-md shadow-amber-950/40 transition"
              >
                {lang === 'pt' ? 'Criar Chain' : 'Create Chain'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Modal Completo de Adicionar Regra com IP Destino, Porta Origem e IPSet */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 overflow-y-auto">
          <form
            onSubmit={handleAddRuleSubmit}
            className="bg-zinc-950 border border-zinc-800 rounded-2xl max-w-2xl w-full p-6 shadow-2xl space-y-4 my-8"
          >
            <div className="flex justify-between items-center pb-2 border-b border-zinc-800">
              <h3 className="font-bold text-zinc-100 flex items-center gap-2">
                <Plus className="w-5 h-5 text-amber-400" />
                <span>
                  {lang === 'pt' ? 'Adicionar Regra em' : 'Add Rule into'}{' '}
                  <span className="text-amber-400 font-mono">*{selectedTable}</span> :
                  <span className="text-amber-300 font-mono">{selectedChain}</span>
                </span>
              </h3>
              <button
                type="button"
                onClick={() => setShowAddModal(false)}
                className="text-zinc-400 hover:text-white"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs font-mono">
              {/* Seção 1: Target e Protocolo */}
              <div className="sm:col-span-2 bg-black p-3 rounded-xl border border-zinc-800/80 grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div>
                  <label className="block text-zinc-400 mb-1 font-sans font-medium">Target (Ação)</label>
                  <select
                    value={ruleForm.target}
                    onChange={(e) => setRuleForm({ ...ruleForm, target: e.target.value })}
                    className="w-full bg-zinc-900 border border-zinc-800 rounded-lg p-2 text-zinc-200 outline-none focus:border-amber-500 font-bold"
                  >
                    <option value="ACCEPT">ACCEPT</option>
                    <option value="DROP">DROP</option>
                    <option value="REJECT">REJECT</option>
                    <option value="LOG">LOG</option>
                    <option value="RETURN">RETURN</option>
                    <option value="MASQUERADE">MASQUERADE</option>
                    <option value="DNAT">DNAT</option>
                    <option value="SNAT">SNAT</option>
                    <option value="REDIRECT">REDIRECT</option>
                  </select>
                </div>

                <div>
                  <label className="block text-zinc-400 mb-1 font-sans font-medium">Protocolo</label>
                  <select
                    value={ruleForm.protocol}
                    onChange={(e) => setRuleForm({ ...ruleForm, protocol: e.target.value })}
                    className="w-full bg-zinc-900 border border-zinc-800 rounded-lg p-2 text-zinc-200 outline-none focus:border-amber-500 font-bold uppercase"
                  >
                    <option value="tcp">TCP</option>
                    <option value="udp">UDP</option>
                    <option value="icmp">ICMP</option>
                    <option value="all">ALL (Qualquer)</option>
                  </select>
                </div>

                <div>
                  <label className="block text-zinc-400 mb-1 font-sans font-medium">Target Options</label>
                  <input
                    type="text"
                    value={ruleForm.target_options}
                    onChange={(e) => setRuleForm({ ...ruleForm, target_options: e.target.value })}
                    placeholder="Ex: --to-ports 8080"
                    className="w-full bg-zinc-900 border border-zinc-800 rounded-lg p-2 text-zinc-200 outline-none focus:border-amber-500"
                  />
                </div>
              </div>

              {/* Seção 2: Endereçamento IP de Origem e Destino */}
              <div className="bg-zinc-900/60 p-3 rounded-xl border border-zinc-800 space-y-3">
                <div className="text-zinc-300 font-sans font-semibold text-xs flex items-center gap-1.5 text-amber-400">
                  <Globe className="w-3.5 h-3.5" />
                  <span>{lang === 'pt' ? 'Endereçamento IP' : 'IP Addressing'}</span>
                </div>

                <div>
                  <label className="block text-zinc-400 mb-1">
                    {lang === 'pt' ? 'IP / CIDR Origem (-s)' : 'Source IP / CIDR (-s)'}
                  </label>
                  <input
                    type="text"
                    value={ruleForm.src_ip}
                    onChange={(e) => setRuleForm({ ...ruleForm, src_ip: e.target.value })}
                    placeholder="Ex: 192.168.1.0/24 (vazio = qualquer)"
                    className="w-full bg-zinc-900 border border-zinc-800 rounded-lg p-2 text-zinc-200 outline-none focus:border-amber-500"
                  />
                </div>

                <div>
                  <label className="block text-zinc-400 mb-1">
                    {lang === 'pt' ? 'IP / CIDR Destino (-d)' : 'Destination IP / CIDR (-d)'}
                  </label>
                  <input
                    type="text"
                    value={ruleForm.dst_ip}
                    onChange={(e) => setRuleForm({ ...ruleForm, dst_ip: e.target.value })}
                    placeholder="Ex: 10.0.0.5 ou 192.168.0.0/16"
                    className="w-full bg-zinc-900 border border-zinc-800 rounded-lg p-2 text-zinc-200 outline-none focus:border-amber-500 text-amber-300"
                  />
                </div>
              </div>

              {/* Seção 3: Portas de Origem e Destino */}
              <div className="bg-zinc-900/60 p-3 rounded-xl border border-zinc-800 space-y-3">
                <div className="text-zinc-300 font-sans font-semibold text-xs flex items-center gap-1.5 text-amber-400">
                  <Hash className="w-3.5 h-3.5" />
                  <span>{lang === 'pt' ? 'Portas Lógicas' : 'Ports'}</span>
                </div>

                <div>
                  <label className="block text-zinc-400 mb-1">
                    {lang === 'pt' ? 'Porta Origem (--sport)' : 'Source Port (--sport)'}
                  </label>
                  <input
                    type="text"
                    value={ruleForm.src_ports}
                    onChange={(e) => setRuleForm({ ...ruleForm, src_ports: e.target.value })}
                    placeholder="Ex: 1024:65535 ou 53"
                    className="w-full bg-zinc-900 border border-zinc-800 rounded-lg p-2 text-zinc-200 outline-none focus:border-amber-500 text-amber-400"
                  />
                </div>

                <div>
                  <label className="block text-zinc-400 mb-1">
                    {lang === 'pt' ? 'Porta Destino (--dport)' : 'Destination Port (--dport)'}
                  </label>
                  <input
                    type="text"
                    value={ruleForm.dst_ports}
                    onChange={(e) => setRuleForm({ ...ruleForm, dst_ports: e.target.value })}
                    placeholder="Ex: 80,443 ou 22"
                    className="w-full bg-zinc-900 border border-zinc-800 rounded-lg p-2 text-zinc-200 outline-none focus:border-amber-500 text-amber-300"
                  />
                </div>
              </div>

              {/* Seção 4: Inclusão e Match por IPSET */}
              <div className="sm:col-span-2 bg-amber-950/20 border border-amber-800/40 p-3.5 rounded-xl space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Layers className="w-4 h-4 text-amber-400" />
                    <span className="font-sans font-bold text-zinc-200 text-xs">
                      {lang === 'pt' ? 'Vincular Regra a um IPSet (-m set --match-set)' : 'Match rule against IPSet (-m set)'}
                    </span>
                  </div>
                  <label className="relative inline-flex items-center cursor-pointer">
                    <input
                      type="checkbox"
                      checked={ruleForm.enable_ipset}
                      onChange={(e) => setRuleForm({ ...ruleForm, enable_ipset: e.target.checked })}
                      className="sr-only peer"
                    />
                    <div className="w-9 h-5 bg-zinc-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-zinc-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-amber-600"></div>
                  </label>
                </div>

                {ruleForm.enable_ipset && (
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-1">
                    <div>
                      <label className="block text-zinc-400 mb-1">
                        {lang === 'pt' ? 'Selecionar ou Digitar Nome do IPSet:' : 'IPSet Name:'}
                      </label>
                      <div className="relative">
                        <input
                          type="text"
                          required={ruleForm.enable_ipset}
                          value={ruleForm.match_set_name}
                          onChange={(e) => setRuleForm({ ...ruleForm, match_set_name: e.target.value })}
                          placeholder="Ex: blacklist_spammers"
                          list="available-ipsets-list"
                          className="w-full bg-black border border-amber-500/50 rounded-lg p-2 text-amber-200 outline-none focus:border-amber-400 font-bold"
                        />
                        <datalist id="available-ipsets-list">
                          {availableIPSets.map((s) => (
                            <option key={s.id} value={s.name}>
                              {s.name} ({s.type_name} - {s.elements_count} elems)
                            </option>
                          ))}
                        </datalist>
                      </div>
                    </div>

                    <div>
                      <label className="block text-zinc-400 mb-1">
                        {lang === 'pt' ? 'Direção de Match:' : 'Match Direction:'}
                      </label>
                      <select
                        value={ruleForm.match_set_direction}
                        onChange={(e) => setRuleForm({ ...ruleForm, match_set_direction: e.target.value })}
                        className="w-full bg-black border border-amber-500/50 rounded-lg p-2 text-zinc-200 outline-none focus:border-amber-400"
                      >
                        <option value="src">src (Comparar IP de Origem)</option>
                        <option value="dst">dst (Comparar IP de Destino)</option>
                        <option value="src,dst">src,dst (Comparar Origem e Destino)</option>
                        <option value="dst,dst">dst,dst (Comparar Destino duplo)</option>
                      </select>
                    </div>

                    <div className="sm:col-span-2 text-[11px] text-amber-300/80 font-sans">
                      {lang === 'pt'
                        ? 'O kernel Linux avaliará o tráfego contra a estrutura hash do IPSet com performance O(1), ideal para proteção contra ataques DDoS e botnets.'
                        : 'Linux kernel evaluates packet match in O(1) time against memory hash table, optimal for threat feeds and botnet blocking.'}
                    </div>
                  </div>
                )}
              </div>

              {/* Seção 5: Conntrack, Interfaces e Critérios Avançados */}
              <div>
                <label className="block text-zinc-400 mb-1">Conntrack State (-m conntrack)</label>
                <input
                  type="text"
                  value={ruleForm.state_match}
                  onChange={(e) => setRuleForm({ ...ruleForm, state_match: e.target.value })}
                  placeholder="Ex: NEW,ESTABLISHED"
                  className="w-full bg-black border border-zinc-800 rounded-lg p-2 text-zinc-200 outline-none focus:border-amber-500"
                />
              </div>

              <div>
                <label className="block text-zinc-400 mb-1">Interface Entrada (-i) / Saída (-o)</label>
                <div className="grid grid-cols-2 gap-2">
                  <input
                    type="text"
                    value={ruleForm.in_interface}
                    onChange={(e) => setRuleForm({ ...ruleForm, in_interface: e.target.value })}
                    placeholder="in: eth0"
                    className="w-full bg-black border border-zinc-800 rounded-lg p-2 text-zinc-200 outline-none focus:border-amber-500"
                  />
                  <input
                    type="text"
                    value={ruleForm.out_interface}
                    onChange={(e) => setRuleForm({ ...ruleForm, out_interface: e.target.value })}
                    placeholder="out: eth1"
                    className="w-full bg-black border border-zinc-800 rounded-lg p-2 text-zinc-200 outline-none focus:border-amber-500"
                  />
                </div>
              </div>

              <div>
                <label className="block text-zinc-400 mb-1">Flags TCP (--tcp-flags)</label>
                <input
                  type="text"
                  value={ruleForm.tcp_flags}
                  onChange={(e) => setRuleForm({ ...ruleForm, tcp_flags: e.target.value })}
                  placeholder="Ex: SYN,ACK,FIN,RST SYN"
                  className="w-full bg-black border border-zinc-800 rounded-lg p-2 text-zinc-200 outline-none focus:border-amber-500"
                />
              </div>

              <div>
                <label className="block text-zinc-400 mb-1">Limite de Taxa (-m limit)</label>
                <div className="grid grid-cols-2 gap-2">
                  <input
                    type="text"
                    value={ruleForm.limit_rate}
                    onChange={(e) => setRuleForm({ ...ruleForm, limit_rate: e.target.value })}
                    placeholder="Ex: 25/minute"
                    className="w-full bg-black border border-zinc-800 rounded-lg p-2 text-zinc-200 outline-none focus:border-amber-500"
                  />
                  <input
                    type="number"
                    value={ruleForm.limit_burst || ''}
                    onChange={(e) => setRuleForm({ ...ruleForm, limit_burst: parseInt(e.target.value) || 0 })}
                    placeholder="burst: 50"
                    className="w-full bg-black border border-zinc-800 rounded-lg p-2 text-zinc-200 outline-none focus:border-amber-500"
                  />
                </div>
              </div>

              <div className="sm:col-span-2">
                <label className="block text-zinc-400 mb-1 font-sans">
                  {lang === 'pt' ? 'Comentário Identificador (-m comment):' : 'Comment (-m comment):'}
                </label>
                <input
                  type="text"
                  value={ruleForm.comment}
                  onChange={(e) => setRuleForm({ ...ruleForm, comment: e.target.value })}
                  placeholder="Ex: Liberar acesso API para parceiros"
                  className="w-full bg-black border border-zinc-800 rounded-lg p-2 text-zinc-200 outline-none focus:border-amber-500 font-sans"
                />
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-3 border-t border-zinc-800">
              <button
                type="button"
                onClick={() => setShowAddModal(false)}
                className="bg-zinc-900 hover:bg-zinc-800 text-zinc-300 border border-zinc-800 px-4 py-2 rounded-lg text-sm transition"
              >
                {lang === 'pt' ? 'Cancelar' : 'Cancel'}
              </button>
              <button
                type="submit"
                className="bg-amber-600 hover:bg-amber-500 text-black font-bold px-5 py-2 rounded-lg text-sm shadow-lg shadow-amber-950/40 transition"
              >
                {lang === 'pt' ? 'Adicionar Regra' : 'Add Rule'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Modal de Diff e Confirmação de Aplicação com Proteção Contra Lockout */}
      {showDiffModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-zinc-950 border border-zinc-800 rounded-2xl max-w-2xl w-full p-6 shadow-2xl space-y-4">
            <h3 className="font-bold text-zinc-100 flex items-center gap-2">
              <Eye className="w-5 h-5 text-amber-400" />
              <span>{lang === 'pt' ? 'Revisão de Diffs & Heurísticas de Risco' : 'Diff Review & Risk Warnings'}</span>
            </h3>

            {/* Avisos de Lockout Heuristic */}
            {diffWarnings.length > 0 && (
              <div className="p-3 rounded-lg bg-rose-500/20 border border-rose-500/40 text-rose-200 text-xs space-y-1">
                <div className="font-bold flex items-center gap-1.5 text-rose-300">
                  <AlertTriangle className="w-4 h-4" />
                  <span>ALERTA DE RISCO DE LOCKOUT DETECTADO:</span>
                </div>
                {diffWarnings.map((w, i) => (
                  <div key={i}>• {w.Message}</div>
                ))}
              </div>
            )}

            <div className="text-xs text-zinc-300">
              {lang === 'pt'
                ? 'As seguintes alterações unificadas serão transmitidas ao agente com mecanismo de proteção automática (auto-rollback de 30 segundos):'
                : 'The following changes will be applied with automatic 30s rollback protection:'}
            </div>

            <div className="bg-black border border-zinc-800 rounded-xl p-3 font-mono text-xs max-h-64 overflow-y-auto whitespace-pre-wrap text-zinc-300">
              {diffContent}
            </div>

            <div className="flex justify-between items-center pt-2">
              <div className="text-xs text-zinc-400 font-mono flex items-center gap-1.5">
                <ShieldCheck className="w-4 h-4 text-amber-400" />
                <span>Rollback timer: 30s</span>
              </div>
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={() => setShowDiffModal(false)}
                  className="bg-zinc-900 hover:bg-zinc-800 text-zinc-300 border border-zinc-800 px-3.5 py-1.5 rounded-lg text-sm transition"
                >
                  {lang === 'pt' ? 'Cancelar' : 'Cancel'}
                </button>
                <button
                  type="button"
                  disabled={isApplying}
                  onClick={handleApplyCommit}
                  className="bg-amber-600 hover:bg-amber-500 text-black font-bold px-4 py-1.5 rounded-lg text-sm transition disabled:opacity-50 shadow-md shadow-amber-950/40"
                >
                  {isApplying ? 'Aplicando...' : 'Aplicar com Proteção (30s)'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
