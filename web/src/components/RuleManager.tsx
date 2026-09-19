import React, { useState } from 'react';
import { Rule, Server, RuleCounterSample } from '../types';
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
} from 'lucide-react';
import { api } from '../api/client';

interface RuleManagerProps {
  servers: Server[];
  selectedServerId: string;
  lang: 'pt' | 'en';
  onTriggerLockout: (changeId: string, timeoutSec: number) => void;
  telemetrySamples: Record<string, RuleCounterSample>;
}

export const RuleManager: React.FC<RuleManagerProps> = ({
  servers,
  selectedServerId,
  lang,
  onTriggerLockout,
  telemetrySamples,
}) => {
  const [selectedTable, setSelectedTable] = useState<'filter' | 'nat' | 'mangle'>('filter');
  const [selectedChain, setSelectedChain] = useState<'INPUT' | 'OUTPUT' | 'FORWARD'>('INPUT');
  const [showAddModal, setShowAddModal] = useState(false);
  const [showDiffModal, setShowDiffModal] = useState(false);
  const [diffContent, setDiffContent] = useState('');
  const [diffWarnings, setDiffWarnings] = useState<any[]>([]);
  const [isApplying, setIsApplying] = useState(false);

  // Form state para nova regra
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
    match_set_name: '',
    match_set_direction: 'src',
    target: 'ACCEPT',
    comment: 'Allow SSH from management',
  });

  // Mock de regras locais para demonstração de edição e diff
  const [rules, setRules] = useState<Rule[]>([
    {
      id: 'r_1',
      chain_id: 'c_input',
      server_id: selectedServerId,
      table_name: 'filter',
      chain_name: 'INPUT',
      ip_version: 'v4',
      position: 1,
      protocol: 'all',
      in_interface: 'lo',
      target: 'ACCEPT',
      comment: 'Aceitar tráfego de loopback',
      packet_counter: 124500,
      byte_counter: 9840200,
    },
    {
      id: 'r_2',
      chain_id: 'c_input',
      server_id: selectedServerId,
      table_name: 'filter',
      chain_name: 'INPUT',
      ip_version: 'v4',
      position: 2,
      protocol: 'all',
      state_match: 'RELATED,ESTABLISHED',
      target: 'ACCEPT',
      comment: 'Permitir conexões existentes',
      packet_counter: 450210,
      byte_counter: 48920100,
    },
    {
      id: 'r_3',
      chain_id: 'c_input',
      server_id: selectedServerId,
      table_name: 'filter',
      chain_name: 'INPUT',
      ip_version: 'v4',
      position: 3,
      protocol: 'tcp',
      dst_ports: '22',
      target: 'ACCEPT',
      comment: 'SSH Administracao',
      packet_counter: 320,
      byte_counter: 28400,
    },
    {
      id: 'r_4',
      chain_id: 'c_input',
      server_id: selectedServerId,
      table_name: 'filter',
      chain_name: 'INPUT',
      ip_version: 'v4',
      position: 4,
      protocol: 'tcp',
      dst_ports: '8443',
      target: 'ACCEPT',
      comment: 'LFM Control Plane Agent Port',
      packet_counter: 1240,
      byte_counter: 98000,
    },
    {
      id: 'r_5',
      chain_id: 'c_input',
      server_id: selectedServerId,
      table_name: 'filter',
      chain_name: 'INPUT',
      ip_version: 'v4',
      position: 5,
      protocol: 'all',
      target: 'DROP',
      comment: 'Drop padrao do restante',
      packet_counter: 0,
      byte_counter: 0,
    },
  ]);

  const handleMove = (index: number, direction: 'up' | 'down') => {
    const newRules = [...rules];
    const targetIdx = direction === 'up' ? index - 1 : index + 1;
    if (targetIdx < 0 || targetIdx >= newRules.length) return;
    const temp = newRules[index];
    newRules[index] = newRules[targetIdx];
    newRules[targetIdx] = temp;
    // Recalcula posições
    newRules.forEach((r, i) => (r.position = i + 1));
    setRules(newRules);
  };

  const handleDelete = (id: string) => {
    setRules(rules.filter((r) => r.id !== id).map((r, i) => ({ ...r, position: i + 1 })));
  };

  const handleDuplicate = (rule: Rule) => {
    const copy: Rule = {
      ...rule,
      id: `r_${Date.now()}`,
      comment: `${rule.comment || ''} (Cópia)`,
      position: rules.length + 1,
      packet_counter: 0,
      byte_counter: 0,
    };
    setRules([...rules, copy]);
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
      position: rules.length + 1,
      ...ruleForm,
      packet_counter: 0,
      byte_counter: 0,
    };
    setRules([...rules, newRule]);
    setShowAddModal(false);
  };

  const generateIptablesSaveText = () => {
    let sb = `*${selectedTable}\n`;
    sb += `:${selectedChain} ACCEPT [0:0]\n`;
    for (const r of rules) {
      let args = `-A ${r.chain_name}`;
      if (r.protocol && r.protocol !== 'all') args += ` -p ${r.protocol}`;
      if (r.in_interface) args += ` -i ${r.in_interface}`;
      if (r.out_interface) args += ` -o ${r.out_interface}`;
      if (r.src_ip) args += ` -s ${r.src_ip}`;
      if (r.dst_ip) args += ` -d ${r.dst_ip}`;
      if (r.dst_ports) args += ` --dport ${r.dst_ports}`;
      if (r.src_ports) args += ` --sport ${r.src_ports}`;
      if (r.state_match) args += ` -m conntrack --ctstate ${r.state_match}`;
      if (r.match_set_name) args += ` -m set --match-set ${r.match_set_name} ${r.match_set_direction || 'src'}`;
      if (r.comment) args += ` -m comment --comment "${r.comment}"`;
      if (r.target) args += ` -j ${r.target}`;
      sb += `${args}\n`;
    }
    sb += 'COMMIT\n';
    return sb;
  };

  const handleOpenPreview = async () => {
    const raw = generateIptablesSaveText();
    const targets = selectedServerId === 'ALL' ? servers.map((s) => s.id) : [selectedServerId];

    try {
      const res = await api.previewBatchRules(targets, raw);
      setDiffWarnings(res.warnings || []);
      const sampleDiff = res.diffs?.[0]?.diff || 'Nenhuma alteração detectada.';
      setDiffContent(sampleDiff);
      setShowDiffModal(true);
    } catch (err) {
      alert('Erro no preview: ' + err);
    }
  };

  const handleApplyCommit = async () => {
    setIsApplying(true);
    const raw = generateIptablesSaveText();
    const targets = selectedServerId === 'ALL' ? servers.map((s) => s.id) : [selectedServerId];

    try {
      const res = await api.applyBatchRules(targets, raw, 30);
      setShowDiffModal(false);
      onTriggerLockout(res.change_id, 30);
    } catch (err) {
      alert('Falha ao aplicar regras: ' + err);
    } finally {
      setIsApplying(false);
    }
  };

  const targetLabel =
    selectedServerId === 'ALL'
      ? `${lang === 'pt' ? 'Todos os Servidores' : 'All Servers'} (${servers.length})`
      : servers.find((s) => s.id === selectedServerId)?.hostname || selectedServerId;

  return (
    <div className="space-y-6">
      {/* Header com Alvo e Ações de Aplicação */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono text-emerald-400">
            <span>{lang === 'pt' ? 'ALVO ATUAL:' : 'CURRENT TARGET:'}</span>
            <span className="px-2 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 font-bold">
              {targetLabel}
            </span>
          </div>
          <h1 className="text-xl font-bold text-slate-100 mt-1 flex items-center gap-2">
            <span>{lang === 'pt' ? 'Editor de Regras e Políticas' : 'Firewall Rules Editor'}</span>
          </h1>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowAddModal(true)}
            className="bg-slate-800 hover:bg-slate-700 text-slate-100 px-3.5 py-2 rounded-lg text-sm flex items-center gap-2 border border-slate-700 transition"
          >
            <Plus className="w-4 h-4 text-emerald-400" />
            <span>{lang === 'pt' ? 'Nova Regra' : 'New Rule'}</span>
          </button>

          <button
            onClick={handleOpenPreview}
            className="bg-emerald-600 hover:bg-emerald-500 text-white font-semibold px-4 py-2 rounded-lg text-sm flex items-center gap-2 shadow-lg shadow-emerald-900/30 transition"
          >
            <Play className="w-4 h-4 fill-white" />
            <span>{lang === 'pt' ? 'Revisar & Aplicar' : 'Review & Apply'}</span>
          </button>
        </div>
      </div>

      {/* Seletores de Tabela e Chain */}
      <div className="flex flex-wrap items-center justify-between gap-4 bg-slate-900/60 p-3 rounded-xl border border-slate-800">
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono text-slate-400 uppercase mr-1">Tabela:</span>
          {(['filter', 'nat', 'mangle'] as const).map((tbl) => (
            <button
              key={tbl}
              onClick={() => setSelectedTable(tbl)}
              className={`px-3 py-1 rounded text-xs font-mono font-medium transition ${
                selectedTable === tbl
                  ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                  : 'bg-slate-800/60 text-slate-400 hover:text-white'
              }`}
            >
              *{tbl}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs font-mono text-slate-400 uppercase mr-1">Chain:</span>
          {(['INPUT', 'OUTPUT', 'FORWARD'] as const).map((ch) => (
            <button
              key={ch}
              onClick={() => setSelectedChain(ch)}
              className={`px-3 py-1 rounded text-xs font-mono font-medium transition ${
                selectedChain === ch
                  ? 'bg-blue-500/20 text-blue-300 border border-blue-500/40'
                  : 'bg-slate-800/60 text-slate-400 hover:text-white'
              }`}
            >
              :{ch}
            </button>
          ))}
        </div>
      </div>

      {/* Tabela de Regras */}
      <div className="bg-slate-900/40 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm text-slate-300">
            <thead className="bg-slate-900/80 text-xs text-slate-400 uppercase font-mono border-b border-slate-800">
              <tr>
                <th className="px-3 py-3 w-12 text-center">#</th>
                <th className="px-3 py-3">{lang === 'pt' ? 'Ação (Target)' : 'Target'}</th>
                <th className="px-3 py-3">{lang === 'pt' ? 'Proto' : 'Proto'}</th>
                <th className="px-3 py-3">{lang === 'pt' ? 'Origem / Destino' : 'Src / Dst'}</th>
                <th className="px-3 py-3">{lang === 'pt' ? 'Portas' : 'Ports'}</th>
                <th className="px-3 py-3">{lang === 'pt' ? 'Match / Flags' : 'Matches'}</th>
                <th className="px-3 py-3">{lang === 'pt' ? 'Comentário' : 'Comment'}</th>
                <th className="px-3 py-3">{lang === 'pt' ? 'Contadores & Taxa' : 'Counters'}</th>
                <th className="px-3 py-3 text-right">{lang === 'pt' ? 'Ações' : 'Actions'}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono text-xs">
              {rules.map((r, idx) => {
                const sampleKey = `${r.table_name}:${r.chain_name}:${r.position}`;
                const liveSample = telemetrySamples[sampleKey];
                const packets = liveSample ? liveSample.packets : r.packet_counter;
                const bytes = liveSample ? liveSample.bytes : r.byte_counter;
                const pps = liveSample ? liveSample.rate_pps : 0;
                const isZeroHits = packets === 0;

                return (
                  <tr key={r.id} className="hover:bg-slate-800/30 transition">
                    <td className="px-3 py-3 text-center text-slate-500 font-bold">{r.position}</td>
                    <td className="px-3 py-3">
                      <span
                        className={`inline-block px-2 py-0.5 rounded text-[11px] font-bold ${
                          r.target === 'ACCEPT'
                            ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                            : r.target === 'DROP' || r.target === 'REJECT'
                            ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                            : 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                        }`}
                      >
                        {r.target}
                      </span>
                    </td>
                    <td className="px-3 py-3 text-slate-300 uppercase">{r.protocol || 'all'}</td>
                    <td className="px-3 py-3 text-slate-300">
                      <div>{r.src_ip ? `src: ${r.src_ip}` : 'src: any'}</div>
                      <div>{r.dst_ip ? `dst: ${r.dst_ip}` : 'dst: any'}</div>
                    </td>
                    <td className="px-3 py-3 text-slate-300">
                      {r.dst_ports ? `dpt:${r.dst_ports}` : r.src_ports ? `spt:${r.src_ports}` : 'any'}
                    </td>
                    <td className="px-3 py-3 text-slate-400">
                      {r.state_match && <div>ctstate: {r.state_match}</div>}
                      {r.in_interface && <div>in: {r.in_interface}</div>}
                      {r.match_set_name && <div>set: {r.match_set_name}</div>}
                    </td>
                    <td className="px-3 py-3 text-slate-400 font-sans text-xs max-w-xs truncate">
                      {r.comment || '—'}
                    </td>
                    <td className="px-3 py-3">
                      <div className="flex items-center gap-1 text-slate-200">
                        <span>{packets.toLocaleString()} pkts</span>
                        {pps > 0 && (
                          <span className="text-[10px] text-emerald-400 font-bold flex items-center">
                            <Zap className="w-3 h-3 inline" />
                            {pps.toFixed(1)}/s
                          </span>
                        )}
                      </div>
                      <div className="text-slate-500 text-[11px]">{(bytes / 1024).toFixed(1)} KB</div>
                      {isZeroHits && (
                        <span className="text-[9px] text-slate-500 uppercase px-1 py-0.2 rounded bg-slate-800">
                          {lang === 'pt' ? 'Sem hits' : '0 hits'}
                        </span>
                      )}
                    </td>
                    <td className="px-3 py-3 text-right space-x-1">
                      <button
                        onClick={() => handleMove(idx, 'up')}
                        disabled={idx === 0}
                        className="p-1 text-slate-400 hover:text-white disabled:opacity-30 rounded hover:bg-slate-800"
                        title={lang === 'pt' ? 'Mover Acima' : 'Move Up'}
                      >
                        <ArrowUp className="w-3.5 h-3.5" />
                      </button>
                      <button
                        onClick={() => handleMove(idx, 'down')}
                        disabled={idx === rules.length - 1}
                        className="p-1 text-slate-400 hover:text-white disabled:opacity-30 rounded hover:bg-slate-800"
                        title={lang === 'pt' ? 'Mover Abaixo' : 'Move Down'}
                      >
                        <ArrowDown className="w-3.5 h-3.5" />
                      </button>
                      <button
                        onClick={() => handleDuplicate(r)}
                        className="p-1 text-slate-400 hover:text-white rounded hover:bg-slate-800"
                        title={lang === 'pt' ? 'Duplicar' : 'Duplicate'}
                      >
                        <Copy className="w-3.5 h-3.5" />
                      </button>
                      <button
                        onClick={() => handleDelete(r.id)}
                        className="p-1 text-rose-400 hover:text-rose-300 rounded hover:bg-slate-800"
                        title={lang === 'pt' ? 'Remover' : 'Delete'}
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Modal de Nova Regra */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <form
            onSubmit={handleAddRuleSubmit}
            className="bg-slate-900 border border-slate-800 rounded-2xl max-w-lg w-full p-6 shadow-2xl space-y-4"
          >
            <h3 className="font-bold text-slate-100 flex items-center gap-2">
              <Plus className="w-5 h-5 text-emerald-400" />
              <span>{lang === 'pt' ? 'Adicionar Regra de Firewall' : 'Add Firewall Rule'}</span>
            </h3>

            <div className="grid grid-cols-2 gap-3 text-xs font-mono">
              <div>
                <label className="block text-slate-400 mb-1">Target (Ação)</label>
                <select
                  value={ruleForm.target}
                  onChange={(e) => setRuleForm({ ...ruleForm, target: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 outline-none"
                >
                  <option value="ACCEPT">ACCEPT</option>
                  <option value="DROP">DROP</option>
                  <option value="REJECT">REJECT</option>
                  <option value="LOG">LOG</option>
                  <option value="RETURN">RETURN</option>
                </select>
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Protocolo</label>
                <select
                  value={ruleForm.protocol}
                  onChange={(e) => setRuleForm({ ...ruleForm, protocol: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 outline-none"
                >
                  <option value="tcp">TCP</option>
                  <option value="udp">UDP</option>
                  <option value="icmp">ICMP</option>
                  <option value="all">ALL</option>
                </select>
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Porta Destino (dports)</label>
                <input
                  type="text"
                  value={ruleForm.dst_ports}
                  onChange={(e) => setRuleForm({ ...ruleForm, dst_ports: e.target.value })}
                  placeholder="Ex: 80,443 ou 22"
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 outline-none"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Conntrack State</label>
                <input
                  type="text"
                  value={ruleForm.state_match}
                  onChange={(e) => setRuleForm({ ...ruleForm, state_match: e.target.value })}
                  placeholder="NEW,ESTABLISHED"
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 outline-none"
                />
              </div>

              <div className="col-span-2">
                <label className="block text-slate-400 mb-1">IP Origem (CIDR)</label>
                <input
                  type="text"
                  value={ruleForm.src_ip}
                  onChange={(e) => setRuleForm({ ...ruleForm, src_ip: e.target.value })}
                  placeholder="Ex: 192.168.1.0/24 (vazio para qualquer)"
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 outline-none"
                />
              </div>

              <div className="col-span-2">
                <label className="block text-slate-400 mb-1">Comentário</label>
                <input
                  type="text"
                  value={ruleForm.comment}
                  onChange={(e) => setRuleForm({ ...ruleForm, comment: e.target.value })}
                  placeholder="Ex: Permitir HTTP e HTTPS"
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 outline-none font-sans"
                />
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={() => setShowAddModal(false)}
                className="bg-slate-800 hover:bg-slate-700 text-slate-300 px-3.5 py-1.5 rounded text-sm transition"
              >
                Cancelar
              </button>
              <button
                type="submit"
                className="bg-emerald-600 hover:bg-emerald-500 text-white font-medium px-4 py-1.5 rounded text-sm transition"
              >
                Adicionar
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Modal de Diff e Confirmação de Aplicação */}
      {showDiffModal && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-2xl w-full p-6 shadow-2xl space-y-4">
            <h3 className="font-bold text-slate-100 flex items-center gap-2">
              <Eye className="w-5 h-5 text-emerald-400" />
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

            <div className="text-xs text-slate-300">
              {lang === 'pt'
                ? 'As seguintes alterações serão enviadas para aplicação com mecanismo de proteção automática (auto-rollback de 30 segundos):'
                : 'The following changes will be applied with automatic 30s rollback protection:'}
            </div>

            <div className="bg-slate-950 border border-slate-800 rounded-xl p-3 font-mono text-xs max-h-60 overflow-y-auto whitespace-pre-wrap text-slate-300">
              {diffContent}
            </div>

            <div className="flex justify-between items-center pt-2">
              <div className="text-xs text-slate-500 font-mono">Rollback timer: 30 segundos</div>
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={() => setShowDiffModal(false)}
                  className="bg-slate-800 hover:bg-slate-700 text-slate-300 px-3.5 py-1.5 rounded text-sm transition"
                >
                  Cancelar
                </button>
                <button
                  type="button"
                  disabled={isApplying}
                  onClick={handleApplyCommit}
                  className="bg-emerald-600 hover:bg-emerald-500 text-white font-bold px-4 py-1.5 rounded text-sm transition disabled:opacity-50"
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
