export interface Server {
  id: string;
  hostname: string;
  ip_address: string;
  group_id?: string;
  group_name?: string;
  status: 'online' | 'offline' | 'drift' | 'applying';
  agent_version: string;
  os_distro: string;
  kernel_version: string;
  iptables_backend: string;
  ipv6_supported: boolean;
  drift_detected: boolean;
  last_canonical_hash?: string;
  tags: string[];
  last_seen_at?: string;
}

export interface Rule {
  id: string;
  chain_id: string;
  server_id: string;
  table_name: string;
  chain_name: string;
  ip_version: string;
  position: number;
  protocol: string;
  src_ip?: string;
  dst_ip?: string;
  in_interface?: string;
  out_interface?: string;
  src_ports?: string;
  dst_ports?: string;
  state_match?: string;
  tcp_flags?: string;
  limit_rate?: string;
  limit_burst?: number;
  match_set_name?: string;
  match_set_direction?: string;
  target: string;
  target_options?: string;
  comment?: string;
  raw_rule_text?: string;
  packet_counter: number;
  byte_counter: number;
  rate_pps?: number;
  rate_bps?: number;
}

export interface RuleCounterSample {
  table_name: string;
  chain_name: string;
  rule_position: number;
  rule_comment?: string;
  packets: number;
  bytes: number;
  delta_packets: number;
  delta_bytes: number;
  rate_pps: number;
  rate_bps: number;
}

export interface IPSetItem {
  id: string;
  name: string;
  type_name: string;
  family: string;
  elements_count: number;
  memory_size_bytes: number;
}

export interface BackupItem {
  id: string;
  server_id: string;
  server_hostname?: string;
  backup_type: string;
  description: string;
  checksum_sha256: string;
  created_by: string;
  created_at: string;
}

export interface AuditLog {
  id: string;
  timestamp: string;
  actor_username: string;
  ip_address: string;
  action: string;
  target_servers: string[];
  diff_payload?: string;
  result: string;
  details?: string;
}

export interface User {
  id: string;
  username: string;
  display_name: string;
  email?: string;
  auth_type: 'local' | 'oidc';
  totp_enabled: boolean;
  role: 'admin' | 'viewer';
  created_at: string;
  updated_at: string;
}

export interface UserSession {
  id: string;
  user_id: string;
  ip_address: string;
  user_agent?: string;
  expires_at: string;
  created_at: string;
}

export interface OIDCConfig {
  enabled: boolean;
  provider_name: string;
  issuer_url: string;
  client_id: string;
  client_secret?: string;
  redirect_url: string;
  scopes: string;
  default_role: 'admin' | 'viewer';
  updated_at?: string;
}

export interface TOTPSetupData {
  secret: string;
  otpauth_url: string;
  issuer: string;
  account_name: string;
}

export type ThemeId = 'slate' | 'ochre' | 'sage' | 'zinc';

export interface ThemeConfig {
  id: ThemeId;
  namePt: string;
  nameEn: string;
  descriptionPt: string;
  descriptionEn: string;
  previewColor: string;
  badgeBg: string;
}

export const AVAILABLE_THEMES: ThemeConfig[] = [
  {
    id: 'slate',
    namePt: 'Azul Aço Fosco (Padrão)',
    nameEn: 'Steel Slate (Default)',
    descriptionPt: 'Visual corporativo e sofisticado com tons de ardósia e azul aço fosco.',
    descriptionEn: 'Sleek corporate console with muted steel and slate accents.',
    previewColor: '#64748b',
    badgeBg: 'bg-slate-500/20 text-slate-300 border-slate-500/30',
  },
  {
    id: 'ochre',
    namePt: 'Ocre Sóbrio',
    nameEn: 'Warm Ochre',
    descriptionPt: 'Âmbar terroso fosco e suave aos olhos, elegante e sem brilhos excessivos.',
    descriptionEn: 'Refined warm amber and earthy ochre with zero harsh glare.',
    previewColor: '#c28b38',
    badgeBg: 'bg-amber-600/20 text-amber-300 border-amber-600/30',
  },
  {
    id: 'sage',
    namePt: 'Verde Sálvia Nórdico',
    nameEn: 'Nordic Sage',
    descriptionPt: 'Tons suaves de sálvia e floresta fosca, perfeito para monitoramento contínuo.',
    descriptionEn: 'Gentle organic sage and muted forest green for calm monitoring.',
    previewColor: '#52796f',
    badgeBg: 'bg-emerald-700/20 text-emerald-300 border-emerald-600/30',
  },
  {
    id: 'zinc',
    namePt: 'Titânio Monocromático',
    nameEn: 'Titanium Stealth',
    descriptionPt: 'Estética minimalista pura em grafite e titânio acetinado de alto contraste.',
    descriptionEn: 'Pure minimalist stealth aesthetic in graphite and satin titanium.',
    previewColor: '#71717a',
    badgeBg: 'bg-zinc-600/20 text-zinc-300 border-zinc-500/30',
  },
];

