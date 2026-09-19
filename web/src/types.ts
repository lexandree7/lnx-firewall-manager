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
