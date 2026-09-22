package models

import (
	"time"
)

// User representa o usuário local ('root') ou federado (OIDC)
type User struct {
	ID                   string     `json:"id"`
	Username             string     `json:"username"`
	DisplayName          string     `json:"display_name"`
	Email                string     `json:"email,omitempty"`
	AuthType             string     `json:"auth_type"` // "local" ou "oidc"
	PasswordHash         string     `json:"-"`
	TOTPSecret           string     `json:"-"`
	TOTPEnabled          bool       `json:"totp_enabled"`
	Role                 string     `json:"role"` // "admin", "operator", "viewer"
	ScopedTags           []string   `json:"scoped_tags,omitempty"`
	ScopedGroups         []string   `json:"scoped_groups,omitempty"`
	FailedLoginAttempts  int        `json:"-"`
	LockedUntil          *time.Time `json:"locked_until,omitempty"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
}

// ServerGroup representa um agrupador lógico de servidores
type ServerGroup struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Server representa um nó Linux gerenciado pelo agente
type Server struct {
	ID                string     `json:"id"`
	Hostname          string     `json:"hostname"`
	IPAddress         string     `json:"ip_address"`
	GroupID           *string    `json:"group_id,omitempty"`
	GroupName         string     `json:"group_name,omitempty"`
	Status            string     `json:"status"` // "online", "offline", "drift", "applying", "error"
	AgentVersion      string     `json:"agent_version"`
	OSDistro          string     `json:"os_distro"`
	KernelVersion     string     `json:"kernel_version"`
	IptablesBackend   string     `json:"iptables_backend"` // "nftables" ou "legacy"
	IPv6Supported     bool       `json:"ipv6_supported"`
	DriftDetected     bool       `json:"drift_detected"`
	LastDriftCheck    *time.Time `json:"last_drift_check,omitempty"`
	LastCanonicalHash string     `json:"last_canonical_hash,omitempty"`
	Tags              []string   `json:"tags"`
	LastSeenAt        *time.Time `json:"last_seen_at,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

// EnrollmentToken representa o token temporário de adoção de novo nó
type EnrollmentToken struct {
	ID            string    `json:"id"`
	TokenHash     string    `json:"-"`
	RawToken      string    `json:"raw_token,omitempty"` // Apenas na criação
	TargetGroupID *string   `json:"target_group_id,omitempty"`
	InitialTags   []string  `json:"initial_tags,omitempty"`
	MaxUses       int       `json:"max_uses"`
	UsesCount     int       `json:"uses_count"`
	ExpiresAt     time.Time `json:"expires_at"`
	CreatedBy     string    `json:"created_by"`
	CreatedAt     time.Time `json:"created_at"`
}

// FirewallChain representa uma chain dentro de uma tabela
type FirewallChain struct {
	ID            string `json:"id"`
	ServerID      string `json:"server_id"`
	TableName     string `json:"table_name"` // "filter", "nat", "mangle", "raw", "security"
	ChainName     string `json:"chain_name"`
	IsBuiltin     bool   `json:"is_builtin"`
	IPVersion     string `json:"ip_version"` // "v4" ou "v6"
	DefaultPolicy string `json:"default_policy"`
	PacketCounter int64  `json:"packet_counter"`
	ByteCounter   int64  `json:"byte_counter"`
}

// FirewallRule representa uma regra estruturada de filtragem/transformação
type FirewallRule struct {
	ID                string     `json:"id"`
	ChainID           string     `json:"chain_id"`
	ServerID          string     `json:"server_id"`
	TableName         string     `json:"table_name"`
	ChainName         string     `json:"chain_name"`
	IPVersion         string     `json:"ip_version"` // "v4" ou "v6"
	Position          int        `json:"position"`
	Protocol          string     `json:"protocol"` // "tcp", "udp", "icmp", "all"
	SrcIP             string     `json:"src_ip,omitempty"`
	DstIP             string     `json:"dst_ip,omitempty"`
	InInterface       string     `json:"in_interface,omitempty"`
	OutInterface      string     `json:"out_interface,omitempty"`
	SrcPorts          string     `json:"src_ports,omitempty"`
	DstPorts          string     `json:"dst_ports,omitempty"`
	StateMatch        string     `json:"state_match,omitempty"`
	TCPFlags          string     `json:"tcp_flags,omitempty"`
	LimitRate         string     `json:"limit_rate,omitempty"`
	LimitBurst        int        `json:"limit_burst,omitempty"`
	MatchSetName      string     `json:"match_set_name,omitempty"`
	MatchSetDirection string     `json:"match_set_direction,omitempty"`
	Target            string     `json:"target"` // ACCEPT, DROP, REJECT, LOG, etc.
	TargetOptions     string     `json:"target_options,omitempty"`
	Comment           string     `json:"comment,omitempty"`
	RawRuleText       string     `json:"raw_rule_text,omitempty"`
	PacketCounter     int64      `json:"packet_counter"`
	ByteCounter       int64      `json:"byte_counter"`
	RatePPS           float64    `json:"rate_pps"`
	RateBPS           float64    `json:"rate_bps"`
	LastHitAt         *time.Time `json:"last_hit_at,omitempty"`
}

// IPSet representa um conjunto de IPs/redes gerenciado via ipset
type IPSet struct {
	ID              string    `json:"id"`
	ServerID        string    `json:"server_id"`
	Name            string    `json:"name"`
	TypeName        string    `json:"type_name"` // "hash:ip", "hash:net", etc.
	Family          string    `json:"family"`    // "inet" ou "inet6"
	MaxElem         int       `json:"maxelem"`
	TimeoutSec      int       `json:"timeout_sec"`
	CommentEnabled  bool      `json:"comment_enabled"`
	CountersEnabled bool      `json:"counters_enabled"`
	MemorySizeBytes int64     `json:"memory_size_bytes"`
	ElementsCount   int64     `json:"elements_count"`
	Entries         []string  `json:"entries,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// FirewallBackup representa um snapshot completo de um host
type FirewallBackup struct {
	ID             string    `json:"id"`
	ServerID       string    `json:"server_id"`
	ServerHostname string    `json:"server_hostname,omitempty"`
	BackupType     string    `json:"backup_type"` // "manual", "scheduled", "pre_apply_snapshot"
	Description    string    `json:"description"`
	IptablesSaveV4 string    `json:"iptables_save_v4"`
	IptablesSaveV6 string    `json:"iptables_save_v6,omitempty"`
	IPSetSave      string    `json:"ipset_save,omitempty"`
	ChecksumSHA256 string    `json:"checksum_sha256"`
	CreatedBy      string    `json:"created_by"`
	CreatedAt      time.Time `json:"created_at"`
}

// AuditLogEntry representa o registro imutável de auditoria
type AuditLogEntry struct {
	ID            string    `json:"id"`
	Timestamp     time.Time `json:"timestamp"`
	ActorID       string    `json:"actor_id"`
	ActorUsername string    `json:"actor_username"`
	IPAddress     string    `json:"ip_address"`
	Action        string    `json:"action"`
	TargetServers []string  `json:"target_servers"`
	DiffPayload   string    `json:"diff_payload,omitempty"`
	Result        string    `json:"result"` // "SUCCESS", "FAILURE", "REVERTED"
	Details       string    `json:"details,omitempty"`
}

// RuleCounterSample representa uma amostra pontual de telemetria
type RuleCounterSample struct {
	TableName    string `json:"table_name"`
	ChainName    string `json:"chain_name"`
	RulePosition int    `json:"rule_position"`
	RuleComment  string `json:"rule_comment,omitempty"`
	Packets      uint64 `json:"packets"`
	Bytes        uint64 `json:"bytes"`
	DeltaPackets uint64 `json:"delta_packets"`
	DeltaBytes   uint64 `json:"delta_bytes"`
	RatePPS      float64 `json:"rate_pps"`
	RateBPS      float64 `json:"rate_bps"`
}

// UserSession representa uma sessão ativa autenticada
type UserSession struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	IPAddress string    `json:"ip_address"`
	UserAgent string    `json:"user_agent"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

// OIDCConfig armazena os parâmetros de autenticação federada OpenID Connect
type OIDCConfig struct {
	Enabled      bool      `json:"enabled"`
	ProviderName string    `json:"provider_name"`
	IssuerURL    string    `json:"issuer_url"`
	ClientID     string    `json:"client_id"`
	ClientSecret string    `json:"client_secret,omitempty"`
	RedirectURL  string    `json:"redirect_url"`
	Scopes       string    `json:"scopes"`
	DefaultRole  string    `json:"default_role"` // "admin" ou "viewer"
	UpdatedAt    time.Time `json:"updated_at"`
}

// PasswordChangeRequest payload para alteração de senha
type PasswordChangeRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// TOTPSetupResponse dados retornados na iniciação da configuração 2FA
type TOTPSetupResponse struct {
	Secret      string `json:"secret"`
	OTPAuthURL  string `json:"otpauth_url"`
	Issuer      string `json:"issuer"`
	AccountName string `json:"account_name"`
}

// TOTPEnableRequest payload para confirmar e ativar o 2FA
type TOTPEnableRequest struct {
	Secret string `json:"secret"`
	Code   string `json:"code"`
}

// TOTPDisableRequest payload para desativar o 2FA com senha
type TOTPDisableRequest struct {
	Password string `json:"password"`
}

// NetworkInterface representa uma interface física ou virtual do servidor
type NetworkInterface struct {
	Name        string   `json:"name"`
	MAC         string   `json:"mac"`
	IPAddresses []string `json:"ips"`
	Flags       string   `json:"flags"`
	IsUp        bool     `json:"is_up"`
	IsLoopback  bool     `json:"is_loopback"`
}

