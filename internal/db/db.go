package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"lnx-firewall-manager/internal/models"
	_ "modernc.org/sqlite"
)

// DB encapsula a conexão e repositórios do banco de dados
type DB struct {
	mu sync.RWMutex
	db *sql.DB
}

// NewDB inicializa o banco SQLite ou PostgreSQL e executa migrações
func NewDB(dbPath string) (*DB, error) {
	if dbPath == "" {
		dbPath = "./data/lfm.db"
	}

	dir := filepath.Dir(dbPath)
	_ = os.MkdirAll(dir, 0700)

	sqlDB, err := sql.Open("sqlite", dbPath+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, fmt.Errorf("falha ao abrir banco de dados: %v", err)
	}

	d := &DB{db: sqlDB}
	if err := d.migrate(); err != nil {
		return nil, fmt.Errorf("falha na migração: %v", err)
	}

	return d, nil
}

func (d *DB) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		username TEXT NOT NULL UNIQUE,
		display_name TEXT NOT NULL,
		email TEXT,
		auth_type TEXT NOT NULL DEFAULT 'local',
		password_hash TEXT,
		totp_secret TEXT,
		totp_enabled INTEGER NOT NULL DEFAULT 0,
		role TEXT NOT NULL DEFAULT 'viewer',
		scoped_tags TEXT,
		scoped_groups TEXT,
		failed_login_attempts INTEGER NOT NULL DEFAULT 0,
		locked_until DATETIME NULL,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS user_sessions (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		session_token_hash TEXT NOT NULL UNIQUE,
		ip_address TEXT NOT NULL,
		user_agent TEXT,
		expires_at DATETIME NOT NULL,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS server_groups (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL UNIQUE,
		description TEXT,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS servers (
		id TEXT PRIMARY KEY,
		hostname TEXT NOT NULL,
		ip_address TEXT NOT NULL,
		group_id TEXT REFERENCES server_groups(id) ON DELETE SET NULL,
		status TEXT NOT NULL DEFAULT 'offline',
		agent_version TEXT,
		os_distro TEXT,
		kernel_version TEXT,
		iptables_backend TEXT,
		ipv6_supported INTEGER NOT NULL DEFAULT 0,
		drift_detected INTEGER NOT NULL DEFAULT 0,
		last_drift_check DATETIME NULL,
		last_canonical_hash TEXT,
		last_seen_at DATETIME NULL,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS server_tags (
		server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
		tag_name TEXT NOT NULL,
		PRIMARY KEY (server_id, tag_name)
	);

	CREATE TABLE IF NOT EXISTS enrollment_tokens (
		id TEXT PRIMARY KEY,
		token_hash TEXT NOT NULL UNIQUE,
		target_group_id TEXT,
		initial_tags TEXT,
		max_uses INTEGER NOT NULL DEFAULT 1,
		uses_count INTEGER NOT NULL DEFAULT 0,
		expires_at DATETIME NOT NULL,
		created_by TEXT,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS agent_certificates (
		id TEXT PRIMARY KEY,
		server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
		serial_number TEXT NOT NULL UNIQUE,
		fingerprint_sha256 TEXT NOT NULL UNIQUE,
		certificate_pem TEXT NOT NULL,
		revoked INTEGER NOT NULL DEFAULT 0,
		revoked_at DATETIME NULL,
		expires_at DATETIME NOT NULL,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS firewall_chains (
		id TEXT PRIMARY KEY,
		server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
		table_name TEXT NOT NULL,
		chain_name TEXT NOT NULL,
		is_builtin INTEGER NOT NULL DEFAULT 1,
		ip_version TEXT NOT NULL DEFAULT 'v4',
		default_policy TEXT DEFAULT 'ACCEPT',
		packet_counter INTEGER DEFAULT 0,
		byte_counter INTEGER DEFAULT 0,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(server_id, table_name, chain_name, ip_version)
	);

	CREATE TABLE IF NOT EXISTS firewall_rules (
		id TEXT PRIMARY KEY,
		chain_id TEXT NOT NULL,
		server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
		table_name TEXT NOT NULL,
		chain_name TEXT NOT NULL,
		ip_version TEXT NOT NULL DEFAULT 'v4',
		position INTEGER NOT NULL,
		protocol TEXT DEFAULT 'all',
		src_ip TEXT,
		dst_ip TEXT,
		in_interface TEXT,
		out_interface TEXT,
		src_ports TEXT,
		dst_ports TEXT,
		state_match TEXT,
		tcp_flags TEXT,
		limit_rate TEXT,
		limit_burst INTEGER,
		match_set_name TEXT,
		match_set_direction TEXT,
		target TEXT NOT NULL,
		target_options TEXT,
		comment TEXT,
		raw_rule_text TEXT,
		packet_counter INTEGER DEFAULT 0,
		byte_counter INTEGER DEFAULT 0,
		last_hit_at DATETIME NULL,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS ipsets (
		id TEXT PRIMARY KEY,
		server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
		name TEXT NOT NULL,
		type_name TEXT NOT NULL,
		family TEXT NOT NULL DEFAULT 'inet',
		maxelem INTEGER DEFAULT 65536,
		timeout_sec INTEGER DEFAULT 0,
		comment_enabled INTEGER DEFAULT 1,
		counters_enabled INTEGER DEFAULT 0,
		memory_size_bytes INTEGER DEFAULT 0,
		elements_count INTEGER DEFAULT 0,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(server_id, name)
	);

	CREATE TABLE IF NOT EXISTS ipset_entries (
		id TEXT PRIMARY KEY,
		ipset_id TEXT NOT NULL REFERENCES ipsets(id) ON DELETE CASCADE,
		entry_value TEXT NOT NULL,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(ipset_id, entry_value)
	);

	CREATE TABLE IF NOT EXISTS firewall_backups (
		id TEXT PRIMARY KEY,
		server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
		backup_type TEXT NOT NULL,
		description TEXT,
		iptables_save_v4 TEXT NOT NULL,
		iptables_save_v6 TEXT,
		ipset_save TEXT,
		checksum_sha256 TEXT NOT NULL,
		created_by TEXT,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS audit_logs (
		id TEXT PRIMARY KEY,
		timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		actor_id TEXT,
		actor_username TEXT NOT NULL,
		ip_address TEXT NOT NULL,
		action TEXT NOT NULL,
		target_servers TEXT NOT NULL,
		diff_payload TEXT,
		result TEXT NOT NULL,
		details TEXT
	);

	CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_logs(timestamp DESC);

	CREATE TABLE IF NOT EXISTS oidc_config (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		enabled INTEGER NOT NULL DEFAULT 0,
		provider_name TEXT NOT NULL DEFAULT 'OpenID Connect',
		issuer_url TEXT NOT NULL DEFAULT '',
		client_id TEXT NOT NULL DEFAULT '',
		client_secret TEXT NOT NULL DEFAULT '',
		redirect_url TEXT NOT NULL DEFAULT '',
		scopes TEXT NOT NULL DEFAULT 'openid profile email',
		default_role TEXT NOT NULL DEFAULT 'viewer',
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	INSERT OR IGNORE INTO oidc_config (id, enabled, provider_name, issuer_url, client_id, client_secret, redirect_url, scopes, default_role)
	VALUES (1, 0, 'OpenID Connect', '', '', '', '', 'openid profile email', 'viewer');
	`

	_, err := d.db.Exec(schema)
	if err != nil {
		return err
	}
	// Migrações incrementais seguras
	_, _ = d.db.Exec("ALTER TABLE servers ADD COLUMN network_interfaces TEXT;")
	return nil
}

// EnsureRootUser garante que o usuário root existe
func (d *DB) EnsureRootUser(passwordHash string) error {
	var count int
	err := d.db.QueryRow("SELECT COUNT(*) FROM users WHERE username = 'root'").Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		id := "usr_root_0000000000000000000000001"
		_, err = d.db.Exec(`
			INSERT INTO users (id, username, display_name, auth_type, password_hash, role, created_at, updated_at)
			VALUES (?, 'root', 'Administrador Local', 'local', ?, 'admin', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		`, id, passwordHash)
		if err != nil {
			return err
		}
		log.Printf("[DB] Usuário root inicializado com sucesso.")
	}
	return nil
}

// GetUserByUsername busca um usuário pelo username
func (d *DB) GetUserByUsername(username string) (*models.User, error) {
	row := d.db.QueryRow(`
		SELECT id, username, display_name, email, auth_type, password_hash, totp_secret, totp_enabled,
		       role, scoped_tags, scoped_groups, failed_login_attempts, locked_until, created_at, updated_at
		FROM users WHERE username = ?
	`, username)

	var u models.User
	var tagsJSON, groupsJSON, passHash, totpSec, email sql.NullString
	var totpEn int
	var locked sql.NullTime

	err := row.Scan(
		&u.ID, &u.Username, &u.DisplayName, &email, &u.AuthType, &passHash, &totpSec, &totpEn,
		&u.Role, &tagsJSON, &groupsJSON, &u.FailedLoginAttempts, &locked, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	u.Email = email.String
	u.PasswordHash = passHash.String
	u.TOTPSecret = totpSec.String
	u.TOTPEnabled = totpEn == 1
	if locked.Valid {
		u.LockedUntil = &locked.Time
	}
	if tagsJSON.Valid && tagsJSON.String != "" {
		_ = json.Unmarshal([]byte(tagsJSON.String), &u.ScopedTags)
	}
	if groupsJSON.Valid && groupsJSON.String != "" {
		_ = json.Unmarshal([]byte(groupsJSON.String), &u.ScopedGroups)
	}

	return &u, nil
}

// UpdateUserAuthStatus atualiza contadores de tentativa de login e bloqueio
func (d *DB) UpdateUserAuthStatus(id string, failedAttempts int, lockedUntil *time.Time) error {
	_, err := d.db.Exec(`
		UPDATE users SET failed_login_attempts = ?, locked_until = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?
	`, failedAttempts, lockedUntil, id)
	return err
}

// CreateSession registra uma nova sessão de usuário
func (d *DB) CreateSession(session *models.User, tokenHash, ip, userAgent string, expiresAt time.Time) (string, error) {
	id := fmt.Sprintf("sess_%d", time.Now().UnixNano())
	_, err := d.db.Exec(`
		INSERT INTO user_sessions (id, user_id, session_token_hash, ip_address, user_agent, expires_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, id, session.ID, tokenHash, ip, userAgent, expiresAt)
	return id, err
}

// ValidateSessionToken verifica se uma sessão é válida
func (d *DB) ValidateSessionToken(tokenHash string) (*models.User, error) {
	row := d.db.QueryRow(`
		SELECT u.id, u.username, u.display_name, u.email, u.auth_type, u.role, u.scoped_tags, u.scoped_groups
		FROM user_sessions s
		JOIN users u ON s.user_id = u.id
		WHERE s.session_token_hash = ? AND s.expires_at > CURRENT_TIMESTAMP
	`, tokenHash)

	var u models.User
	var tagsJSON, groupsJSON, email sql.NullString

	err := row.Scan(&u.ID, &u.Username, &u.DisplayName, &email, &u.AuthType, &u.Role, &tagsJSON, &groupsJSON)
	if err != nil {
		return nil, err
	}
	u.Email = email.String
	if tagsJSON.Valid && tagsJSON.String != "" {
		_ = json.Unmarshal([]byte(tagsJSON.String), &u.ScopedTags)
	}
	if groupsJSON.Valid && groupsJSON.String != "" {
		_ = json.Unmarshal([]byte(groupsJSON.String), &u.ScopedGroups)
	}
	return &u, nil
}

// InvalidateSession remove a sessão
func (d *DB) InvalidateSession(tokenHash string) error {
	_, err := d.db.Exec("DELETE FROM user_sessions WHERE session_token_hash = ?", tokenHash)
	return err
}

// GetUserByID busca usuário pelo ID interno
func (d *DB) GetUserByID(id string) (*models.User, error) {
	row := d.db.QueryRow(`
		SELECT id, username, display_name, email, auth_type, password_hash, totp_secret, totp_enabled,
		       role, scoped_tags, scoped_groups, failed_login_attempts, locked_until, created_at, updated_at
		FROM users WHERE id = ?
	`, id)

	var u models.User
	var tagsJSON, groupsJSON, passHash, totpSec, email sql.NullString
	var totpEn int
	var locked sql.NullTime

	err := row.Scan(
		&u.ID, &u.Username, &u.DisplayName, &email, &u.AuthType, &passHash, &totpSec, &totpEn,
		&u.Role, &tagsJSON, &groupsJSON, &u.FailedLoginAttempts, &locked, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	u.Email = email.String
	u.PasswordHash = passHash.String
	u.TOTPSecret = totpSec.String
	u.TOTPEnabled = totpEn == 1
	if locked.Valid {
		u.LockedUntil = &locked.Time
	}
	if tagsJSON.Valid && tagsJSON.String != "" {
		_ = json.Unmarshal([]byte(tagsJSON.String), &u.ScopedTags)
	}
	if groupsJSON.Valid && groupsJSON.String != "" {
		_ = json.Unmarshal([]byte(groupsJSON.String), &u.ScopedGroups)
	}

	return &u, nil
}

// UpdateUserPassword atualiza a hash da senha do usuário
func (d *DB) UpdateUserPassword(userID, passwordHash string) error {
	_, err := d.db.Exec(`
		UPDATE users SET password_hash = ?, failed_login_attempts = 0, locked_until = NULL, updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`, passwordHash, userID)
	return err
}

// UpdateUserTOTP atualiza o segredo e status do 2FA TOTP
func (d *DB) UpdateUserTOTP(userID, secret string, enabled bool) error {
	enVal := 0
	if enabled {
		enVal = 1
	}
	_, err := d.db.Exec(`
		UPDATE users SET totp_secret = ?, totp_enabled = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`, secret, enVal, userID)
	return err
}

// ListUserSessions lista sessões ativas do usuário
func (d *DB) ListUserSessions(userID string) ([]models.UserSession, error) {
	rows, err := d.db.Query(`
		SELECT id, user_id, ip_address, user_agent, expires_at, created_at
		FROM user_sessions
		WHERE user_id = ? AND expires_at > CURRENT_TIMESTAMP
		ORDER BY created_at DESC
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	sessions := make([]models.UserSession, 0)
	for rows.Next() {
		var s models.UserSession
		var ua sql.NullString
		if err := rows.Scan(&s.ID, &s.UserID, &s.IPAddress, &ua, &s.ExpiresAt, &s.CreatedAt); err != nil {
			continue
		}
		s.UserAgent = ua.String
		sessions = append(sessions, s)
	}
	return sessions, nil
}

// RevokeUserSession revoga uma sessão específica de um usuário
func (d *DB) RevokeUserSession(sessionID, userID string) error {
	_, err := d.db.Exec("DELETE FROM user_sessions WHERE id = ? AND user_id = ?", sessionID, userID)
	return err
}

// GetOIDCConfig recupera os parâmetros OIDC do sistema
func (d *DB) GetOIDCConfig() (*models.OIDCConfig, error) {
	row := d.db.QueryRow(`
		SELECT enabled, provider_name, issuer_url, client_id, client_secret, redirect_url, scopes, default_role, updated_at
		FROM oidc_config WHERE id = 1
	`)

	var cfg models.OIDCConfig
	var enabledInt int
	err := row.Scan(
		&enabledInt, &cfg.ProviderName, &cfg.IssuerURL, &cfg.ClientID,
		&cfg.ClientSecret, &cfg.RedirectURL, &cfg.Scopes, &cfg.DefaultRole, &cfg.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return &models.OIDCConfig{
				Enabled:      false,
				ProviderName: "OpenID Connect",
				Scopes:       "openid profile email",
				DefaultRole:  "viewer",
			}, nil
		}
		return nil, err
	}
	cfg.Enabled = enabledInt == 1
	if cfg.DefaultRole != "admin" && cfg.DefaultRole != "viewer" {
		cfg.DefaultRole = "viewer"
	}
	return &cfg, nil
}

// SaveOIDCConfig atualiza as configurações do provedor OIDC
func (d *DB) SaveOIDCConfig(cfg *models.OIDCConfig) error {
	enVal := 0
	if cfg.Enabled {
		enVal = 1
	}
	if cfg.DefaultRole != "admin" && cfg.DefaultRole != "viewer" {
		cfg.DefaultRole = "viewer"
	}
	if cfg.Scopes == "" {
		cfg.Scopes = "openid profile email"
	}

	_, err := d.db.Exec(`
		UPDATE oidc_config SET
			enabled = ?,
			provider_name = ?,
			issuer_url = ?,
			client_id = ?,
			client_secret = CASE WHEN ? != '' THEN ? ELSE client_secret END,
			redirect_url = ?,
			scopes = ?,
			default_role = ?,
			updated_at = CURRENT_TIMESTAMP
		WHERE id = 1
	`, enVal, cfg.ProviderName, cfg.IssuerURL, cfg.ClientID, cfg.ClientSecret, cfg.ClientSecret, cfg.RedirectURL, cfg.Scopes, cfg.DefaultRole)
	return err
}

// UpsertFederatedUser provisiona ou atualiza um usuário autenticado via OIDC
func (d *DB) UpsertFederatedUser(username, displayName, email, role string) (*models.User, error) {
	if role != "admin" && role != "viewer" {
		role = "viewer"
	}
	if username == "" {
		return nil, fmt.Errorf("username não pode ser vazio")
	}

	existing, err := d.GetUserByUsername(username)
	if err == nil && existing != nil {
		// Atualiza dados
		_, err = d.db.Exec(`
			UPDATE users SET display_name = ?, email = ?, updated_at = CURRENT_TIMESTAMP
			WHERE id = ?
		`, displayName, email, existing.ID)
		if err != nil {
			return nil, err
		}
		existing.DisplayName = displayName
		existing.Email = email
		return existing, nil
	}

	// Cria novo usuário federado
	id := fmt.Sprintf("usr_oidc_%d", time.Now().UnixNano())
	_, err = d.db.Exec(`
		INSERT INTO users (id, username, display_name, email, auth_type, role, created_at, updated_at)
		VALUES (?, ?, ?, ?, 'oidc', ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
	`, id, username, displayName, email, role)
	if err != nil {
		return nil, err
	}

	return d.GetUserByUsername(username)
}

// CreateEnrollmentToken persiste um token de enrollment
func (d *DB) CreateEnrollmentToken(token *models.EnrollmentToken) error {
	tagsJSON, _ := json.Marshal(token.InitialTags)
	_, err := d.db.Exec(`
		INSERT INTO enrollment_tokens (id, token_hash, target_group_id, initial_tags, max_uses, uses_count, expires_at, created_by)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, token.ID, token.TokenHash, token.TargetGroupID, string(tagsJSON), token.MaxUses, token.UsesCount, token.ExpiresAt, token.CreatedBy)
	return err
}

// ConsumeEnrollmentToken valida e decrementa uso do token
func (d *DB) ConsumeEnrollmentToken(tokenHash string) (*models.EnrollmentToken, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	var t models.EnrollmentToken
	var tagsJSON, grp sql.NullString

	row := d.db.QueryRow(`
		SELECT id, token_hash, target_group_id, initial_tags, max_uses, uses_count, expires_at, created_by
		FROM enrollment_tokens
		WHERE token_hash = ? AND expires_at > CURRENT_TIMESTAMP AND uses_count < max_uses
	`, tokenHash)

	err := row.Scan(&t.ID, &t.TokenHash, &grp, &tagsJSON, &t.MaxUses, &t.UsesCount, &t.ExpiresAt, &t.CreatedBy)
	if err != nil {
		return nil, fmt.Errorf("token inválido, expirado ou já utilizado")
	}

	if grp.Valid {
		t.TargetGroupID = &grp.String
	}
	if tagsJSON.Valid && tagsJSON.String != "" {
		_ = json.Unmarshal([]byte(tagsJSON.String), &t.InitialTags)
	}

	// Incrementa contagem de uso
	_, _ = d.db.Exec("UPDATE enrollment_tokens SET uses_count = uses_count + 1 WHERE id = ?", t.ID)

	return &t, nil
}

// UpsertServer registra ou atualiza um servidor
func (d *DB) UpsertServer(s *models.Server) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	ipv6Int := 0
	if s.IPv6Supported {
		ipv6Int = 1
	}
	driftInt := 0
	if s.DriftDetected {
		driftInt = 1
	}

	ifacesJSON := ""
	if len(s.NetworkInterfaces) > 0 {
		if b, err := json.Marshal(s.NetworkInterfaces); err == nil {
			ifacesJSON = string(b)
		}
	}

	_, err := d.db.Exec(`
		INSERT INTO servers (id, hostname, ip_address, group_id, status, agent_version, os_distro, kernel_version,
		                     iptables_backend, ipv6_supported, drift_detected, last_canonical_hash, network_interfaces, last_seen_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		ON CONFLICT(id) DO UPDATE SET
			hostname = excluded.hostname,
			ip_address = excluded.ip_address,
			status = excluded.status,
			agent_version = excluded.agent_version,
			os_distro = excluded.os_distro,
			kernel_version = excluded.kernel_version,
			iptables_backend = excluded.iptables_backend,
			ipv6_supported = excluded.ipv6_supported,
			drift_detected = excluded.drift_detected,
			last_canonical_hash = COALESCE(excluded.last_canonical_hash, servers.last_canonical_hash),
			network_interfaces = CASE WHEN excluded.network_interfaces != '' THEN excluded.network_interfaces ELSE servers.network_interfaces END,
			last_seen_at = CURRENT_TIMESTAMP,
			updated_at = CURRENT_TIMESTAMP
	`, s.ID, s.Hostname, s.IPAddress, s.GroupID, s.Status, s.AgentVersion, s.OSDistro, s.KernelVersion,
		s.IptablesBackend, ipv6Int, driftInt, s.LastCanonicalHash, ifacesJSON)
	if err != nil {
		return err
	}

	// Atualiza tags
	if len(s.Tags) > 0 {
		for _, tag := range s.Tags {
			_, _ = d.db.Exec("INSERT OR IGNORE INTO server_tags (server_id, tag_name) VALUES (?, ?)", s.ID, strings.TrimSpace(tag))
		}
	}

	return nil
}

// UpdateServerInterfaces persiste atomicamente a lista de interfaces do servidor
func (d *DB) UpdateServerInterfaces(id string, ifaces []models.NetworkInterface) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	b, err := json.Marshal(ifaces)
	if err != nil {
		return err
	}
	_, err = d.db.Exec("UPDATE servers SET network_interfaces = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", string(b), id)
	return err
}

// UpdateServerStatus atualiza apenas status e last_seen
func (d *DB) UpdateServerStatus(id, status string) error {
	_, err := d.db.Exec("UPDATE servers SET status = ?, last_seen_at = CURRENT_TIMESTAMP WHERE id = ?", status, id)
	return err
}

// ListServers retorna todos os servidores com tags agregadas
func (d *DB) ListServers() ([]*models.Server, error) {
	rows, err := d.db.Query(`
		SELECT s.id, s.hostname, s.ip_address, s.group_id, COALESCE(g.name, '') as group_name,
		       s.status, s.agent_version, s.os_distro, s.kernel_version, s.iptables_backend,
		       s.ipv6_supported, s.drift_detected, s.last_canonical_hash, s.last_seen_at,
		       COALESCE(s.network_interfaces, '') as network_interfaces, s.created_at, s.updated_at
		FROM servers s
		LEFT JOIN server_groups g ON s.group_id = g.id
		ORDER BY s.hostname ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	servers := make([]*models.Server, 0)
	for rows.Next() {
		var s models.Server
		var grpID, hash, ifacesJSON sql.NullString
		var ipv6Int, driftInt int
		var lastSeen sql.NullTime

		err := rows.Scan(
			&s.ID, &s.Hostname, &s.IPAddress, &grpID, &s.GroupName,
			&s.Status, &s.AgentVersion, &s.OSDistro, &s.KernelVersion, &s.IptablesBackend,
			&ipv6Int, &driftInt, &hash, &lastSeen, &ifacesJSON, &s.CreatedAt, &s.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}

		if grpID.Valid {
			s.GroupID = &grpID.String
		}
		s.LastCanonicalHash = hash.String
		s.IPv6Supported = ipv6Int == 1
		s.DriftDetected = driftInt == 1
		if lastSeen.Valid {
			s.LastSeenAt = &lastSeen.Time
		}
		if ifacesJSON.Valid && ifacesJSON.String != "" {
			_ = json.Unmarshal([]byte(ifacesJSON.String), &s.NetworkInterfaces)
		}

		servers = append(servers, &s)
	}
	rows.Close()

	// Carrega todas as tags em uma única consulta sem travar cursor
	tagRows, err := d.db.Query("SELECT server_id, tag_name FROM server_tags")
	if err == nil {
		tagsByServer := make(map[string][]string)
		for tagRows.Next() {
			var sID, tag string
			if err := tagRows.Scan(&sID, &tag); err == nil {
				tagsByServer[sID] = append(tagsByServer[sID], tag)
			}
		}
		tagRows.Close()

		for _, s := range servers {
			s.Tags = tagsByServer[s.ID]
		}
	}

	return servers, nil
}

// GetServerByID busca um servidor específico
func (d *DB) GetServerByID(id string) (*models.Server, error) {
	servers, err := d.ListServers()
	if err != nil {
		return nil, err
	}
	for _, s := range servers {
		if s.ID == id {
			return s, nil
		}
	}
	return nil, fmt.Errorf("servidor %s não encontrado", id)
}

// RecordAuditLog insere um registro imutável de auditoria
func (d *DB) RecordAuditLog(entry *models.AuditLogEntry) error {
	targetsJSON, _ := json.Marshal(entry.TargetServers)
	id := fmt.Sprintf("aud_%d", time.Now().UnixNano())
	_, err := d.db.Exec(`
		INSERT INTO audit_logs (id, timestamp, actor_id, actor_username, ip_address, action, target_servers, diff_payload, result, details)
		VALUES (?, CURRENT_TIMESTAMP, ?, ?, ?, ?, ?, ?, ?, ?)
	`, id, entry.ActorID, entry.ActorUsername, entry.IPAddress, entry.Action, string(targetsJSON), entry.DiffPayload, entry.Result, entry.Details)
	return err
}

// ListAuditLogs lista logs de auditoria
func (d *DB) ListAuditLogs(limit, offset int) ([]*models.AuditLogEntry, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := d.db.Query(`
		SELECT id, timestamp, actor_id, actor_username, ip_address, action, target_servers, diff_payload, result, details
		FROM audit_logs
		ORDER BY timestamp DESC
		LIMIT ? OFFSET ?
	`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	logs := make([]*models.AuditLogEntry, 0)
	for rows.Next() {
		var l models.AuditLogEntry
		var targetsJSON, diff, details, actorID sql.NullString

		if err := rows.Scan(&l.ID, &l.Timestamp, &actorID, &l.ActorUsername, &l.IPAddress, &l.Action, &targetsJSON, &diff, &l.Result, &details); err != nil {
			return nil, err
		}
		l.ActorID = actorID.String
		l.DiffPayload = diff.String
		l.Details = details.String
		if targetsJSON.Valid {
			_ = json.Unmarshal([]byte(targetsJSON.String), &l.TargetServers)
		}
		logs = append(logs, &l)
	}

	return logs, nil
}

// SaveBackup armazena um backup de firewall
func (d *DB) SaveBackup(b *models.FirewallBackup) error {
	_, err := d.db.Exec(`
		INSERT INTO firewall_backups (id, server_id, backup_type, description, iptables_save_v4, iptables_save_v6, ipset_save, checksum_sha256, created_by)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, b.ID, b.ServerID, b.BackupType, b.Description, b.IptablesSaveV4, b.IptablesSaveV6, b.IPSetSave, b.ChecksumSHA256, b.CreatedBy)
	return err
}

// ListBackups retorna backups de um servidor
func (d *DB) ListBackups(serverID string) ([]*models.FirewallBackup, error) {
	rows, err := d.db.Query(`
		SELECT id, server_id, backup_type, description, checksum_sha256, created_by, created_at
		FROM firewall_backups
		WHERE server_id = ?
		ORDER BY created_at DESC
	`, serverID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	backups := make([]*models.FirewallBackup, 0)
	for rows.Next() {
		var b models.FirewallBackup
		var desc, author sql.NullString
		if err := rows.Scan(&b.ID, &b.ServerID, &b.BackupType, &desc, &b.ChecksumSHA256, &author, &b.CreatedAt); err != nil {
			return nil, err
		}
		b.Description = desc.String
		b.CreatedBy = author.String
		backups = append(backups, &b)
	}

	return backups, nil
}

// GetBackupByID busca o conteúdo integral do backup
func (d *DB) GetBackupByID(backupID string) (*models.FirewallBackup, error) {
	row := d.db.QueryRow(`
		SELECT id, server_id, backup_type, description, iptables_save_v4, iptables_save_v6, ipset_save, checksum_sha256, created_by, created_at
		FROM firewall_backups WHERE id = ?
	`, backupID)

	var b models.FirewallBackup
	var desc, v6, ipset, author sql.NullString
	err := row.Scan(&b.ID, &b.ServerID, &b.BackupType, &desc, &b.IptablesSaveV4, &v6, &ipset, &b.ChecksumSHA256, &author, &b.CreatedAt)
	if err != nil {
		return nil, err
	}
	b.Description = desc.String
	b.IptablesSaveV6 = v6.String
	b.IPSetSave = ipset.String
	b.CreatedBy = author.String
	return &b, nil
}

// ListIPSets lista conjuntos ipset de um servidor
func (d *DB) ListIPSets(serverID string) ([]*models.IPSet, error) {
	rows, err := d.db.Query(`
		SELECT id, server_id, name, type_name, family, maxelem, timeout_sec, comment_enabled, counters_enabled, memory_size_bytes, elements_count, created_at, updated_at
		FROM ipsets
		WHERE server_id = ? OR server_id = 'global'
		ORDER BY name ASC
	`, serverID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	sets := make([]*models.IPSet, 0)
	for rows.Next() {
		var s models.IPSet
		var comment, counters int
		if err := rows.Scan(&s.ID, &s.ServerID, &s.Name, &s.TypeName, &s.Family, &s.MaxElem, &s.TimeoutSec, &comment, &counters, &s.MemorySizeBytes, &s.ElementsCount, &s.CreatedAt, &s.UpdatedAt); err != nil {
			return nil, err
		}
		s.CommentEnabled = comment == 1
		s.CountersEnabled = counters == 1
		sets = append(sets, &s)
	}
	return sets, nil
}

// UpsertIPSet insere ou atualiza um conjunto ipset
func (d *DB) UpsertIPSet(s *models.IPSet) error {
	commentVal := 0
	if s.CommentEnabled {
		commentVal = 1
	}
	countersVal := 0
	if s.CountersEnabled {
		countersVal = 1
	}
	_, err := d.db.Exec(`
		INSERT INTO ipsets (id, server_id, name, type_name, family, maxelem, timeout_sec, comment_enabled, counters_enabled, memory_size_bytes, elements_count, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(server_id, name) DO UPDATE SET
			type_name = excluded.type_name,
			family = excluded.family,
			elements_count = excluded.elements_count,
			updated_at = CURRENT_TIMESTAMP
	`, s.ID, s.ServerID, s.Name, s.TypeName, s.Family, s.MaxElem, s.TimeoutSec, commentVal, countersVal, s.MemorySizeBytes, s.ElementsCount)
	return err
}

// GetIPSet busca um conjunto ipset por serverID e nome
func (d *DB) GetIPSet(serverID, name string) (*models.IPSet, error) {
	row := d.db.QueryRow(`
		SELECT id, server_id, name, type_name, family, maxelem, timeout_sec, comment_enabled, counters_enabled, memory_size_bytes, elements_count, created_at, updated_at
		FROM ipsets
		WHERE (server_id = ? OR server_id = 'global') AND name = ?
		LIMIT 1
	`, serverID, name)

	var s models.IPSet
	var comment, counters int
	if err := row.Scan(&s.ID, &s.ServerID, &s.Name, &s.TypeName, &s.Family, &s.MaxElem, &s.TimeoutSec, &comment, &counters, &s.MemorySizeBytes, &s.ElementsCount, &s.CreatedAt, &s.UpdatedAt); err != nil {
		return nil, err
	}
	s.CommentEnabled = comment == 1
	s.CountersEnabled = counters == 1
	return &s, nil
}

// GetIPSetEntries retorna todas as entradas registradas para um ipset
func (d *DB) GetIPSetEntries(ipsetID string) ([]string, error) {
	rows, err := d.db.Query(`
		SELECT entry_value
		FROM ipset_entries
		WHERE ipset_id = ?
		ORDER BY created_at ASC, id ASC
	`, ipsetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []string
	for rows.Next() {
		var val string
		if err := rows.Scan(&val); err == nil {
			entries = append(entries, val)
		}
	}
	if entries == nil {
		entries = []string{}
	}
	return entries, nil
}

// SaveIPSetEntries substitui a lista de entradas de um ipset atomicamente no banco
func (d *DB) SaveIPSetEntries(ipsetID string, entries []string) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec("DELETE FROM ipset_entries WHERE ipset_id = ?", ipsetID); err != nil {
		return err
	}

	stmt, err := tx.Prepare("INSERT OR IGNORE INTO ipset_entries (id, ipset_id, entry_value) VALUES (?, ?, ?)")
	if err != nil {
		return err
	}
	defer stmt.Close()

	for i, entry := range entries {
		val := strings.TrimSpace(entry)
		if val == "" {
			continue
		}
		id := fmt.Sprintf("ent_%s_%d", ipsetID, i)
		if _, err := stmt.Exec(id, ipsetID, val); err != nil {
			return err
		}
	}

	// Atualiza contagem no conjunto ipset
	if _, err := tx.Exec("UPDATE ipsets SET elements_count = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", len(entries), ipsetID); err != nil {
		return err
	}

	return tx.Commit()
}

// FindRulesUsingIPSet busca regras no banco que utilizam um determinado conjunto IPSet
func (d *DB) FindRulesUsingIPSet(serverID, setName string) ([]*models.FirewallRule, error) {
	query := `
		SELECT id, chain_id, server_id, table_name, chain_name, ip_version, position, protocol, target, match_set_name, raw_rule_text
		FROM firewall_rules
		WHERE (server_id = ? OR server_id = 'global')
		  AND (match_set_name = ? OR raw_rule_text LIKE '%' || ? || '%')
	`
	rows, err := d.db.Query(query, serverID, setName, "--match-set "+setName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []*models.FirewallRule
	for rows.Next() {
		var r models.FirewallRule
		var matchSet, rawText sql.NullString
		if err := rows.Scan(&r.ID, &r.ChainID, &r.ServerID, &r.TableName, &r.ChainName, &r.IPVersion, &r.Position, &r.Protocol, &r.Target, &matchSet, &rawText); err != nil {
			return nil, err
		}
		if matchSet.Valid {
			r.MatchSetName = matchSet.String
		}
		if rawText.Valid {
			r.RawRuleText = rawText.String
		}
		rules = append(rules, &r)
	}
	return rules, nil
}

// DeleteIPSet remove um conjunto ipset e suas entradas do banco
func (d *DB) DeleteIPSet(serverID, name string) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var setID string
	err = tx.QueryRow("SELECT id FROM ipsets WHERE (server_id = ? OR server_id = 'global') AND name = ?", serverID, name).Scan(&setID)
	if err == nil && setID != "" {
		_, _ = tx.Exec("DELETE FROM ipset_entries WHERE ipset_id = ?", setID)
		_, _ = tx.Exec("DELETE FROM ipsets WHERE id = ?", setID)
	}

	return tx.Commit()
}

