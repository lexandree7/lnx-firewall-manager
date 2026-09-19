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
	`

	_, err := d.db.Exec(schema)
	return err
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

	_, err := d.db.Exec(`
		INSERT INTO servers (id, hostname, ip_address, group_id, status, agent_version, os_distro, kernel_version,
		                     iptables_backend, ipv6_supported, drift_detected, last_canonical_hash, last_seen_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
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
			last_seen_at = CURRENT_TIMESTAMP,
			updated_at = CURRENT_TIMESTAMP
	`, s.ID, s.Hostname, s.IPAddress, s.GroupID, s.Status, s.AgentVersion, s.OSDistro, s.KernelVersion,
		s.IptablesBackend, ipv6Int, driftInt, s.LastCanonicalHash)
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
		       s.ipv6_supported, s.drift_detected, s.last_canonical_hash, s.last_seen_at, s.created_at, s.updated_at
		FROM servers s
		LEFT JOIN server_groups g ON s.group_id = g.id
		ORDER BY s.hostname ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var servers []*models.Server
	for rows.Next() {
		var s models.Server
		var grpID, hash sql.NullString
		var ipv6Int, driftInt int
		var lastSeen sql.NullTime

		err := rows.Scan(
			&s.ID, &s.Hostname, &s.IPAddress, &grpID, &s.GroupName,
			&s.Status, &s.AgentVersion, &s.OSDistro, &s.KernelVersion, &s.IptablesBackend,
			&ipv6Int, &driftInt, &hash, &lastSeen, &s.CreatedAt, &s.UpdatedAt,
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

	var logs []*models.AuditLogEntry
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

	var backups []*models.FirewallBackup
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
