package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"lnx-firewall-manager/internal/db"
	"lnx-firewall-manager/internal/models"
	"golang.org/x/crypto/argon2"
)

const (
	argonMemory      = 64 * 1024 // 64 MB
	argonIterations  = 3
	argonParallelism = 2
	argonKeyLen      = 32
	argonSaltLen     = 16
)

// AuthManager gerencia a segurança, senhas, sessões e TOTP
type AuthManager struct {
	db *db.DB
}

// NewAuthManager inicializa o gerenciador de autenticação
func NewAuthManager(database *db.DB, defaultRootPassword string) (*AuthManager, error) {
	mgr := &AuthManager{db: database}

	if defaultRootPassword == "" {
		defaultRootPassword = "admin" // Senha padrão inicial para setup
	}

	hash, err := mgr.HashPassword(defaultRootPassword)
	if err != nil {
		return nil, err
	}

	if err := database.EnsureRootUser(hash); err != nil {
		return nil, err
	}

	return mgr, nil
}

// HashPassword deriva a chave usando Argon2id
func (a *AuthManager) HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, argonIterations, argonMemory, argonParallelism, argonKeyLen)
	encoded := fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argonMemory, argonIterations, argonParallelism,
		hex.EncodeToString(salt),
		hex.EncodeToString(hash),
	)

	return encoded, nil
}

// VerifyPassword valida uma senha contra a hash Argon2id
func (a *AuthManager) VerifyPassword(password, encodedHash string) bool {
	parts := strings.Split(encodedHash, "$")
	if len(parts) < 6 || parts[1] != "argon2id" {
		return false
	}

	salt, err := hex.DecodeString(parts[4])
	if err != nil {
		return false
	}

	expectedHash, err := hex.DecodeString(parts[5])
	if err != nil {
		return false
	}

	calculatedHash := argon2.IDKey([]byte(password), salt, argonIterations, argonMemory, argonParallelism, argonKeyLen)
	return subtle.ConstantTimeCompare(calculatedHash, expectedHash) == 1
}

// GenerateTOTPSecret gera uma chave Base32 para 2FA
func (a *AuthManager) GenerateTOTPSecret() string {
	b := make([]byte, 20)
	_, _ = rand.Read(b)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}

// ValidateTOTP valida o código de 6 dígitos baseado no RFC 6238
func (a *AuthManager) ValidateTOTP(secret, code string) bool {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return false
	}

	currentEpoch := time.Now().Unix() / 30
	// Permite janela de -1, 0, +1 intervalos (90 segundos de tolerância de relógio)
	for i := -1; i <= 1; i++ {
		t := currentEpoch + int64(i)
		buf := make([]byte, 8)
		binary.BigEndian.PutUint64(buf, uint64(t))

		mac := hmac.New(sha1.New, key)
		mac.Write(buf)
		h := mac.Sum(nil)

		offset := h[len(h)-1] & 0x0F
		truncatedHash := binary.BigEndian.Uint32(h[offset : offset+4])
		truncatedHash &= 0x7FFFFFFF
		otp := truncatedHash % 1000000

		if fmt.Sprintf("%06d", otp) == strings.TrimSpace(code) {
			return true
		}
	}

	return false
}

// AuthenticateLocal processa login do usuário local (root) com proteção de força bruta
func (a *AuthManager) AuthenticateLocal(username, password, totpCode string) (*models.User, error) {
	if username != "root" {
		return nil, fmt.Errorf("apenas o usuário 'root' local é suportado")
	}

	user, err := a.db.GetUserByUsername(username)
	if err != nil {
		return nil, fmt.Errorf("usuário não encontrado")
	}

	// Verifica se a conta está temporariamente bloqueada por força bruta
	if user.LockedUntil != nil && user.LockedUntil.After(time.Now()) {
		remaining := time.Until(*user.LockedUntil).Round(time.Second)
		return nil, fmt.Errorf("conta bloqueada por excesso de tentativas. Tente novamente em %v", remaining)
	}

	// Validação da senha
	if !a.VerifyPassword(password, user.PasswordHash) {
		failed := user.FailedLoginAttempts + 1
		var lockTime *time.Time
		if failed >= 5 {
			t := time.Now().Add(15 * time.Minute)
			lockTime = &t
		}
		_ = a.db.UpdateUserAuthStatus(user.ID, failed, lockTime)
		return nil, fmt.Errorf("credenciais inválidas")
	}

	// Validação de 2FA TOTP se ativado
	if user.TOTPEnabled {
		if totpCode == "" || !a.ValidateTOTP(user.TOTPSecret, totpCode) {
			return nil, fmt.Errorf("código TOTP de 2 fatores inválido ou ausente")
		}
	}

	// Sucesso: reseta tentativas de falha
	_ = a.db.UpdateUserAuthStatus(user.ID, 0, nil)

	return user, nil
}

// GenerateSessionToken cria um token de sessão criptográfico
func (a *AuthManager) GenerateSessionToken() (string, string) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	token := hex.EncodeToString(b)
	hash := sha256.Sum256([]byte(token))
	return token, hex.EncodeToString(hash[:])
}

// HashToken calcula o SHA-256 do token
func HashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// CheckPermission verifica permissão RBAC e escopo por tags
func CheckPermission(user *models.User, requiredRole string, server *models.Server) bool {
	if user == nil {
		return false
	}

	// Admin tem permissão global irrevogável
	if user.Role == "admin" {
		return true
	}

	// Papéis hierárquicos
	roleWeights := map[string]int{
		"viewer":   1,
		"operator": 2,
		"admin":    3,
	}

	if roleWeights[user.Role] < roleWeights[requiredRole] {
		return false
	}

	// Se for operator ou viewer, checa escopo por tags se configurado
	if len(user.ScopedTags) > 0 && server != nil {
		hasMatchingTag := false
		for _, uTag := range user.ScopedTags {
			for _, sTag := range server.Tags {
				if strings.EqualFold(uTag, sTag) {
					hasMatchingTag = true
					break
				}
			}
			if hasMatchingTag {
				break
			}
		}
		if !hasMatchingTag {
			return false
		}
	}

	return true
}

// SecurityHeadersMiddleware injeta cabeçalhos de segurança HTTP (CSP, HSTS, X-Frame-Options)
func SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		next.ServeHTTP(w, r)
	})
}
