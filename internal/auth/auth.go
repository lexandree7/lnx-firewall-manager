package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
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

// ChangeUserPassword valida e atualiza a senha de um usuário local
func (a *AuthManager) ChangeUserPassword(userID, currentPassword, newPassword string) error {
	if len(newPassword) < 6 {
		return fmt.Errorf("a nova senha deve possuir no mínimo 6 caracteres")
	}

	user, err := a.db.GetUserByID(userID)
	if err != nil {
		return fmt.Errorf("usuário não encontrado: %v", err)
	}

	if user.PasswordHash != "" {
		if !a.VerifyPassword(currentPassword, user.PasswordHash) {
			return fmt.Errorf("senha atual incorreta")
		}
	}

	newHash, err := a.HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("erro ao gerar hash da nova senha: %v", err)
	}

	return a.db.UpdateUserPassword(userID, newHash)
}

// SetupTOTP gera um segredo Base32 para o usuário
func (a *AuthManager) SetupTOTP(userID string) (*models.TOTPSetupResponse, error) {
	user, err := a.db.GetUserByID(userID)
	if err != nil {
		return nil, fmt.Errorf("usuário não encontrado: %v", err)
	}

	secret := a.GenerateTOTPSecret()
	account := user.Username
	issuer := "LFM"
	otpAuthURL := fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s", issuer, account, secret, issuer)

	return &models.TOTPSetupResponse{
		Secret:      secret,
		OTPAuthURL:  otpAuthURL,
		Issuer:      issuer,
		AccountName: account,
	}, nil
}

// EnableTOTP valida o código com o segredo e ativa o 2FA
func (a *AuthManager) EnableTOTP(userID, secret, code string) error {
	if !a.ValidateTOTP(secret, code) {
		return fmt.Errorf("código TOTP de 6 dígitos inválido")
	}
	return a.db.UpdateUserTOTP(userID, secret, true)
}

// DisableTOTP valida a senha do usuário e desativa o 2FA
func (a *AuthManager) DisableTOTP(userID, password string) error {
	user, err := a.db.GetUserByID(userID)
	if err != nil {
		return fmt.Errorf("usuário não encontrado: %v", err)
	}

	if user.PasswordHash != "" && !a.VerifyPassword(password, user.PasswordHash) {
		return fmt.Errorf("senha incorreta para confirmação")
	}

	return a.db.UpdateUserTOTP(userID, "", false)
}

// OIDCDiscoveryDoc armazena os endpoints descobertos no IdP
type OIDCDiscoveryDoc struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
}

// OIDCUserInfo armazena os dados do usuário extraídos do token/userinfo
type OIDCUserInfo struct {
	Subject           string `json:"sub"`
	PreferredUsername string `json:"preferred_username"`
	Email             string `json:"email"`
	Name              string `json:"name"`
}

// FetchOIDCDiscovery consulta o endpoint .well-known/openid-configuration
func FetchOIDCDiscovery(issuerURL string) (*OIDCDiscoveryDoc, error) {
	cleanURL := strings.TrimSuffix(issuerURL, "/")
	wellKnown := cleanURL + "/.well-known/openid-configuration"

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(wellKnown)
	if err != nil {
		return nil, fmt.Errorf("falha ao conectar ao provedor OIDC: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("provedor OIDC retornou status HTTP %d", resp.StatusCode)
	}

	var doc OIDCDiscoveryDoc
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("falha ao interpretar JSON de descoberta: %v", err)
	}

	if doc.AuthorizationEndpoint == "" || doc.TokenEndpoint == "" {
		return nil, fmt.Errorf("documento de descoberta OIDC não contém endpoints obrigatórios")
	}

	return &doc, nil
}

// BuildOIDCAuthURL constrói a URL de redirecionamento para login no IdP
func BuildOIDCAuthURL(doc *OIDCDiscoveryDoc, clientID, redirectURL, scopes, state, nonce string) string {
	if scopes == "" {
		scopes = "openid profile email"
	}
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", clientID)
	params.Set("redirect_uri", redirectURL)
	params.Set("scope", scopes)
	params.Set("state", state)
	params.Set("nonce", nonce)

	separator := "?"
	if strings.Contains(doc.AuthorizationEndpoint, "?") {
		separator = "&"
	}
	return doc.AuthorizationEndpoint + separator + params.Encode()
}

// ExchangeOIDCCode troca o código de autorização por tokens e dados do usuário
func ExchangeOIDCCode(doc *OIDCDiscoveryDoc, clientID, clientSecret, redirectURL, code string) (*OIDCUserInfo, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", redirectURL)
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)

	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest("POST", doc.TokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("falha na requisição ao token_endpoint: %v", err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("erro no token_endpoint (HTTP %d): %s", resp.StatusCode, string(bodyBytes))
	}

	var tokenRes struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal(bodyBytes, &tokenRes); err != nil {
		return nil, fmt.Errorf("falha ao interpretar tokens OIDC: %v", err)
	}

	userInfo := &OIDCUserInfo{}

	// Tenta extrair claims básicas do id_token (JWT payload)
	if tokenRes.IDToken != "" {
		parts := strings.Split(tokenRes.IDToken, ".")
		if len(parts) >= 2 {
			payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
			if err == nil {
				_ = json.Unmarshal(payloadBytes, userInfo)
			}
		}
	}

	// Se não veio userinfo completo ou se houver userinfo_endpoint, consulta para garantir
	if (userInfo.PreferredUsername == "" || userInfo.Email == "") && doc.UserinfoEndpoint != "" && tokenRes.AccessToken != "" {
		uReq, _ := http.NewRequest("GET", doc.UserinfoEndpoint, nil)
		uReq.Header.Set("Authorization", "Bearer "+tokenRes.AccessToken)
		if uResp, err := client.Do(uReq); err == nil && uResp.StatusCode == http.StatusOK {
			defer uResp.Body.Close()
			_ = json.NewDecoder(uResp.Body).Decode(userInfo)
		}
	}

	if userInfo.PreferredUsername == "" {
		if userInfo.Email != "" {
			userInfo.PreferredUsername = strings.Split(userInfo.Email, "@")[0]
		} else if userInfo.Subject != "" {
			userInfo.PreferredUsername = userInfo.Subject
		} else {
			return nil, fmt.Errorf("não foi possível identificar o username nas claims do OIDC")
		}
	}

	return userInfo, nil
}

