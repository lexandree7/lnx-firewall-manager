package auth

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"time"

	"lnx-firewall-manager/internal/models"
)

func TestArgon2idPasswordHashing(t *testing.T) {
	mgr := &AuthManager{}
	password := "SecretP@ssw0rd!2026"

	hash, err := mgr.HashPassword(password)
	if err != nil {
		t.Fatalf("Erro ao gerar hash Argon2id: %v", err)
	}

	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Errorf("Formato de hash inválido, esperado prefixo $argon2id$: %s", hash)
	}

	if !mgr.VerifyPassword(password, hash) {
		t.Errorf("Falha ao verificar senha correta contra hash gerada")
	}

	if mgr.VerifyPassword("wrong-password", hash) {
		t.Errorf("Validação incorretamente sucedeu com senha incorreta")
	}
}

func TestTOTPGenerationAndValidation(t *testing.T) {
	mgr := &AuthManager{}
	secret := mgr.GenerateTOTPSecret()

	if len(secret) < 16 {
		t.Fatalf("Segredo Base32 gerado é curto demais: %s", secret)
	}

	// Gera código válido para o timestamp atual manualmente para checagem cruzada
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatalf("Segredo gerado não é Base32 válido: %v", err)
	}

	epoch := time.Now().Unix() / 30
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(epoch))

	mac := hmac.New(sha1.New, key)
	mac.Write(buf)
	h := mac.Sum(nil)
	offset := h[len(h)-1] & 0x0F
	truncated := binary.BigEndian.Uint32(h[offset : offset+4]) & 0x7FFFFFFF
	validCode := fmt.Sprintf("%06d", truncated%1000000)

	if !mgr.ValidateTOTP(secret, validCode) {
		t.Errorf("Falha ao validar código TOTP legítimo gerado: %s", validCode)
	}

	if mgr.ValidateTOTP(secret, "000000") && validCode != "000000" {
		t.Errorf("Código TOTP falso foi aceito indevidamente")
	}
}

func TestRBACPermissions(t *testing.T) {
	adminUser := &models.User{
		Username: "root",
		Role:     "admin",
	}

	viewerUser := &models.User{
		Username: "auditor",
		Role:     "viewer",
	}

	server := &models.Server{
		ID:   "srv_1",
		Tags: []string{"production"},
	}

	// Admin deve ter acesso a tudo
	if !CheckPermission(adminUser, "admin", server) {
		t.Errorf("Admin deveria ter permissão admin")
	}
	if !CheckPermission(adminUser, "viewer", server) {
		t.Errorf("Admin deveria ter permissão viewer")
	}

	// Viewer deve ter acesso apenas a viewer
	if !CheckPermission(viewerUser, "viewer", server) {
		t.Errorf("Viewer deveria ter permissão viewer")
	}
	if CheckPermission(viewerUser, "admin", server) {
		t.Errorf("Viewer NÃO deveria ter permissão admin")
	}
}

func TestBuildOIDCAuthURL(t *testing.T) {
	doc := &OIDCDiscoveryDoc{
		AuthorizationEndpoint: "https://auth.company.com/oauth2/authorize",
	}

	authURL := BuildOIDCAuthURL(doc, "client123", "http://localhost:8443/callback", "openid email", "stateXYZ", "nonceABC")

	if !strings.Contains(authURL, "response_type=code") {
		t.Errorf("URL deve conter response_type=code: %s", authURL)
	}
	if !strings.Contains(authURL, "client_id=client123") {
		t.Errorf("URL deve conter client_id: %s", authURL)
	}
	if !strings.Contains(authURL, "state=stateXYZ") {
		t.Errorf("URL deve conter state: %s", authURL)
	}
}
