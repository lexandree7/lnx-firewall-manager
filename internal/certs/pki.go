package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// PKIManager gerencia a CA interna e emissão de certificados mTLS
type PKIManager struct {
	mu           sync.RWMutex
	baseDir      string
	caCert       *x509.Certificate
	caKey        *ecdsa.PrivateKey
	caPEM        []byte
	serverCert   *tls.Certificate
	revokedList  map[string]time.Time // Serial Number -> Data de Revogação
}

// NewPKIManager inicializa ou carrega a autoridade certificadora interna
func NewPKIManager(baseDir string) (*PKIManager, error) {
	if baseDir == "" {
		baseDir = "./certs_data"
	}
	_ = os.MkdirAll(baseDir, 0700)

	mgr := &PKIManager{
		baseDir:     baseDir,
		revokedList: make(map[string]time.Time),
	}

	caCertFile := filepath.Join(baseDir, "ca.crt")
	caKeyFile := filepath.Join(baseDir, "ca.key")

	if _, err := os.Stat(caCertFile); err == nil {
		if err := mgr.loadCA(caCertFile, caKeyFile); err != nil {
			return nil, fmt.Errorf("falha ao carregar CA: %v", err)
		}
	} else {
		if err := mgr.generateRootCA(caCertFile, caKeyFile); err != nil {
			return nil, fmt.Errorf("falha ao criar Root CA: %v", err)
		}
	}

	return mgr, nil
}

func (p *PKIManager) generateRootCA(certFile, keyFile string) error {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:  []string{"Linux Firewall Manager Internal"},
			CommonName:    "LFM Internal Root CA",
			Country:       []string{"BR"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // 10 anos
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		return err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyBytes, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
		return err
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		return err
	}

	p.caCert, _ = x509.ParseCertificate(derBytes)
	p.caKey = privKey
	p.caPEM = certPEM

	return nil
}

func (p *PKIManager) loadCA(certFile, keyFile string) error {
	certData, err := os.ReadFile(certFile)
	if err != nil {
		return err
	}
	keyData, err := os.ReadFile(keyFile)
	if err != nil {
		return err
	}

	certBlock, _ := pem.Decode(certData)
	if certBlock == nil {
		return fmt.Errorf("falha ao decodificar PEM da CA")
	}
	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return err
	}

	keyBlock, _ := pem.Decode(keyData)
	if keyBlock == nil {
		return fmt.Errorf("falha ao decodificar chave privada da CA")
	}
	caKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return err
	}

	p.caCert = caCert
	p.caKey = caKey
	p.caPEM = certData
	return nil
}

// GetCAPEM retorna o certificado da CA em formato PEM
func (p *PKIManager) GetCAPEM() []byte {
	return p.caPEM
}

// IssueServerCertificate emite ou retorna o certificado TLS do servidor
func (p *PKIManager) IssueServerCertificate(dnsNames []string, ips []net.IP) (*tls.Certificate, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.serverCert != nil {
		return p.serverCert, nil
	}

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Linux Firewall Manager"},
			CommonName:   "lfm-server",
		},
		DNSNames:              append(dnsNames, "localhost", "127.0.0.1"),
		IPAddresses:           append(ips, net.ParseIP("127.0.0.1"), net.ParseIP("::1")),
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(3 * 365 * 24 * time.Hour), // 3 anos
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, p.caCert, &privKey.PublicKey, p.caKey)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyBytes, _ := x509.MarshalECPrivateKey(privKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	p.serverCert = &tlsCert
	return p.serverCert, nil
}

// ClientCertResult contém o resultado da emissão de certificado para o agente
type ClientCertResult struct {
	CertPEM      string
	SerialNumber string
	Fingerprint  string
	ExpiresAt    time.Time
}

// IssueClientCertificate assina um CSR de agente ou emite par completo
func (p *PKIManager) IssueClientCertificate(serverID, hostname string) (*ClientCertResult, string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	expiresAt := time.Now().Add(365 * 24 * time.Hour) // 1 ano

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Linux Firewall Manager Managed Agents"},
			CommonName:   fmt.Sprintf("agent-%s", serverID),
		},
		DNSNames:              []string{hostname},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              expiresAt,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, p.caCert, &privKey.PublicKey, p.caKey)
	if err != nil {
		return nil, "", err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyBytes, _ := x509.MarshalECPrivateKey(privKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	hash := sha256.Sum256(derBytes)
	fingerprint := hex.EncodeToString(hash[:])
	serialStr := serialNumber.Text(16)

	res := &ClientCertResult{
		CertPEM:      string(certPEM),
		SerialNumber: serialStr,
		Fingerprint:  fingerprint,
		ExpiresAt:    expiresAt,
	}

	return res, string(keyPEM), nil
}

// RevokeCertificate revoga o certificado do agente
func (p *PKIManager) RevokeCertificate(serialNumber string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.revokedList[serialNumber] = time.Now()
}

// IsRevoked verifica se um certificado foi revogado
func (p *PKIManager) IsRevoked(serialNumber string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	_, ok := p.revokedList[serialNumber]
	return ok
}

// GetServerTLSConfig cria uma configuração TLS para o servidor com mTLS opcional/estrito
func (p *PKIManager) GetServerTLSConfig(requireClientCert bool) (*tls.Config, error) {
	serverCert, err := p.IssueServerCertificate(nil, nil)
	if err != nil {
		return nil, err
	}

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(p.caPEM)

	clientAuth := tls.NoClientCert
	if requireClientCert {
		clientAuth = tls.RequireAndVerifyClientCert
	}

	return &tls.Config{
		Certificates: []tls.Certificate{*serverCert},
		ClientCAs:    caPool,
		ClientAuth:   clientAuth,
		MinVersion:   tls.VersionTLS12,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return nil
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}
			if p.IsRevoked(cert.SerialNumber.Text(16)) {
				return fmt.Errorf("certificado do cliente revogado: serial %s", cert.SerialNumber.Text(16))
			}
			return nil
		},
	}, nil
}
