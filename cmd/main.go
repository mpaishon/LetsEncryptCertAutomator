package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

// ======== CONFIGURATION ========
const (
	domain     = "www.thehopswarm.com"       // 🔁 Replace with your actual domain
	email      = "michael.paishon@gmail.com"      // 🔁 Replace with your actual email
	certPath   = "certs"
	certFile   = "cert.pem"
	keyFile    = "key.pem"
)

// ======== GLOBAL STATE ========
var (
	challengeMap = make(map[string]string)
	mu           sync.RWMutex
)

// ======== LEGO USER ========
type MyUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *MyUser) GetEmail() string                         { return u.Email }
func (u *MyUser) GetRegistration() *registration.Resource  { return u.Registration }
func (u *MyUser) GetPrivateKey() crypto.PrivateKey         { return u.key }

// ======== HTTP PROVIDER ========
type HTTPProvider struct{}

func (p HTTPProvider) Present(domain, token, keyAuth string) error {
	mu.Lock()
	defer mu.Unlock()
	challengeMap[token] = keyAuth
	return nil
}

func (p HTTPProvider) CleanUp(domain, token, keyAuth string) error {
	mu.Lock()
	defer mu.Unlock()
	delete(challengeMap, token)
	return nil
}

// ======== ACME CERT HANDLER ========
func setupCertificate() error {
	// Check if certs already exist
	if _, err := os.Stat(filepath.Join(certPath, certFile)); err == nil {
		log.Println("✅ Certificate already exists, skipping issuance.")
		return nil
	}

	// Create RSA key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}

	user := &MyUser{Email: email, key: key}
	config := lego.NewConfig(user)
	config.Certificate.KeyType = certcrypto.RSA2048

	client, err := lego.NewClient(config)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	// Set custom HTTP provider (backed by Gin)
	if err := client.Challenge.SetHTTP01Provider(HTTPProvider{}); err != nil {
		return err
	}

	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return fmt.Errorf("registration failed: %w", err)
	}
	user.Registration = reg

	request := certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	}

	certs, err := client.Certificate.Obtain(request)
	if err != nil {
		return fmt.Errorf("certificate obtain failed: %w", err)
	}

	// Save certs
	os.MkdirAll(certPath, 0700)
	os.WriteFile(filepath.Join(certPath, certFile), certs.Certificate, 0600)
	os.WriteFile(filepath.Join(certPath, keyFile), certs.PrivateKey, 0600)

	log.Println("✅ Certificate successfully obtained.")
	return nil
}

// ======== GIN HTTP SERVER FOR CHALLENGE ========
func startHTTPChallengeServer() {
	r := gin.Default()

	r.GET("/.well-known/acme-challenge/:token", func(c *gin.Context) {
		token := c.Param("token")
		mu.RLock()
		keyAuth, ok := challengeMap[token]
		mu.RUnlock()

		if !ok {
			log.Printf("❌ Challenge token not found: %s", token)
			c.String(http.StatusNotFound, "not found")
			return
		}
		log.Printf("✅ Responding to challenge: %s => %s", token, keyAuth)
		c.String(http.StatusOK, keyAuth)
	})

	r.NoRoute(func(c *gin.Context) {
		raw, _ := json.Marshal(map[string]interface{}{
			"method":  c.Request.Method,
			"path":    c.Request.URL.Path,
			"headers": c.Request.Header,
		})
		log.Printf("🔍 [HTTP] %s\n", raw)
		c.String(http.StatusNotFound, "not found")
	})

	go func() {
		if err := r.Run(":80"); err != nil {
			log.Fatalf("HTTP server (port 80) failed: %v", err)
		}
	}()
}

// ======== HTTPS SERVER ========
func startHTTPSServer() {
	certFilePath := filepath.Join(certPath, certFile)
	keyFilePath := filepath.Join(certPath, keyFile)

	cert, err := tls.LoadX509KeyPair(certFilePath, keyFilePath)
	if err != nil {
		log.Fatalf("Failed to load TLS cert: %v", err)
	}

	server := &http.Server{
		Addr: ":443",
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("🔐 [HTTPS] %s %s", r.Method, r.URL.Path)
			w.Write([]byte("✅ Hello from your secure HTTPS server!\n"))
		}),
	}

	log.Println("🔐 HTTPS server listening on port 443...")
	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("HTTPS server failed: %v", err)
	}
}

// ======== MAIN ENTRY POINT ========
func main() {
	startHTTPChallengeServer()

	if err := setupCertificate(); err != nil {
		log.Fatalf("❌ Failed to setup certificate: %v", err)
	}

	startHTTPSServer()
}
