package main

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"log/slog"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

var rsaKey *rsa.PrivateKey

const (
	tmpPath     = "/opt/token-service/tmp/WORK-cert.pub"
	privKeyPath = "/opt/token-service/token_private.pem"
	pubKeyPath = "/opt/token-service/token_public.pem"
	header      = `{"alg":"RS256","typ":"JWT"}`
	listenAddr  = ":8085"
)

// TokenJSON is the package-level struct used across all functions
type TokenJSON struct {
	Sub    string `json:"sub"`
	Action string `json:"action"`
	Scope  string `json:"scope"`
	Aud    string `json:"aud"`
	Iat    int64  `json:"iat"`
	Exp    int64  `json:"exp"`
	Jti    string `json:"jti"`
	Data   string `json:"data"`
	Auth   string `json:"auth"`
}

type statusResponse struct {
	Status string `json:"status"`
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func errJSON(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, statusResponse{Status: msg})
}



func signJWT(payload string, rsaKey *rsa.PrivateKey) (string, error) {
	b64url := func(data []byte) string {
		return base64.RawURLEncoding.EncodeToString(data)
	}

	headerB64 := b64url([]byte(header))
	payloadB64 := b64url([]byte(payload))
	data := headerB64 + "." + payloadB64

	hashed := sha256.Sum256([]byte(data))
	sig, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, hashed[:])
	if err != nil {
		return "", fmt.Errorf("signing failed: %w", err)
	}
	return data + "." + b64url(sig), nil
}
//going to make this declare global var at start of main, since changing to http server with concurrency, it is wasteful to load hmac from disk every time.
func loadHMACSecret() (string, error) {
	b, err := os.ReadFile("/opt/token-service/hmac_secret.txt")
	if err != nil {
		return "", errors.New("failed to load HMAC secret")
	}
	return strings.TrimSpace(string(b)), nil
}


func computeHMACToken(secret, aud string) string {
	h := hmac.New(sha256.New, []byte(secret))
	_, _ = h.Write([]byte(aud))
	return hex.EncodeToString(h.Sum(nil))
}


func verifyToken(encoded string) ([]byte, error) {
	//splits JWT into 3 parts and takes second section which is payload.
	parts := strings.Split(encoded, ".")
	if len(parts) != 3 {
		slog.Warn("Invalid JWT format")
		return nil, errors.New("Invalid JWT format")
	}

	decodedSig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		slog.Warn("Failed to decode sig")
		return nil, errors.New("Failed to decode sig")
	}

	//load public key file
	pubKeyData, err := os.ReadFile(pubKeyPath)
	if err != nil {
		slog.Warn("Failed to read pub key file from path")
		return nil, errors.New("Failed to read pub key file")

	}

	block, _ := pem.Decode(pubKeyData)
	if block == nil {
		slog.Warn("Failed to decode pubkey data")
		return nil, errors.New("Failed to decode pubkey data")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		slog.Warn("Failed to parse pub key")
		return nil, errors.New("Failed to parse pub key")
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
    if !ok {
		slog.Warn("could not convert into Go pub key object. Failed.")
        return nil, errors.New("could not convert into go pub key object.")
    }

	//header + payload need to be hashed. The signature is a signed hash of the header + payload, not their raw contents.
	signingInput := parts[0] + "." + parts[1]
	//sha256.Sum256 takes any byte input and returns bytes (hash)
	hash := sha256.Sum256([]byte(signingInput))


	err = rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, hash[:], decodedSig)
	if err != nil {
		slog.Warn("Failed to verify sig")
		return nil, errors.New("Failed to verify sig")
	}
	slog.Info("SIG VERIFIED")


	//this needs to be fed the split string second part of the JWT
    decoded, err := base64.RawURLEncoding.DecodeString(parts[1])
    if err != nil {
        return nil, errors.New("Failed to decode payload")
    }
    return decoded, nil
}


func validateSSHJWT(token, auth string) error {
	secret, err := loadHMACSecret()
	if err != nil {
		return err
	}

	token = strings.TrimSpace(token)
	out, err := verifyToken(token)
	if err != nil {
		slog.Warn("Failed to verify token")
		return err
	}

	var req TokenJSON
	if err := json.Unmarshal(out, &req); err != nil {
		slog.Warn("Failed to parse token JSON")
		return err
	}

	if auth != computeHMACToken(secret, req.Aud) {
		slog.Warn("Failed to verify HMAC token")
		return errors.New("Failed to verify HMAC")
	}
	return nil
}

func contains(slice []string, val string) bool {
	for _, s := range slice {
		if s == val {
			return true
		}
	}
	return false
}

func SSHCertSign(runnerAud string) error {
	caBytes, err := os.ReadFile("/etc/runner-ca/runnerCA")
	if err != nil {
		return fmt.Errorf("failed to read CA key: %w", err)
	}
	caSigner, err := ssh.ParsePrivateKey(caBytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA private key: %w", err)
	}

	pubBytes, err := os.ReadFile("/etc/runner-ca/WORK.pub")
	if err != nil {
		return fmt.Errorf("failed to read runner public key: %w", err)
	}
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(pubBytes)
	if err != nil {
		return fmt.Errorf("failed to parse runner public key: %w", err)
	}

	cert := &ssh.Certificate{
		Key:             pubKey,
		Serial:          1,
		CertType:        ssh.UserCert,
		KeyId:           runnerAud,
		ValidPrincipals: []string{runnerAud},
		ValidAfter:      uint64(time.Now().Unix()),
		ValidBefore:     uint64(time.Now().Add(4 * time.Hour).Unix()), // fixed: was 72h
		Permissions: ssh.Permissions{
			Extensions: map[string]string{
				"permit-pty":              "",
				"permit-agent-forwarding": "",
				"permit-port-forwarding":  "",
			},
		},
	}

	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		return fmt.Errorf("failed to sign SSH certificate: %w", err)
	}
	if err := os.WriteFile(tmpPath, ssh.MarshalAuthorizedKey(cert), 0644); err != nil {
		return fmt.Errorf("failed to write certificate to disk: %w", err)
	}
	if _, err = os.Stat(tmpPath); err != nil {
		return fmt.Errorf("cert write succeeded but stat failed: %w", err)
	}
	return nil
}

func InstallCertOnRunner(runnerName string) error {
	slog.Info("CERT READY")
	// TODO: SCP cert to runner; trigger Ansible playbook based on runnerName
	return nil
}



// handleRequest signs a JWT from the incoming payload.
func handleRequest(w http.ResponseWriter, r *http.Request) {



	if r.Method != http.MethodPost {
		errJSON(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		errJSON(w, http.StatusBadRequest, "failed to read body")
		return
	}

	var req TokenJSON
	if err := json.Unmarshal(body, &req); err != nil {
		errJSON(w, http.StatusBadRequest, "invalid json")
		return
	}

	payloadJSON, err := json.Marshal(req)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "failed to marshal payload")
		return
	}

	token, err := signJWT(string(payloadJSON), rsaKey)
	if err != nil {
		log.Printf("ERROR signing JWT: %v", err)
		errJSON(w, http.StatusInternalServerError, "signing failed")
		return
	}

	// Return raw token string, matching original stdout behaviour.
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, token)
}



// handleCert validates an SSH JWT and issues a signed SSH certificate.
func handleCert(w http.ResponseWriter, r *http.Request) {



	if r.Method != http.MethodPost {
		slog.Warn("Request dropped as was not POST method")
		errJSON(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		slog.Warn("Failed to ready body of POST request. Dropped.")
		errJSON(w, http.StatusBadRequest, "failed to read body")
		return
	}

	var req TokenJSON
	if err := json.Unmarshal(body, &req); err != nil {
		errJSON(w, http.StatusBadRequest, "invalid json")
		return
	}

	if err := validateSSHJWT(req.Data, req.Auth); err != nil {
		errJSON(w, http.StatusUnauthorized, "cannot validate")
		return
	}

	allowedAud := []string{"runner", "hvboss", "console"}
	if !contains(allowedAud, req.Aud) {
		errJSON(w, http.StatusForbidden, "forbidden")
		return
	}

	if err := SSHCertSign(req.Aud); err != nil {
		slog.Warn("ERROR signing SSH cert")
		errJSON(w, http.StatusInternalServerError, "failed to sign cert")
		return
	}

	if err := InstallCertOnRunner(req.Aud); err != nil {
		slog.Warn("ERROR installing cert")
		errJSON(w, http.StatusInternalServerError, fmt.Sprintf("failed to install cert on runner %s", req.Aud))
		return
	}

	writeJSON(w, http.StatusOK, statusResponse{Status: "ok"})
}

func main() {

	//loading RSA key
		privKeyData, err := os.ReadFile(privKeyPath)
	if err != nil {
		log.Printf("ERROR reading private key: %v", err)
		return
	}
	block, _ := pem.Decode(privKeyData)
	if block == nil || block.Type != "PRIVATE KEY" {
		log.Println("ERROR: failed to decode PEM block")
		return
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		log.Printf("ERROR parsing private key: %v", err)
		return
	}
	var ok bool
	rsaKey, ok = key.(*rsa.PrivateKey)
	if !ok {
		log.Println("ERROR: not an RSA private key")
		return
	}

	//http server

	mux := http.NewServeMux()
	mux.HandleFunc("/request", handleRequest)
	mux.HandleFunc("/cert", handleCert)

	log.Printf("token-signer listening on %s", listenAddr)
	if err := http.ListenAndServe(listenAddr, mux); err != nil {
		log.Fatal(err)
	}
}
