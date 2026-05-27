package main

//this is also far from complete. just a first edition rewrite from bash to go.
// a lot of validation, error handling, edge case and extra features needed to complete.



import (
        "database/sql"
        "encoding/json"
        "fmt"
        "io"
        "log/slog"
        "net/http"
        "os"
        "errors"
        "bytes"
        "regexp"
        "strings"
        "time"

        _ "github.com/lib/pq"
)


//REGEX RULES
var (
        //JWT
        reAction = regexp.MustCompile(`^[A-Za-z]{4,10}$`)
        reScope  = regexp.MustCompile(`^[A-Za-z.]{4,12}$`)
        reAud    = regexp.MustCompile(`^[A-Za-z]{4,10}$`)


        //SSH CERT
    //    reData  = regexp.MustCompile(`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`)
     //   reAuth    = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)



)

var db *sql.DB

func main() {
        var err error
        dsn := "host=127.0.0.1 user=token_user dbname=token_service sslmode=disable"
        db, err = sql.Open("postgres", dsn)
        if err != nil {
                slog.Error("db open failed", "err", err)
                os.Exit(1)
        }
        if err = db.Ping(); err != nil {
                slog.Error("db ping failed", "err", err)
                os.Exit(1)
        }

        http.HandleFunc("/", handler)
        http.HandleFunc("/ssh", sshHandler)
        addr := ":8080"
        slog.Info("listening", "addr", addr)
        if err := http.ListenAndServe(addr, nil); err != nil {
                slog.Error("server error", "err", err)
                os.Exit(1)
        }
}

//SSH Handler

func sshHandler(w http.ResponseWriter, r *http.Request) {
        srcIP := r.Header.Get("X-Real-IP")
        if srcIP == "" {
                srcIP = r.RemoteAddr
        }
        srcIP = strings.SplitN(srcIP, ",", 2)[0]

        w.Header().Set("Content-Type", "application/json")

        if r.Method != http.MethodPost {
                slog.Warn("method not allowed", "ip", srcIP)
                jsonErr(w, http.StatusMethodNotAllowed, "POST only")
                return
        }

        body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
        if err != nil || len(body) == 0 {
                slog.Error("empty body", "ip", srcIP)
                jsonErr(w, http.StatusBadRequest, "empty body")
                return
        }

        var req struct {
	        Action string `json:"action"` // cert
	        Aud    string `json:"aud"` // runner 
	        Data string `json:"data"` // JWT	        
	        Auth string `json:"auth"` // Auth is the MFA layer HMAC token, required for SSH cert requests
        }


        
        if err := json.Unmarshal(body, &req); err != nil || req.Action == "" || req.Aud == "" || req.Data == "" || req.Auth == "" {
                jsonErr(w, http.StatusBadRequest, "empty fields")
                return
        }
        //need regex validation

//|| reData.MatchString(req.Data) || reAuth.MatchString(req.Auth)
        if !reAction.MatchString(req.Action) || !reAud.MatchString(req.Aud)  {
                jsonErr(w, http.StatusBadRequest, "invalid data")
                return
        }


        payload, err := json.Marshal(map[string]any{
                "action":   req.Action,
                "aud":   req.Aud,
                "data": req.Data,
                "auth":   req.Auth,
        })
        if err != nil {
                slog.Error("marshal payload", "err", err)
                jsonErr(w, http.StatusInternalServerError, "internal error")
                return
        }

        socketResponse, err := signPayload(payload, "/cert")
        if err != nil {
                slog.Error("trigger socket failure", "err", err)
                jsonErr(w, http.StatusInternalServerError, "signing error")
                return
        }

        if socketResponse == "" {
                slog.Error("Empty response from signer")
                jsonErr(w, http.StatusInternalServerError, "error")
                return
        }

        w.WriteHeader(http.StatusOK)
        fmt.Fprintf(w, `{"STATUS":"OK"}`)

        }




func handler(w http.ResponseWriter, r *http.Request) {
        srcIP := r.Header.Get("X-Real-IP")
        if srcIP == "" {
                srcIP = r.RemoteAddr
        }
        srcIP = strings.SplitN(srcIP, ",", 2)[0]
        tlsFingerprint := r.Header.Get("X-Client-Fingerprint")

        w.Header().Set("Content-Type", "application/json")

        if r.Method != http.MethodPost {
                slog.Warn("method not allowed", "ip", srcIP)
                jsonErr(w, http.StatusMethodNotAllowed, "POST only")
                return
        }

        body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
        if err != nil || len(body) == 0 {
                slog.Error("empty body", "ip", srcIP)
                jsonErr(w, http.StatusBadRequest, "empty body")
                return
        }

        var req struct {
                Action string `json:"action"`
                Scope  string `json:"scope"`
                Aud    string `json:"aud"`
        }
        if err := json.Unmarshal(body, &req); err != nil || req.Action == "" || req.Scope == "" || req.Aud == "" {
                jsonErr(w, http.StatusBadRequest, "action, scope and audience required")
                return
        }

        if !reAction.MatchString(req.Action) || !reScope.MatchString(req.Scope) || !reAud.MatchString(req.Aud) {
                jsonErr(w, http.StatusBadRequest, "invalid data")
                return
        }

        // Lookup host by fingerprint + permissions
        var hostID string
        err = db.QueryRowContext(r.Context(), `
                SELECT h.id
                FROM hosts h
                JOIN host_permissions p ON p.host_id = h.id
                WHERE h.cert_fingerprint = $1
                  AND h.enabled = TRUE
                  AND p.action = $2
                  AND p.scope = $3
                  AND p.audience = $4
                LIMIT 1`,
                tlsFingerprint, req.Action, req.Scope, req.Aud,
        ).Scan(&hostID)

        if err == sql.ErrNoRows {
                slog.Warn("unauthorised", "ip", srcIP, "fingerprint", tlsFingerprint)
                jsonErr(w, http.StatusForbidden, "unauthorised")
                return
        }
        if err != nil {
                slog.Error("db lookup error", "err", err)
                jsonErr(w, http.StatusInternalServerError, "internal error")
                return
        }

        // Build JWT payload and sign via Unix socket 
        now := time.Now().Unix()
        exp := now + 300
        jti, err := randomHex(16)
        if err != nil {
                slog.Error("rand failed", "err", err)
                jsonErr(w, http.StatusInternalServerError, "internal error")
                return
        }

        payload, err := json.Marshal(map[string]any{
                "sub":   hostID,
                "action":   req.Action,
                "scope": req.Scope,
                "aud":   req.Aud,
                "iat":   now,
                "exp":   exp,
                "jti":   jti,
        })
        if err != nil {
                slog.Error("marshal payload", "err", err)
                jsonErr(w, http.StatusInternalServerError, "internal error")
                return
        }

        jwt, err := signPayload(payload, "/request")
        if err != nil {
                slog.Error("sign failed", "err", err)
                jsonErr(w, http.StatusInternalServerError, "signing error")
                return
        }

        // Insert token, reject if active duplicate exists
        var result int
        err = db.QueryRowContext(r.Context(), `
                WITH ins AS (
                        INSERT INTO tokens (jti, host_id, action, scope, audience, issued_at, expires_at, created_at)
                        SELECT $1, $2, $3, $4, $5,
                               to_timestamp($6), to_timestamp($7), to_timestamp($6)
                        WHERE NOT EXISTS (
                                SELECT 1 FROM tokens
                                WHERE host_id = $2
                                  AND action = $3
                                  AND scope  = $4
                                  AND audience = $5
                                  AND expires_at > now()
                        )
                        ON CONFLICT DO NOTHING
                        RETURNING 1
                )
                SELECT COALESCE((SELECT 1 FROM ins), 0)`,
                jti, hostID, req.Action, req.Scope, req.Aud, now, exp,
        ).Scan(&result)

        if err != nil {
                slog.Error("token insert error", "err", err)
                jsonErr(w, http.StatusInternalServerError, "internal error")
                return
        }

        if result == 1 {
                w.WriteHeader(http.StatusOK)
                fmt.Fprintf(w, `{"TOKEN":%q}`, jwt)
        } else {
                jsonErr(w, http.StatusForbidden, "token already exists")
        }
}

func signPayload(payload []byte, endpoint string) (string, error) {
    slog.Info(endpoint)
        resp, err := http.Post(
                "http://127.0.0.1:8085"+endpoint,
                "application/json",
                bytes.NewBuffer(payload),
        )
        if err != nil {
                slog.Warn("Failed to sign")
                return "", err
        }
        defer resp.Body.Close()

        body, err := io.ReadAll(resp.Body)
        if err != nil {
                slog.Warn("Failed to read body from signer")
                return "", err
        }

        if resp.StatusCode != http.StatusOK {
                return "", errors.New("Bad HTTP response")
        }

        strbody := string(body)
        return strbody, nil


}

func randomHex(n int) (string, error) {
        buf := make([]byte, n)
        f, err := os.Open("/dev/urandom")
        if err != nil {
                return "", err
        }
        defer f.Close()
        if _, err := io.ReadFull(f, buf); err != nil {
                return "", err
        }
        return fmt.Sprintf("%x", buf), nil
}

func jsonErr(w http.ResponseWriter, code int, msg string) {
        w.WriteHeader(code)
        fmt.Fprintf(w, `{"error":%q}`, msg)
}
