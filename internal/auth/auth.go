package auth

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"s3web/internal/config"
	"s3web/internal/model"
	"s3web/internal/rbac"
	"s3web/internal/store"
)

type contextKey string

const principalContextKey contextKey = "s3web_principal"
const SessionCookieName = "s3web_session"

// PrincipalFromContext retrieves the authenticated Principal from the request context.
func PrincipalFromContext(ctx context.Context) *model.Principal {
	if p, ok := ctx.Value(principalContextKey).(*model.Principal); ok {
		return p
	}
	return nil
}

// WithPrincipal attaches a Principal to a context.
func WithPrincipal(ctx context.Context, p *model.Principal) context.Context {
	return context.WithValue(ctx, principalContextKey, p)
}

// Authenticator handles OIDC SSO sessions, GitHub Actions OIDC JWTs, and Service Account Basic/Bearer auth.
type Authenticator struct {
	cfg       *config.Config
	store     store.MetadataStore
	evaluator *rbac.Evaluator

	jwksMu    sync.RWMutex
	jwksKeys  map[string]*rsa.PublicKey
	jwksFetch time.Time
}

// NewAuthenticator creates a new Authenticator.
func NewAuthenticator(cfg *config.Config, st store.MetadataStore, eval *rbac.Evaluator) *Authenticator {
	a := &Authenticator{
		cfg:       cfg,
		store:     st,
		evaluator: eval,
		jwksKeys:  make(map[string]*rsa.PublicKey),
	}
	if cfg.GitHubPinnedJWKSJSON != "" {
		_ = a.loadJWKSFromJSON([]byte(cfg.GitHubPinnedJWKSJSON))
	}
	return a
}

// HashSecret hashes a service account secret with a random salt using SHA-256 HMAC iterations.
func HashSecret(secret string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	derived := deriveKey([]byte(secret), salt, 100_000)
	return fmt.Sprintf("pbkdf2$100000$%s$%s", hex.EncodeToString(salt), hex.EncodeToString(derived)), nil
}

// VerifySecret checks a plaintext secret against a stored HashSecret string in constant time.
func VerifySecret(secret, encodedHash string) bool {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2" {
		return false
	}
	salt, err := hex.DecodeString(parts[2])
	if err != nil {
		return false
	}
	expected, err := hex.DecodeString(parts[3])
	if err != nil {
		return false
	}
	actual := deriveKey([]byte(secret), salt, 100_000)
	return hmac.Equal(actual, expected)
}

func deriveKey(password, salt []byte, iterations int) []byte {
	mac := hmac.New(sha256.New, password)
	mac.Write(salt)
	mac.Write([]byte{0, 0, 0, 1})
	u := mac.Sum(nil)
	out := make([]byte, len(u))
	copy(out, u)
	for i := 1; i < iterations; i++ {
		mac.Reset()
		mac.Write(u)
		u = mac.Sum(nil)
		for j := range out {
			out[j] ^= u[j]
		}
	}
	return out
}

// GenerateToken generates a random service account secret prefixed with "s3w_".
func GenerateToken() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "s3w_" + base64.RawURLEncoding.EncodeToString(b), nil
}

type sessionPayload struct {
	ID          string   `json:"id"`
	Email       string   `json:"email"`
	DisplayName string   `json:"name"`
	OIDCGroups  []string `json:"groups"`
	ExpiresAt   int64    `json:"exp"`
}

// IssueSessionCookie signs and sets an HttpOnly session cookie for an SSO user.
func (a *Authenticator) IssueSessionCookie(w http.ResponseWriter, email, displayName string, oidcGroups []string) error {
	payload := sessionPayload{
		ID:          email,
		Email:       email,
		DisplayName: displayName,
		OIDCGroups:  oidcGroups,
		ExpiresAt:   time.Now().Add(12 * time.Hour).Unix(),
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	b64 := base64.RawURLEncoding.EncodeToString(raw)
	sig := a.signString(b64)
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    b64 + "." + sig,
		Path:     "/",
		HttpOnly: true,
		Secure:   a.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   12 * 3600,
	})
	return nil
}

// ClearSessionCookie logs out the browser user.
func (a *Authenticator) ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   a.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

func (a *Authenticator) signString(data string) string {
	mac := hmac.New(sha256.New, []byte(a.cfg.SessionSecret))
	mac.Write([]byte(data))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// AuthenticateAdminLogin verifies the bootstrap admin email/username and password.
func (a *Authenticator) AuthenticateAdminLogin(username, password string) bool {
	if !strings.EqualFold(strings.TrimSpace(username), a.cfg.BootstrapAdminEmail) &&
		!strings.EqualFold(strings.TrimSpace(username), "admin") {
		return false
	}
	if a.cfg.BootstrapAdminPassword == "" {
		return false
	}
	return hmac.Equal([]byte(password), []byte(a.cfg.BootstrapAdminPassword))
}

// AuthenticateRequest inspects the HTTP request for:
// 1. HTTP Basic Auth (Bootstrap Admin OR Service Account — e.g., Sonatype Nexus)
// 2. HTTP Bearer Token (Service Account "s3w_..." OR GitHub Actions OIDC JWT "eyJ...")
// 3. Encrypted Session Cookie (SSO / Admin User)
func (a *Authenticator) AuthenticateRequest(r *http.Request) (*model.Principal, error) {
	ctx := r.Context()

	// 1. Check HTTP Basic Auth (Bootstrap Admin OR Sonatype Nexus / CLI Service Account)
	if username, password, ok := r.BasicAuth(); ok && username != "" {
		if a.AuthenticateAdminLogin(username, password) {
			p := &model.Principal{
				Type:        model.PrincipalSSOUser,
				ID:          a.cfg.BootstrapAdminEmail,
				Email:       a.cfg.BootstrapAdminEmail,
				DisplayName: "Bootstrap Admin (" + a.cfg.BootstrapAdminEmail + ")",
				OIDCGroups:  []string{a.cfg.BootstrapAdminOIDCGroup},
			}
			return a.enrichPrincipal(ctx, p)
		}
		return a.authenticateServiceAccount(ctx, username, password)
	}

	// 2. Check Authorization: Bearer <token>
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		token := strings.TrimSpace(authHeader[7:])
		// Check if it is a service account token ("id:s3w_..." or "s3w_...")
		if strings.Contains(token, ":s3w_") {
			parts := strings.SplitN(token, ":", 2)
			return a.authenticateServiceAccount(ctx, parts[0], parts[1])
		}
		// Check if it is a JWT (GitHub Actions OIDC JWT or signed internal JWT)
		if strings.Count(token, ".") == 2 {
			return a.authenticateGitHubOIDCJWT(ctx, token)
		}
	}

	// 3. Check Session Cookie (Human SSO User)
	if cookie, err := r.Cookie(SessionCookieName); err == nil && cookie.Value != "" {
		return a.authenticateSessionCookie(ctx, cookie.Value)
	}

	// 4. In local development mode, if no session cookie is set yet, provide a default SSO session
	// so the developer can immediately test the UI and switch personas in the header switcher.
	if a.cfg.BackendMode == "local" && !a.cfg.OIDCEnabled {
		p := &model.Principal{
			Type:        model.PrincipalSSOUser,
			ID:          a.cfg.BootstrapAdminEmail,
			Email:       a.cfg.BootstrapAdminEmail,
			DisplayName: "Local SSO Admin (" + a.cfg.BootstrapAdminEmail + ")",
			OIDCGroups:  []string{a.cfg.BootstrapAdminOIDCGroup},
		}
		return a.enrichPrincipal(ctx, p)
	}

	return nil, errors.New("unauthenticated request")
}

func (a *Authenticator) authenticateSessionCookie(ctx context.Context, cookieVal string) (*model.Principal, error) {
	parts := strings.SplitN(cookieVal, ".", 2)
	if len(parts) != 2 {
		return nil, errors.New("malformed session cookie")
	}
	expectedSig := a.signString(parts[0])
	if !hmac.Equal([]byte(parts[1]), []byte(expectedSig)) {
		return nil, errors.New("invalid session signature")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	var payload sessionPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, err
	}
	if time.Now().Unix() > payload.ExpiresAt {
		return nil, errors.New("session expired")
	}
	p := &model.Principal{
		Type:        model.PrincipalSSOUser,
		ID:          payload.Email,
		Email:       payload.Email,
		DisplayName: payload.DisplayName,
		OIDCGroups:  payload.OIDCGroups,
	}
	return a.enrichPrincipal(ctx, p)
}

func (a *Authenticator) authenticateServiceAccount(ctx context.Context, accountID, secret string) (*model.Principal, error) {
	sa, err := a.store.GetServiceAccount(ctx, accountID)
	if err != nil {
		return nil, errors.New("invalid service account credentials")
	}
	if sa.Revoked {
		return nil, errors.New("service account is revoked")
	}
	if sa.ExpiresAt != nil && time.Now().After(*sa.ExpiresAt) {
		return nil, errors.New("service account has expired")
	}
	if !VerifySecret(secret, sa.SecretHash) {
		return nil, errors.New("invalid service account secret")
	}
	now := time.Now().UTC()
	sa.LastUsedAt = &now
	_ = a.store.UpsertServiceAccount(ctx, sa)

	p := &model.Principal{
		Type:        model.PrincipalServiceAccount,
		ID:          sa.AccountID,
		DisplayName: sa.Name,
	}
	return a.enrichPrincipal(ctx, p)
}

// authenticateGitHubOIDCJWT validates a GitHub Actions OIDC JWT ("Authorization: Bearer <jwt>").
// Supports both RS256 JWKS verification (from GitHub OIDC or pinned JWKS in private VPCs)
// and HS256 signed workflow tokens (for local/integration testing).
func (a *Authenticator) authenticateGitHubOIDCJWT(ctx context.Context, token string) (*model.Principal, error) {
	if !a.cfg.GitHubOIDCEnabled {
		return nil, errors.New("GitHub OIDC authentication is disabled")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid JWT format")
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("invalid JWT header encoding")
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &hdr); err != nil {
		return nil, errors.New("invalid JWT header JSON")
	}

	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("invalid JWT claims encoding")
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, errors.New("invalid JWT claims JSON")
	}

	// Verify signature (RS256 against JWKS, or HS256 with SessionSecret for local/self-hosted test tokens)
	signingInput := parts[0] + "." + parts[1]
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("invalid JWT signature encoding")
	}

	switch hdr.Alg {
	case "RS256":
		pubKey, err := a.getJWKSKey(ctx, hdr.Kid)
		if err != nil {
			return nil, fmt.Errorf("JWKS key lookup failed: %w", err)
		}
		digest := sha256.Sum256([]byte(signingInput))
		if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, digest[:], sigBytes); err != nil {
			return nil, errors.New("invalid RS256 JWT signature")
		}
	case "HS256":
		mac := hmac.New(sha256.New, []byte(a.cfg.SessionSecret))
		mac.Write([]byte(signingInput))
		if !hmac.Equal(sigBytes, mac.Sum(nil)) {
			return nil, errors.New("invalid HS256 JWT signature")
		}
	default:
		return nil, fmt.Errorf("unsupported JWT algorithm: %s", hdr.Alg)
	}

	// Verify exp
	if expVal, ok := claims["exp"].(float64); ok {
		if time.Now().Unix() > int64(expVal) {
			return nil, errors.New("GitHub OIDC JWT has expired")
		}
	}

	repo, _ := claims["repository"].(string)
	ref, _ := claims["ref"].(string)
	env, _ := claims["environment"].(string)
	sub, _ := claims["sub"].(string)
	workflowRef, _ := claims["workflow_ref"].(string)
	actor, _ := claims["actor"].(string)
	runID, _ := claims["run_id"].(string)

	if repo == "" && sub == "" {
		return nil, errors.New("JWT missing required GitHub repository/sub claims")
	}

	principalID := sub
	if repo != "" {
		principalID = fmt.Sprintf("gh:%s@%s", repo, strings.TrimPrefix(ref, "refs/heads/"))
		if runID != "" {
			principalID += "#" + runID
		}
	}

	p := &model.Principal{
		Type:        model.PrincipalGitHubWorkflow,
		ID:          principalID,
		DisplayName: fmt.Sprintf("GitHub Workflow (%s)", repo),
		GitHubClaims: map[string]string{
			"sub":          sub,
			"repository":   repo,
			"ref":          ref,
			"environment":  env,
			"workflow_ref": workflowRef,
			"actor":        actor,
		},
	}
	return a.enrichPrincipal(ctx, p)
}

func (a *Authenticator) enrichPrincipal(ctx context.Context, p *model.Principal) (*model.Principal, error) {
	if p.Type == model.PrincipalSSOUser && p.Email != "" {
		appGroups, err := a.store.GetUserAppGroups(ctx, p.Email)
		if err == nil {
			p.AppGroups = appGroups
		}
	}
	perm, err := a.evaluator.Resolve(ctx, p, "")
	if err != nil {
		return nil, err
	}
	p.EffectivePerm = perm
	return p, nil
}

// MintTestGitHubJWT creates a signed GitHub Actions OIDC JWT for testing workflow authentication.
func (a *Authenticator) MintTestGitHubJWT(repository, ref, environment, actor string) (string, error) {
	hdr := map[string]string{"alg": "HS256", "typ": "JWT"}
	claims := map[string]interface{}{
		"iss":          a.cfg.GitHubOIDCIssuerURL,
		"aud":          a.cfg.GitHubOIDCAudience,
		"sub":          fmt.Sprintf("repo:%s:ref:%s", repository, ref),
		"repository":   repository,
		"ref":          ref,
		"environment":  environment,
		"actor":        actor,
		"workflow_ref": fmt.Sprintf("%s/.github/workflows/release-iso.yml@%s", repository, ref),
		"iat":          time.Now().Unix(),
		"exp":          time.Now().Add(1 * time.Hour).Unix(),
	}
	hdrJSON, _ := json.Marshal(hdr)
	claimsJSON, _ := json.Marshal(claims)
	signingInput := base64.RawURLEncoding.EncodeToString(hdrJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	mac := hmac.New(sha256.New, []byte(a.cfg.SessionSecret))
	mac.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return signingInput + "." + sig, nil
}

type jwksDocument struct {
	Keys []struct {
		Kid string `json:"kid"`
		Kty string `json:"kty"`
		N   string `json:"n"`
		E   string `json:"e"`
	} `json:"keys"`
}

func (a *Authenticator) loadJWKSFromJSON(raw []byte) error {
	var doc jwksDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return err
	}
	a.jwksMu.Lock()
	defer a.jwksMu.Unlock()
	for _, k := range doc.Keys {
		if k.Kty != "RSA" {
			continue
		}
		nBytes, err1 := base64.RawURLEncoding.DecodeString(k.N)
		eBytes, err2 := base64.RawURLEncoding.DecodeString(k.E)
		if err1 != nil || err2 != nil {
			continue
		}
		eInt := 0
		for _, b := range eBytes {
			eInt = (eInt << 8) | int(b)
		}
		a.jwksKeys[k.Kid] = &rsa.PublicKey{
			N: new(big.Int).SetBytes(nBytes),
			E: eInt,
		}
	}
	a.jwksFetch = time.Now()
	return nil
}

func (a *Authenticator) getJWKSKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	a.jwksMu.RLock()
	key, ok := a.jwksKeys[kid]
	fresh := time.Since(a.jwksFetch) < 1*time.Hour
	a.jwksMu.RUnlock()
	if ok && fresh {
		return key, nil
	}

	jwksURL := strings.TrimRight(a.cfg.GitHubOIDCIssuerURL, "/") + "/.well-known/jwks"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		if ok {
			return key, nil // Fallback to cached key inside private VPC if egress is unreachable
		}
		return nil, err
	}
	defer resp.Body.Close()

	var buf []byte
	buf = make([]byte, 64*1024)
	n, _ := resp.Body.Read(buf)
	if err := a.loadJWKSFromJSON(buf[:n]); err != nil {
		return nil, err
	}

	a.jwksMu.RLock()
	defer a.jwksMu.RUnlock()
	if k, found := a.jwksKeys[kid]; found {
		return k, nil
	}
	return nil, fmt.Errorf("kid %q not found in JWKS", kid)
}

