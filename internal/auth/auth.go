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
	"io"
	"math/big"
	"net/http"
	"strconv"
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

	cfgMu                  sync.RWMutex
	adminOIDCGroup         string
	githubOIDCEnabled      bool
	githubOIDCIssuerURL    string
	githubOIDCAudience     string
	jwtProviders           []model.JWTProviderConfig
	anonymousAccessEnabled bool

	credCacheMu sync.RWMutex
	credCache   map[string]time.Time

	jwksMu    sync.RWMutex
	jwksKeys  map[string]*rsa.PublicKey
	jwksFetch time.Time
}

// NewAuthenticator creates a new Authenticator.
func NewAuthenticator(cfg *config.Config, st store.MetadataStore, eval *rbac.Evaluator) *Authenticator {
	a := &Authenticator{
		cfg:                 cfg,
		store:               st,
		evaluator:           eval,
		adminOIDCGroup:      cfg.BootstrapAdminOIDCGroup,
		githubOIDCEnabled:   cfg.GitHubOIDCEnabled,
		githubOIDCIssuerURL: cfg.GitHubOIDCIssuerURL,
		githubOIDCAudience:     cfg.GitHubOIDCAudience,
		anonymousAccessEnabled: cfg.AnonymousAccessEnabled,
		credCache:              make(map[string]time.Time),
		jwksKeys:            make(map[string]*rsa.PublicKey),
	}
	if cfg.GitHubPinnedJWKSJSON != "" {
		_ = a.loadJWKSFromJSON([]byte(cfg.GitHubPinnedJWKSJSON))
	}
	return a
}

// UpdateAuthConfig updates runtime-mutable OIDC and JWT configuration under a write lock.
func (a *Authenticator) UpdateAuthConfig(
	adminOIDCGroup string,
	githubOIDCEnabled bool,
	githubOIDCIssuerURL string,
	githubOIDCAudience string,
	jwtProviders []model.JWTProviderConfig,
) {
	a.cfgMu.Lock()
	defer a.cfgMu.Unlock()
	if adminOIDCGroup != "" {
		a.adminOIDCGroup = adminOIDCGroup
	}
	a.githubOIDCEnabled = githubOIDCEnabled
	a.githubOIDCIssuerURL = githubOIDCIssuerURL
	a.githubOIDCAudience = githubOIDCAudience
	if len(jwtProviders) > 0 {
		cp := make([]model.JWTProviderConfig, len(jwtProviders))
		copy(cp, jwtProviders)
		a.jwtProviders = cp
	}
}

// SetAnonymousAccessEnabled dynamically enables or disables unauthenticated anonymous access.
func (a *Authenticator) SetAnonymousAccessEnabled(enabled bool) {
	a.cfgMu.Lock()
	defer a.cfgMu.Unlock()
	a.anonymousAccessEnabled = enabled
}

// IsAnonymousAccessEnabled returns whether unauthenticated anonymous access is currently enabled.
func (a *Authenticator) IsAnonymousAccessEnabled() bool {
	a.cfgMu.RLock()
	defer a.cfgMu.RUnlock()
	return a.anonymousAccessEnabled
}

func (a *Authenticator) getAdminOIDCGroup() string {
	a.cfgMu.RLock()
	defer a.cfgMu.RUnlock()
	return a.adminOIDCGroup
}

func (a *Authenticator) getJWTConfig() (bool, string, string, []model.JWTProviderConfig) {
	a.cfgMu.RLock()
	defer a.cfgMu.RUnlock()
	var providers []model.JWTProviderConfig
	if len(a.jwtProviders) > 0 {
		providers = make([]model.JWTProviderConfig, len(a.jwtProviders))
		copy(providers, a.jwtProviders)
	}
	return a.githubOIDCEnabled, a.githubOIDCIssuerURL, a.githubOIDCAudience, providers
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
	iters, err := strconv.Atoi(parts[1])
	if err != nil || iters < 1000 {
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
	actual := deriveKey([]byte(secret), salt, iters)
	return hmac.Equal(actual, expected)
}

func (a *Authenticator) verifySecretCached(secret, encodedHash string) bool {
	if secret == "" || encodedHash == "" {
		return false
	}
	sum := sha256.Sum256([]byte(encodedHash + "\x00" + secret))
	cacheKey := hex.EncodeToString(sum[:])
	now := time.Now()

	a.credCacheMu.RLock()
	exp, ok := a.credCache[cacheKey]
	a.credCacheMu.RUnlock()
	if ok && now.Before(exp) {
		return true
	}

	if !VerifySecret(secret, encodedHash) {
		return false
	}

	a.credCacheMu.Lock()
	if len(a.credCache) > 1024 {
		for k, v := range a.credCache {
			if now.After(v) {
				delete(a.credCache, k)
			}
		}
	}
	a.credCache[cacheKey] = now.Add(60 * time.Second)
	a.credCacheMu.Unlock()
	return true
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

// GenerateRandomPassword generates a cryptographically random password of the given length without modulo bias.
func GenerateRandomPassword(length int) (string, error) {
	if length < 12 {
		length = 20
	}
	const charset = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#%^&*-_=+"
	max := big.NewInt(int64(len(charset)))
	out := make([]byte, length)
	for i := 0; i < length; i++ {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		out[i] = charset[n.Int64()]
	}
	return string(out), nil
}

type sessionPayload struct {
	PrincipalType model.PrincipalType `json:"type,omitempty"`
	Username      string              `json:"username,omitempty"`
	ID            string              `json:"id"`
	Email         string              `json:"email"`
	DisplayName   string              `json:"name"`
	SlackLink     string              `json:"slack_link,omitempty"`
	OIDCGroups    []string            `json:"groups"`
	IssuedAt      int64               `json:"iat"`
	ExpiresAt     int64               `json:"exp"`
}

// IssueLocalSessionCookie signs and sets an HttpOnly session cookie for a local user account.
func (a *Authenticator) IssueLocalSessionCookie(w http.ResponseWriter, user *model.LocalUser) error {
	var groups []string
	adminGrp := a.getAdminOIDCGroup()
	if user.IsAdmin && adminGrp != "" {
		groups = []string{adminGrp}
	}
	now := time.Now()
	payload := sessionPayload{
		PrincipalType: model.PrincipalLocalUser,
		Username:      user.Username,
		ID:            user.Username,
		Email:         user.Email,
		DisplayName:   user.DisplayName,
		SlackLink:     user.SlackLink,
		OIDCGroups:    groups,
		IssuedAt:      now.Unix(),
		ExpiresAt:     now.Add(12 * time.Hour).Unix(),
	}
	return a.writeSessionCookie(w, payload)
}

// IssueSessionCookie signs and sets an HttpOnly session cookie for an SSO user.
func (a *Authenticator) IssueSessionCookie(w http.ResponseWriter, email, displayName string, oidcGroups []string) error {
	return a.IssueSessionCookieWithSlack(w, email, displayName, "", oidcGroups)
}

// IssueSessionCookieWithSlack signs and sets an HttpOnly session cookie for an SSO user with Slack handle.
func (a *Authenticator) IssueSessionCookieWithSlack(w http.ResponseWriter, email, displayName, slackLink string, oidcGroups []string) error {
	now := time.Now()
	payload := sessionPayload{
		PrincipalType: model.PrincipalSSOUser,
		ID:            email,
		Email:         email,
		DisplayName:   displayName,
		SlackLink:     slackLink,
		OIDCGroups:    oidcGroups,
		IssuedAt:      now.Unix(),
		ExpiresAt:     now.Add(12 * time.Hour).Unix(),
	}
	return a.writeSessionCookie(w, payload)
}

func (a *Authenticator) writeSessionCookie(w http.ResponseWriter, payload sessionPayload) error {
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

// AuthenticateLocalUser verifies a local user's username or email and password, ensuring the account is not disabled.
func (a *Authenticator) AuthenticateLocalUser(ctx context.Context, usernameOrEmail, password string) (*model.LocalUser, error) {
	usernameOrEmail = strings.TrimSpace(usernameOrEmail)
	if usernameOrEmail == "" || password == "" {
		return nil, errors.New("username and password are required")
	}
	user, err := a.store.GetLocalUser(ctx, usernameOrEmail)
	if err != nil {
		return nil, errors.New("invalid username or password")
	}
	if user.Disabled {
		return nil, errors.New("local account is disabled")
	}
	if !a.verifySecretCached(password, user.PasswordHash) {
		return nil, errors.New("invalid username or password")
	}
	now := time.Now().UTC()
	user.LastLoginAt = &now
	_ = a.store.TouchLocalUserLogin(ctx, user.Username, now)
	return user, nil
}

// AuthenticateRequest inspects the HTTP request for:
// 1. HTTP Basic Auth (Local User Account OR Service Account — e.g., HTML Raw Access / CLI)
// 2. HTTP Bearer Token (Service Account "s3w_..." OR CI OIDC JWT "eyJ...")
// 3. Encrypted Session Cookie (Authenticated Local User or SSO User)
// Anonymous access is strictly disabled.
func (a *Authenticator) AuthenticateRequest(r *http.Request) (*model.Principal, error) {
	ctx := r.Context()

	// 1. Check HTTP Basic Auth (Local User Account OR HTML Raw Access / CLI Service Account)
	if username, password, ok := r.BasicAuth(); ok && username != "" {
		if existingUser, err := a.store.GetLocalUser(ctx, username); err == nil && existingUser != nil {
			user, authErr := a.AuthenticateLocalUser(ctx, username, password)
			if authErr != nil {
				return nil, authErr
			}
			return a.principalFromLocalUser(ctx, user)
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

	// 3. Check Session Cookie (Authenticated Local User or Human SSO User)
	if cookie, err := r.Cookie(SessionCookieName); err == nil && cookie.Value != "" {
		return a.authenticateSessionCookie(ctx, cookie.Value)
	}

	// 4. Check if Anonymous Access is enabled
	if a.IsAnonymousAccessEnabled() {
		p := &model.Principal{
			Type:        model.PrincipalAnonymous,
			ID:          "anonymous",
			Username:    "anonymous",
			DisplayName: "Anonymous Guest",
			OIDCGroups:  []string{"anonymous"},
		}
		return a.enrichPrincipal(ctx, p)
	}

	// Anonymous access is disabled.
	return nil, errors.New("authentication required")
}

func (a *Authenticator) principalFromLocalUser(ctx context.Context, user *model.LocalUser) (*model.Principal, error) {
	var oidcGroups []string
	adminGrp := a.getAdminOIDCGroup()
	if user.IsAdmin && adminGrp != "" {
		oidcGroups = []string{adminGrp}
	}
	displayName := user.DisplayName
	if displayName == "" {
		displayName = user.Username
	}
	p := &model.Principal{
		Type:         model.PrincipalLocalUser,
		ID:           user.Username,
		Username:     user.Username,
		Email:        user.Email,
		DisplayName:  displayName,
		SlackLink:    user.SlackLink,
		IsLocalAdmin: user.IsAdmin,
		OIDCGroups:   oidcGroups,
	}
	return a.enrichPrincipal(ctx, p)
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
	if payload.PrincipalType == model.PrincipalLocalUser || payload.Username != "" {
		lookupKey := payload.Username
		if lookupKey == "" {
			lookupKey = payload.ID
		}
		user, err := a.store.GetLocalUser(ctx, lookupKey)
		if err != nil {
			return nil, errors.New("local account not found")
		}
		if user.Disabled {
			return nil, errors.New("local account is disabled")
		}
		if user.PasswordChangedAt != nil && payload.IssuedAt > 0 && payload.IssuedAt < user.PasswordChangedAt.Unix() {
			return nil, errors.New("session invalidated by password change")
		}
		return a.principalFromLocalUser(ctx, user)
	}
	// Also check if an SSO session matches a local user that has been disabled
	if u, err := a.store.GetLocalUser(ctx, payload.Email); err == nil && u != nil && u.Disabled {
		return nil, errors.New("local account is disabled")
	}
	p := &model.Principal{
		Type:        model.PrincipalSSOUser,
		ID:          payload.Email,
		Email:       payload.Email,
		DisplayName: payload.DisplayName,
		SlackLink:   payload.SlackLink,
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
	if !a.verifySecretCached(secret, sa.SecretHash) {
		return nil, errors.New("invalid service account secret")
	}
	now := time.Now().UTC()
	_ = a.store.TouchServiceAccountUsed(ctx, sa.AccountID, now)

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
	ghEnabled, ghIssuer, ghAudience, jwtProviders := a.getJWTConfig()
	if !ghEnabled {
		return nil, errors.New("CI OIDC JWT authentication is disabled")
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
		pubKey, err := a.getJWKSKey(ctx, hdr.Kid, ghIssuer)
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

	// Require exp claim and verify token has not expired
	expVal, hasExp := claims["exp"].(float64)
	if !hasExp || time.Now().Unix() > int64(expVal) {
		return nil, errors.New("CI OIDC JWT is missing exp or has expired")
	}
	if nbfVal, hasNbf := claims["nbf"].(float64); hasNbf && time.Now().Unix() < int64(nbfVal)-60 {
		return nil, errors.New("CI OIDC JWT is not yet valid (nbf)")
	}

	// Validate iss and aud against configured JWT providers (or primary GitHub OIDC config)
	iss, _ := claims["iss"].(string)
	if !validateJWTIssuerAndAudience(iss, claims["aud"], ghIssuer, ghAudience, jwtProviders) {
		return nil, errors.New("CI OIDC JWT issuer or audience does not match configured trust providers")
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

func validateJWTIssuerAndAudience(
	tokenIss string,
	rawAud interface{},
	defaultIssuer string,
	defaultAudience string,
	providers []model.JWTProviderConfig,
) bool {
	normIss := strings.TrimRight(strings.TrimSpace(tokenIss), "/")
	if len(providers) == 0 {
		providers = []model.JWTProviderConfig{
			{
				Enabled:   true,
				IssuerURL: defaultIssuer,
				Audience:  defaultAudience,
			},
		}
	}
	for _, prov := range providers {
		if !prov.Enabled {
			continue
		}
		expectedIss := strings.TrimRight(strings.TrimSpace(prov.IssuerURL), "/")
		if expectedIss != "" && !strings.EqualFold(normIss, expectedIss) {
			continue
		}
		expectedAud := strings.TrimRight(strings.TrimSpace(prov.Audience), "/")
		if expectedAud != "" && !audienceClaimMatches(rawAud, expectedAud) {
			continue
		}
		return true
	}
	return false
}

func audienceClaimMatches(rawAud interface{}, expectedAud string) bool {
	switch v := rawAud.(type) {
	case string:
		return strings.EqualFold(strings.TrimRight(strings.TrimSpace(v), "/"), expectedAud)
	case []interface{}:
		for _, item := range v {
			if s, ok := item.(string); ok && strings.EqualFold(strings.TrimRight(strings.TrimSpace(s), "/"), expectedAud) {
				return true
			}
		}
	}
	return false
}

func (a *Authenticator) enrichPrincipal(ctx context.Context, p *model.Principal) (*model.Principal, error) {
	if p.Type == model.PrincipalSSOUser || p.Type == model.PrincipalLocalUser {
		groupSet := make(map[string]struct{})
		var merged []string
		for _, id := range []string{p.Email, p.Username, p.ID} {
			if id == "" {
				continue
			}
			if groups, err := a.store.GetUserAppGroups(ctx, id); err == nil {
				for _, g := range groups {
					if _, exists := groupSet[g]; !exists {
						groupSet[g] = struct{}{}
						merged = append(merged, g)
					}
				}
			}
		}
		p.AppGroups = merged
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
	_, ghIssuer, ghAudience, _ := a.getJWTConfig()
	hdr := map[string]string{"alg": "HS256", "typ": "JWT"}
	claims := map[string]interface{}{
		"iss":          ghIssuer,
		"aud":          ghAudience,
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

func (a *Authenticator) getJWKSKey(ctx context.Context, kid string, issuerURL string) (*rsa.PublicKey, error) {
	a.jwksMu.RLock()
	key, ok := a.jwksKeys[kid]
	fresh := time.Since(a.jwksFetch) < 1*time.Hour
	a.jwksMu.RUnlock()
	if ok && fresh {
		return key, nil
	}

	jwksURL := strings.TrimRight(issuerURL, "/") + "/.well-known/jwks"
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

	if resp.StatusCode != http.StatusOK {
		if ok {
			return key, nil
		}
		return nil, fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}
	rawBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if readErr != nil {
		return nil, readErr
	}
	if err := a.loadJWKSFromJSON(rawBody); err != nil {
		return nil, err
	}

	a.jwksMu.RLock()
	defer a.jwksMu.RUnlock()
	if k, found := a.jwksKeys[kid]; found {
		return k, nil
	}
	return nil, fmt.Errorf("kid %q not found in JWKS", kid)
}
