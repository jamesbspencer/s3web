package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"mime"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"s3web/internal/auth"
	"s3web/internal/config"
	"s3web/internal/model"
	"s3web/internal/rbac"
	"s3web/internal/storage"
	"s3web/internal/store"
	"s3web/internal/ui"
)

// Server wires together the Web UI, REST API, HTML Raw Access (/raw), In-App RBAC, and Access Logger.
type Server struct {
	cfg         *config.Config
	store       store.MetadataStore
	storage     storage.ObjectStorage
	evaluator   *rbac.Evaluator
	authn       *auth.Authenticator
	mux         *http.ServeMux
	uiAssets    http.FileSystem
	settingsMu  sync.RWMutex
	settings    model.AppSettings
}

// New creates and initializes a new Server instance.
func New(cfg *config.Config, st store.MetadataStore, objStore storage.ObjectStorage) (*Server, error) {
	eval := rbac.NewEvaluator(st)
	authn := auth.NewAuthenticator(cfg, st, eval)

	s := &Server{
		cfg:       cfg,
		store:     st,
		storage:   objStore,
		evaluator: eval,
		authn:     authn,
		mux:       http.NewServeMux(),
		uiAssets:  ui.FileSystem(),
		settings: model.AppSettings{
			RepositoryTitle:          "s3web — S3 Artifact Repository",
			DefaultTreeState:         "expanded",
			EnableHTMLAutoindex:      true,
			EnableChecksumSidecars:   true,
			DefaultRestoreDays:       7,
			DefaultRestoreTier:       "Standard",
			AccessLogRetentionDays:   cfg.AccessLogRetentionDays,
			OIDCEnabled:              cfg.OIDCEnabled,
			OIDCIssuerURL:            cfg.OIDCIssuerURL,
			OIDCClientID:             cfg.OIDCClientID,
			OIDCGroupsClaim:          cfg.OIDCGroupsClaim,
			BootstrapAdminOIDCGroup:  cfg.BootstrapAdminOIDCGroup,
			GitHubOIDCEnabled:        cfg.GitHubOIDCEnabled,
			GitHubOIDCIssuerURL:      cfg.GitHubOIDCIssuerURL,
			GitHubOIDCAudience:       cfg.GitHubOIDCAudience,
			SSOProviders: []model.SSOProviderConfig{
				{
					ID:          "sso-default",
					Name:        "Corporate OIDC SSO",
					Enabled:     cfg.OIDCEnabled,
					IssuerURL:   cfg.OIDCIssuerURL,
					ClientID:    cfg.OIDCClientID,
					GroupsClaim: cfg.OIDCGroupsClaim,
					AdminGroup:  cfg.BootstrapAdminOIDCGroup,
				},
			},
			JWTProviders: []model.JWTProviderConfig{
				{
					ID:            "jwt-github-actions",
					Name:          "GitHub Actions OIDC",
					Enabled:       cfg.GitHubOIDCEnabled,
					IssuerURL:     cfg.GitHubOIDCIssuerURL,
					Audience:      cfg.GitHubOIDCAudience,
					SubjectPrefix: "repo:",
				},
			},
			BackendMode:              cfg.BackendMode,
			AWSRegion:                cfg.AWSRegion,
			S3Bucket:                 cfg.S3Bucket,
			Buckets: []model.BucketMount{
				{
					ID:           "primary",
					FriendlyName: "Primary Artifacts",
					BucketName:   cfg.S3Bucket,
					Region:       cfg.AWSRegion,
				},
			},
			DynamoDBTable:            cfg.DynamoDBTable,
			SQSQueueURL:              cfg.SQSQueueURL,
			BootstrapNexusAccountID:  cfg.BootstrapNexusAccountID,
			UpdatedBy:                "system",
			UpdatedAt:                time.Now().UTC(),
		},
	}

	if err := s.seedBootstrapData(context.Background()); err != nil {
		return nil, fmt.Errorf("seed bootstrap data: %w", err)
	}
	s.registerRoutes()
	return s, nil
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Security headers for private VPC deployment
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	s.mux.ServeHTTP(w, r)
}

func (s *Server) registerRoutes() {
	// Healthcheck for AWS Internal ALB Target Group
	s.mux.HandleFunc("/healthz", s.handleHealthz)

	// Authentication & Local Account Password Endpoints
	s.mux.HandleFunc("/auth/login", s.handleAuthLogin)
	s.mux.HandleFunc("/auth/logout", s.handleAuthLogout)
	s.mux.HandleFunc("/api/v1/auth/password", s.withAuth(s.handleChangeOwnPassword))
	s.mux.HandleFunc("/api/v1/auth/session", s.withAuth(s.handleSwitchSession))
	s.mux.HandleFunc("/api/v1/auth/github-test-jwt", s.withAuth(s.handleMintTestGitHubJWT))

	// HTML Raw Access & Apache/Nginx autoindex Repository Endpoint (uses identical access control as default UI)
	s.mux.HandleFunc("/raw", s.withAuth(s.handleRawProxy))
	s.mux.HandleFunc("/raw/", s.withAuth(s.handleRawProxy))

	// Web UI API Endpoints
	s.mux.HandleFunc("/api/v1/me", s.withAuth(s.handleMe))
	s.mux.HandleFunc("/api/v1/browse", s.withAuth(s.handleBrowse))
	s.mux.HandleFunc("/api/v1/search", s.withAuth(s.handleSearch))
	s.mux.HandleFunc("/api/v1/objects/", s.withAuth(s.handleObjectsRouter))

	// In-App Permission Management, Local Accounts, App Groups, Service Accounts & Settings (Admin Console)
	s.mux.HandleFunc("/api/v1/admin/local-users", s.withAuth(s.handleAdminLocalUsers))
	s.mux.HandleFunc("/api/v1/admin/local-users/", s.withAuth(s.handleAdminLocalUsersByID))
	s.mux.HandleFunc("/api/v1/admin/grants", s.withAuth(s.handleAdminGrants))
	s.mux.HandleFunc("/api/v1/admin/grants/", s.withAuth(s.handleAdminGrantsByID))
	s.mux.HandleFunc("/api/v1/admin/groups", s.withAuth(s.handleAdminGroups))
	s.mux.HandleFunc("/api/v1/admin/groups/", s.withAuth(s.handleAdminGroupsByName))
	s.mux.HandleFunc("/api/v1/admin/service-accounts", s.withAuth(s.handleAdminServiceAccounts))
	s.mux.HandleFunc("/api/v1/admin/service-accounts/", s.withAuth(s.handleAdminServiceAccountsByID))
	s.mux.HandleFunc("/api/v1/settings", s.withAuth(s.handleSettings))

	// Embedded Self-Contained Web UI Assets (Zero external CDN calls)
	s.mux.Handle("/", http.FileServer(s.uiAssets))
}

func (s *Server) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, err := s.authn.AuthenticateRequest(r)
		if err != nil {
			if strings.HasPrefix(r.URL.Path, "/raw") {
				w.Header().Set("WWW-Authenticate", `Basic realm="s3web"`)
			}
			writeJSONError(w, http.StatusUnauthorized, err.Error())
			return
		}
		next(w, r.WithContext(auth.WithPrincipal(r.Context(), p)))
	}
}

func (s *Server) withRawAuth(next http.HandlerFunc) http.HandlerFunc {
	return s.withAuth(next)
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":         "ok",
		"service":        "s3web",
		"bucket":         s.cfg.S3Bucket,
		"storage_class":  "INTELLIGENT_TIERING",
		"network_mode":   "private-vpc-vpn-only",
		"backend_mode":   s.cfg.BackendMode,
		"timestamp_utc":  time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "POST required for login")
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		_ = json.NewDecoder(r.Body).Decode(&req)
	} else {
		_ = r.ParseForm()
		req.Username = r.FormValue("username")
		req.Password = r.FormValue("password")
	}
	user, err := s.authn.AuthenticateLocalUser(r.Context(), req.Username, req.Password)
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, err.Error())
		return
	}
	if err := s.authn.IssueLocalSessionCookie(w, user); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":       "authenticated",
		"username":     user.Username,
		"email":        user.Email,
		"display_name": user.DisplayName,
		"is_admin":     user.IsAdmin,
	})
}

func (s *Server) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	s.authn.ClearSessionCookie(w)
	if strings.Contains(r.Header.Get("Accept"), "application/json") || r.Method == http.MethodPost {
		writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) handleChangeOwnPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	p := auth.PrincipalFromContext(r.Context())
	if p == nil || p.Type != model.PrincipalLocalUser {
		writeJSONError(w, http.StatusBadRequest, "password self-service is only available for local accounts")
		return
	}
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if strings.TrimSpace(req.CurrentPassword) == "" || strings.TrimSpace(req.NewPassword) == "" {
		writeJSONError(w, http.StatusBadRequest, "current_password and new_password are required")
		return
	}
	if len(strings.TrimSpace(req.NewPassword)) < 6 {
		writeJSONError(w, http.StatusBadRequest, "new_password must be at least 6 characters")
		return
	}
	user, err := s.store.GetLocalUser(r.Context(), p.Username)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "local account not found")
		return
	}
	if user.Disabled {
		writeJSONError(w, http.StatusForbidden, "local account is disabled")
		return
	}
	if !auth.VerifySecret(req.CurrentPassword, user.PasswordHash) {
		writeJSONError(w, http.StatusUnauthorized, "current password is incorrect")
		return
	}
	newHash, err := auth.HashSecret(req.NewPassword)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	now := time.Now().UTC()
	user.PasswordHash = newHash
	user.PasswordChangedAt = &now
	if err := s.store.UpsertLocalUser(r.Context(), user); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.authn.IssueLocalSessionCookie(w, user)
	writeJSON(w, http.StatusOK, map[string]string{
		"status":   "password_updated",
		"username": user.Username,
	})
}

func (s *Server) handleSwitchSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	p := auth.PrincipalFromContext(r.Context())
	if p == nil || !p.EffectivePerm.IsAdmin {
		writeJSONError(w, http.StatusForbidden, "admin permission required")
		return
	}
	var req struct {
		Email      string   `json:"email"`
		Name       string   `json:"name"`
		OIDCGroups []string `json:"oidc_groups"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if strings.TrimSpace(req.Email) == "" {
		writeJSONError(w, http.StatusBadRequest, "email is required")
		return
	}
	if req.Name == "" {
		req.Name = req.Email
	}
	if err := s.authn.IssueSessionCookie(w, req.Email, req.Name, req.OIDCGroups); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "email": req.Email})
}

func (s *Server) handleMintTestGitHubJWT(w http.ResponseWriter, r *http.Request) {
	p := auth.PrincipalFromContext(r.Context())
	if !p.EffectivePerm.IsAdmin {
		writeJSONError(w, http.StatusForbidden, "admin permission required")
		return
	}
	var req struct {
		Repository  string `json:"repository"`
		Ref         string `json:"ref"`
		Environment string `json:"environment"`
		Actor       string `json:"actor"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.Repository == "" {
		req.Repository = "my-org/iso-builder"
	}
	if req.Ref == "" {
		req.Ref = "refs/heads/main"
	}
	if req.Environment == "" {
		req.Environment = "production"
	}
	if req.Actor == "" {
		req.Actor = p.ID
	}
	token, err := s.authn.MintTestGitHubJWT(req.Repository, req.Ref, req.Environment, req.Actor)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"jwt":          token,
		"subject":      fmt.Sprintf("repo:%s:ref:%s", req.Repository, req.Ref),
		"curl_example": fmt.Sprintf(`curl -H "Authorization: Bearer %s" -T ./sample.iso "%s/api/v1/objects/isos/nightly/sample.iso"`, token, s.cfg.BaseURL),
	})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	p := auth.PrincipalFromContext(r.Context())
	prefix := strings.TrimSpace(r.URL.Query().Get("prefix"))
	perm, err := s.evaluator.Resolve(r.Context(), p, prefix)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"principal":             p,
		"prefix":                prefix,
		"effective_permissions": perm,
		"bucket":                s.cfg.S3Bucket,
		"base_url":              s.cfg.BaseURL,
	})
}

func (s *Server) handleBrowse(w http.ResponseWriter, r *http.Request) {
	p := auth.PrincipalFromContext(r.Context())
	prefix := strings.TrimSpace(r.URL.Query().Get("prefix"))
	tierFilter := strings.TrimSpace(r.URL.Query().Get("tier"))

	perm, err := s.evaluator.Resolve(r.Context(), p, prefix)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !perm.CanRead {
		writeJSONError(w, http.StatusForbidden, "read permission denied for prefix")
		return
	}

	entries, err := s.store.ListDirectory(r.Context(), prefix, tierFilter)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"bucket":                s.cfg.S3Bucket,
		"prefix":                prefix,
		"tier_filter":           tierFilter,
		"entries":               entries,
		"effective_permissions": perm,
	})
}

func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	p := auth.PrincipalFromContext(r.Context())
	if !p.EffectivePerm.CanRead {
		writeJSONError(w, http.StatusForbidden, "read permission required")
		return
	}
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	tier := strings.TrimSpace(r.URL.Query().Get("tier"))
	rawResults, err := s.store.SearchObjects(r.Context(), q, tier)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	results := make([]model.ObjectMeta, 0, len(rawResults))
	for _, item := range rawResults {
		if perm, permErr := s.evaluator.Resolve(r.Context(), p, item.Key); permErr == nil && perm.CanRead {
			results = append(results, item)
		}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"query":   q,
		"tier":    tier,
		"results": results,
	})
}

// handleObjectsRouter routes /api/v1/objects/{key...} actions:
// - GET /api/v1/objects/{key}/meta
// - GET /api/v1/objects/{key}/logs
// - GET /api/v1/objects/{key}/download
// - POST /api/v1/objects/{key}/restore
// - POST /api/v1/objects/{key}/tier (admin/testing tier transition simulation)
// - POST or PUT /api/v1/objects/{key} (streaming upload with SHA-256 + SHA-1 computation)
// - DELETE /api/v1/objects/{key}
func (s *Server) handleObjectsRouter(w http.ResponseWriter, r *http.Request) {
	rawPath := strings.TrimPrefix(r.URL.Path, "/api/v1/objects/")
	rawPath = strings.TrimLeft(rawPath, "/")
	if rawPath == "" {
		writeJSONError(w, http.StatusBadRequest, "object key is required")
		return
	}

	switch {
	case r.Method == http.MethodGet && strings.HasSuffix(rawPath, "/meta"):
		key := strings.TrimSuffix(rawPath, "/meta")
		s.handleObjectMeta(w, r, key)
	case r.Method == http.MethodGet && strings.HasSuffix(rawPath, "/logs"):
		key := strings.TrimSuffix(rawPath, "/logs")
		s.handleObjectLogs(w, r, key)
	case r.Method == http.MethodGet && strings.HasSuffix(rawPath, "/download"):
		key := strings.TrimSuffix(rawPath, "/download")
		s.streamObjectDownload(w, r, key, true)
	case r.Method == http.MethodPost && strings.HasSuffix(rawPath, "/restore"):
		key := strings.TrimSuffix(rawPath, "/restore")
		s.handleObjectRestore(w, r, key)
	case r.Method == http.MethodPost && strings.HasSuffix(rawPath, "/tier"):
		key := strings.TrimSuffix(rawPath, "/tier")
		s.handleObjectTierUpdate(w, r, key)
	case r.Method == http.MethodPost || r.Method == http.MethodPut:
		s.handleObjectUpload(w, r, rawPath)
	case r.Method == http.MethodDelete:
		s.handleObjectDelete(w, r, rawPath)
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "unsupported object operation")
	}
}

func (s *Server) handleObjectMeta(w http.ResponseWriter, r *http.Request, key string) {
	p := auth.PrincipalFromContext(r.Context())
	perm, err := s.evaluator.Resolve(r.Context(), p, key)
	if err != nil || !perm.CanRead {
		writeJSONError(w, http.StatusForbidden, "read permission denied")
		return
	}
	meta, err := s.store.GetObjectMeta(r.Context(), key)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeJSONError(w, http.StatusNotFound, "object not found")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, meta)
}

func (s *Server) handleObjectLogs(w http.ResponseWriter, r *http.Request, key string) {
	p := auth.PrincipalFromContext(r.Context())
	perm, err := s.evaluator.Resolve(r.Context(), p, key)
	if err != nil || !perm.CanRead {
		writeJSONError(w, http.StatusForbidden, "read permission denied")
		return
	}
	actionFilter := r.URL.Query().Get("action")
	actorFilter := r.URL.Query().Get("actor")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	logs, err := s.store.ListObjectAccessLogs(r.Context(), key, actionFilter, actorFilter, limit)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"object_key": key,
		"logs":       logs,
	})
}

func (s *Server) handleObjectUpload(w http.ResponseWriter, r *http.Request, key string) {
	start := time.Now()
	p := auth.PrincipalFromContext(r.Context())
	perm, err := s.evaluator.Resolve(r.Context(), p, key)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !perm.CanUpload {
		writeJSONError(w, http.StatusForbidden, fmt.Sprintf("in-app upload permission required for prefix %q", key))
		return
	}

	var reader io.Reader = r.Body
	contentType := r.Header.Get("Content-Type")
	if strings.HasPrefix(contentType, "multipart/form-data") {
		file, header, err := r.FormFile("file")
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "missing multipart 'file' field: "+err.Error())
			return
		}
		defer file.Close()
		reader = file
		contentType = header.Header.Get("Content-Type")
	}
	if contentType == "" || strings.HasPrefix(contentType, "multipart/") {
		contentType = detectContentType(key)
	}

	putRes, err := s.storage.PutStream(r.Context(), key, reader, contentType)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "upload failed: "+err.Error())
		return
	}

	now := time.Now().UTC()
	bucketName := strings.TrimSpace(r.URL.Query().Get("bucket"))
	if bucketName == "" {
		bucketName = s.cfg.S3Bucket
	}
	meta := &model.ObjectMeta{
		Key:             putRes.Key,
		BucketName:      bucketName,
		Size:            putRes.Size,
		ContentType:     contentType,
		StorageClass:    "INTELLIGENT_TIERING",
		IntelligentTier: model.TierFrequentAccess,
		RestoreStatus:   model.RestoreNone,
		SHA256:          putRes.SHA256,
		SHA1:            putRes.SHA1,
		HashStatus:      model.HashReady,
		S3ETag:          putRes.ETag,
		UploadedBy:      p.ID,
		UpdatedAt:       now,
		LastAccessedAt:  now,
	}
	if err := s.store.PutObjectMeta(r.Context(), meta); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to save object metadata: "+err.Error())
		return
	}

	s.recordAccessLog(r, p, meta.Key, model.ActionUpload, putRes.Size, http.StatusCreated, false, time.Since(start))
	saved, _ := s.store.GetObjectMeta(r.Context(), meta.Key)
	writeJSON(w, http.StatusCreated, saved)
}

func (s *Server) handleObjectDelete(w http.ResponseWriter, r *http.Request, key string) {
	start := time.Now()
	p := auth.PrincipalFromContext(r.Context())
	perm, err := s.evaluator.Resolve(r.Context(), p, key)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !perm.CanDelete {
		writeJSONError(w, http.StatusForbidden, fmt.Sprintf("in-app delete permission required for prefix %q", key))
		return
	}

	if err := s.storage.Delete(r.Context(), key); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "storage delete failed: "+err.Error())
		return
	}
	if err := s.store.DeleteObjectMeta(r.Context(), key); err != nil && !errors.Is(err, store.ErrNotFound) {
		writeJSONError(w, http.StatusInternalServerError, "metadata delete failed: "+err.Error())
		return
	}

	s.recordAccessLog(r, p, key, model.ActionDelete, 0, http.StatusOK, false, time.Since(start))
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted", "key": key})
}

func (s *Server) handleObjectRestore(w http.ResponseWriter, r *http.Request, key string) {
	start := time.Now()
	p := auth.PrincipalFromContext(r.Context())
	perm, err := s.evaluator.Resolve(r.Context(), p, key)
	if err != nil || !perm.CanRead {
		writeJSONError(w, http.StatusForbidden, "permission denied")
		return
	}
	s.settingsMu.RLock()
	restoreDays := s.settings.DefaultRestoreDays
	s.settingsMu.RUnlock()
	if restoreDays <= 0 {
		restoreDays = 7
	}
	if err := s.storage.Restore(r.Context(), key, restoreDays); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Transition object back to Frequent Access (FA) with RestoreRestored status
	if err := s.store.UpdateObjectTier(r.Context(), key, model.TierFrequentAccess, model.RestoreRestored); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.recordAccessLog(r, p, key, model.ActionRestore, 0, http.StatusAccepted, false, time.Since(start))
	meta, _ := s.store.GetObjectMeta(r.Context(), key)
	writeJSON(w, http.StatusAccepted, meta)
}

func (s *Server) handleObjectTierUpdate(w http.ResponseWriter, r *http.Request, key string) {
	p := auth.PrincipalFromContext(r.Context())
	perm, err := s.evaluator.Resolve(r.Context(), p, key)
	if err != nil || (!perm.IsAdmin && !perm.CanUpload) {
		writeJSONError(w, http.StatusForbidden, "admin or upload permission required to change tier")
		return
	}
	var req struct {
		IntelligentTier model.IntelligentTier `json:"intelligent_tier"`
		RestoreStatus   model.RestoreStatus   `json:"restore_status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if err := s.store.UpdateObjectTier(r.Context(), key, req.IntelligentTier, req.RestoreStatus); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	meta, _ := s.store.GetObjectMeta(r.Context(), key)
	writeJSON(w, http.StatusOK, meta)
}

// handleRawProxy serves /raw/{key...} for HTML Raw Access, curl/wget, and browser direct links:
// 1. HTML Directory Index ("autoindex" style) when path is a folder.
// 2. Virtual .sha256 and .sha1 sidecar files served directly from DynamoDB metadata.
// 3. HEAD and GET (with Range support, ETag, X-Checksum-Sha256, X-Checksum-Sha1, X-Amz-Storage-Class, X-Amz-Intelligent-Tier).
func (s *Server) handleRawProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	rawKey := strings.TrimPrefix(r.URL.Path, "/raw")
	rawKey = strings.TrimLeft(rawKey, "/")

	p := auth.PrincipalFromContext(r.Context())
	perm, err := s.evaluator.Resolve(r.Context(), p, rawKey)
	if err != nil || !perm.CanRead {
		http.Error(w, "403 Forbidden", http.StatusForbidden)
		return
	}

	s.settingsMu.RLock()
	enableSidecars := s.settings.EnableChecksumSidecars
	enableAutoindex := s.settings.EnableHTMLAutoindex
	s.settingsMu.RUnlock()

	// 1. Check if request is for a virtual sidecar (.sha256 or .sha1)
	if strings.HasSuffix(rawKey, ".sha256") || strings.HasSuffix(rawKey, ".sha1") {
		if !enableSidecars {
			http.Error(w, "404 Checksum Sidecars Disabled", http.StatusNotFound)
			return
		}
		s.serveVirtualChecksumSidecar(w, r, rawKey)
		return
	}

	// 2. If rawKey is empty or ends with "/", or doesn't exist as a file but has directory children, render HTML autoindex
	if rawKey == "" || strings.HasSuffix(r.URL.Path, "/") {
		if !enableAutoindex {
			http.Error(w, "403 HTML Directory Autoindex Disabled", http.StatusForbidden)
			return
		}
		s.serveRawDirectoryIndex(w, r, rawKey)
		return
	}

	if _, err := s.store.GetObjectMeta(r.Context(), rawKey); errors.Is(err, store.ErrNotFound) {
		entries, listErr := s.store.ListDirectory(r.Context(), rawKey+"/", "")
		if listErr == nil && len(entries) > 0 && enableAutoindex {
			http.Redirect(w, r, "/raw/"+strings.TrimSuffix(rawKey, "/")+"/", http.StatusMovedPermanently)
			return
		}
		http.Error(w, "404 Not Found", http.StatusNotFound)
		return
	}

	// 3. Serve the actual file (HEAD or streaming GET)
	s.streamObjectDownload(w, r, rawKey, false)
}

func (s *Server) serveVirtualChecksumSidecar(w http.ResponseWriter, r *http.Request, sidecarKey string) {
	isSHA256 := strings.HasSuffix(sidecarKey, ".sha256")
	baseKey := strings.TrimSuffix(strings.TrimSuffix(sidecarKey, ".sha256"), ".sha1")

	meta, err := s.store.GetObjectMeta(r.Context(), baseKey)
	if err != nil {
		http.Error(w, "404 Checksum Target Not Found", http.StatusNotFound)
		return
	}
	digest := meta.SHA1
	if isSHA256 {
		digest = meta.SHA256
	}
	body := digest + "\n"
	if strings.EqualFold(r.URL.Query().Get("format"), "gnu") {
		body = fmt.Sprintf("%s  %s\n", digest, meta.Filename)
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Header().Set("Last-Modified", meta.UpdatedAt.UTC().Format(http.TimeFormat))
	w.Header().Set("ETag", fmt.Sprintf("%q", digest))
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	_, _ = io.WriteString(w, body)
}

func (s *Server) serveRawDirectoryIndex(w http.ResponseWriter, r *http.Request, prefix string) {
	entries, err := s.store.ListDirectory(r.Context(), prefix, "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	displayPrefix := "/" + strings.Trim(prefix, "/")
	if displayPrefix != "/" {
		displayPrefix += "/"
	}

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "<!DOCTYPE html>\n<html>\n<head><meta charset=\"utf-8\"><link rel=\"icon\" href=\"/logo.png\"><title>Index of /raw%s</title>", html.EscapeString(displayPrefix))
	fmt.Fprintf(&buf, "<style>body{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;background:#0f172a;color:#e2e8f0;padding:24px;} a{color:#38bdf8;text-decoration:none;} a:hover{text-decoration:underline;} hr{border:0;border-top:1px solid #334155;margin:16px 0;} .tier{color:#94a3b8;font-size:12px;} .hdr{display:flex;align-items:center;gap:14px;}</style></head>\n")
	fmt.Fprintf(&buf, "<body>\n<div class=\"hdr\"><img src=\"/logo.png\" alt=\"Logo\" style=\"height:42px;width:auto;border-radius:6px;object-fit:contain;\"><h2>Index of /raw%s</h2></div>\n<hr>\n<pre>\n", html.EscapeString(displayPrefix))
	if prefix != "" {
		fmt.Fprintf(&buf, "<a href=\"../\">../</a>\n")
	}
	for _, e := range entries {
		if e.Type == "DIR" {
			fmt.Fprintf(&buf, "<a href=\"%s\">%-52s</a> %20s %14s\n",
				html.EscapeString(e.Name),
				html.EscapeString(e.Name),
				e.UpdatedAt.UTC().Format("2006-01-02 15:04:05"),
				"-")
		} else {
			fmt.Fprintf(&buf, "<a href=\"%s\">%-52s</a> %20s %14d  <span class=\"tier\">[%s]</span>  <a href=\"%s.sha256\">[.sha256]</a> <a href=\"%s.sha1\">[.sha1]</a>\n",
				html.EscapeString(e.Name),
				html.EscapeString(e.Name),
				e.UpdatedAt.UTC().Format("2006-01-02 15:04:05"),
				e.Size,
				html.EscapeString(string(e.IntelligentTier)),
				html.EscapeString(e.Name),
				html.EscapeString(e.Name))
		}
	}
	fmt.Fprintf(&buf, "</pre>\n<hr>\n<small>s3web HTML Raw Access &bull; Bucket: %s (S3 Intelligent-Tiering)</small>\n</body>\n</html>\n", html.EscapeString(s.cfg.S3Bucket))

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(buf.Bytes())
	}
}

func (s *Server) streamObjectDownload(w http.ResponseWriter, r *http.Request, key string, forceAttachment bool) {
	start := time.Now()
	p := auth.PrincipalFromContext(r.Context())

	meta, err := s.store.GetObjectMeta(r.Context(), key)
	if err != nil {
		http.Error(w, "404 Not Found", http.StatusNotFound)
		return
	}

	// Check if object is in an asynchronous Intelligent-Tiering Archive tier (AA or DAA) and not yet restored
	if meta.IsAsyncArchived() {
		w.Header().Set("Retry-After", "3600")
		w.Header().Set("X-Amz-Storage-Class", meta.StorageClass)
		w.Header().Set("X-Amz-Archive-Status", string(meta.IntelligentTier))
		writeJSONError(w, http.StatusConflict, fmt.Sprintf(
			"Object %q is currently stored in S3 Intelligent-Tiering %s and requires restoration before download.",
			meta.Key, meta.TierLabel))
		return
	}

	// Set HTML Raw Access & S3 Intelligent-Tiering headers
	etag := fmt.Sprintf("%q", meta.SHA256)
	w.Header().Set("ETag", etag)
	w.Header().Set("Last-Modified", meta.UpdatedAt.UTC().Format(http.TimeFormat))
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("X-Checksum-Sha256", meta.SHA256)
	w.Header().Set("X-Checksum-Sha1", meta.SHA1)
	w.Header().Set("X-Amz-Storage-Class", meta.StorageClass)
	w.Header().Set("X-Amz-Intelligent-Tier", string(meta.IntelligentTier))
	if meta.ContentType != "" {
		w.Header().Set("Content-Type", meta.ContentType)
	} else {
		w.Header().Set("Content-Type", detectContentType(meta.Key))
	}
	if forceAttachment {
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", meta.Filename))
	} else {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
	}

	// Handle conditional If-None-Match
	if inm := strings.TrimSpace(r.Header.Get("If-None-Match")); inm != "" && inm == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	if r.Method == http.MethodHead {
		w.Header().Set("Content-Length", strconv.FormatInt(meta.Size, 10))
		w.WriteHeader(http.StatusOK)
		return
	}

	rangeHdr := r.Header.Get("Range")
	getRes, err := s.storage.GetStream(r.Context(), key, rangeHdr)
	if err != nil {
		if errors.Is(err, storage.ErrInvalidRange) {
			w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", meta.Size))
			http.Error(w, "416 Range Not Satisfiable", http.StatusRequestedRangeNotSatisfiable)
			return
		}
		http.Error(w, "500 Internal Storage Error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer getRes.Body.Close()

	w.Header().Set("Content-Length", strconv.FormatInt(getRes.ContentLength, 10))
	statusCode := http.StatusOK
	if getRes.IsPartial {
		w.Header().Set("Content-Range", getRes.ContentRange)
		statusCode = http.StatusPartialContent
	}
	w.WriteHeader(statusCode)

	bytesSent, _ := io.Copy(w, getRes.Body)

	// Update LastAccessedAt (which automatically moves IA/AIA back to Frequent Access FA) and append per-item access log
	_ = s.store.TouchObjectAccess(r.Context(), meta.Key, time.Now().UTC())
	s.recordAccessLog(r, p, meta.Key, model.ActionDownload, bytesSent, statusCode, getRes.IsPartial, time.Since(start))
}

func (s *Server) recordAccessLog(
	r *http.Request,
	p *model.Principal,
	key string,
	action model.AccessAction,
	bytesSent int64,
	statusCode int,
	isRange bool,
	duration time.Duration,
) {
	var groups []string
	groups = append(groups, p.OIDCGroups...)
	groups = append(groups, p.AppGroups...)

	entry := &model.AccessLogEntry{
		ObjectKey:     key,
		Timestamp:     time.Now().UTC(),
		Action:        action,
		PrincipalType: p.Type,
		PrincipalID:   p.ID,
		Groups:        groups,
		ClientIP:      extractClientIP(r),
		UserAgent:     r.UserAgent(),
		BytesSent:     bytesSent,
		StatusCode:    statusCode,
		RangeRequest:  isRange,
		DurationMs:    duration.Milliseconds(),
	}
	_ = s.store.AppendAccessLog(r.Context(), entry)
}

// --- In-App Admin Endpoints (Local Accounts, Access Grants, App Groups, Service Accounts) ---

func (s *Server) handleAdminLocalUsers(w http.ResponseWriter, r *http.Request) {
	p := auth.PrincipalFromContext(r.Context())
	if !p.EffectivePerm.IsAdmin {
		writeJSONError(w, http.StatusForbidden, "admin permission required to manage local accounts")
		return
	}
	switch r.Method {
	case http.MethodGet:
		users, err := s.store.ListLocalUsers(r.Context())
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		sanitized := make([]model.LocalUser, 0, len(users))
		for _, u := range users {
			sanitized = append(sanitized, u.Sanitized())
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"local_users": sanitized})

	case http.MethodPost:
		var req struct {
			Username    string `json:"username"`
			Email       string `json:"email"`
			DisplayName string `json:"display_name"`
			Password    string `json:"password"`
			IsAdmin     bool   `json:"is_admin"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		username := strings.ToLower(strings.TrimSpace(req.Username))
		if username == "" {
			writeJSONError(w, http.StatusBadRequest, "username is required")
			return
		}
		password := strings.TrimSpace(req.Password)
		if len(password) < 6 {
			writeJSONError(w, http.StatusBadRequest, "password must be at least 6 characters")
			return
		}
		email := strings.TrimSpace(req.Email)
		if email == "" {
			email = username + "@example.com"
		}
		if existing, err := s.store.GetLocalUser(r.Context(), username); err == nil && existing != nil {
			writeJSONError(w, http.StatusConflict, "local account username or email already exists")
			return
		}
		if existingByEmail, err := s.store.GetLocalUser(r.Context(), email); err == nil && existingByEmail != nil {
			writeJSONError(w, http.StatusConflict, "local account username or email already exists")
			return
		}
		displayName := strings.TrimSpace(req.DisplayName)
		if displayName == "" {
			displayName = username
		}
		hash, err := auth.HashSecret(password)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		user := &model.LocalUser{
			Username:     username,
			Email:        email,
			DisplayName:  displayName,
			PasswordHash: hash,
			IsAdmin:      req.IsAdmin,
			Disabled:     false,
			CreatedBy:    p.ID,
			CreatedAt:    time.Now().UTC(),
		}
		if err := s.store.UpsertLocalUser(r.Context(), user); err != nil {
			if errors.Is(err, store.ErrDuplicateUser) {
				writeJSONError(w, http.StatusConflict, err.Error())
				return
			}
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, user.Sanitized())

	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleAdminLocalUsersByID(w http.ResponseWriter, r *http.Request) {
	p := auth.PrincipalFromContext(r.Context())
	if !p.EffectivePerm.IsAdmin {
		writeJSONError(w, http.StatusForbidden, "admin permission required to manage local accounts")
		return
	}

	subPath := strings.TrimPrefix(r.URL.Path, "/api/v1/admin/local-users/")
	subPath = strings.Trim(subPath, "/")
	if subPath == "" {
		writeJSONError(w, http.StatusBadRequest, "local username or action is required")
		return
	}

	// Bulk action: POST /api/v1/admin/local-users/disable-all
	if subPath == "disable-all" {
		if r.Method != http.MethodPost && r.Method != http.MethodPut {
			writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		var req struct {
			Disabled *bool `json:"disabled"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		targetDisabled := true
		if req.Disabled != nil {
			targetDisabled = *req.Disabled
		}
		users, err := s.store.ListLocalUsers(r.Context())
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		count := 0
		for i := range users {
			u := users[i]
			u.Disabled = targetDisabled
			if err := s.store.UpsertLocalUser(r.Context(), &u); err == nil {
				count++
			}
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"status":   "updated_all",
			"disabled": targetDisabled,
			"count":    count,
		})
		return
	}

	// Per-user actions:
	// - PUT/POST /api/v1/admin/local-users/{username}/password
	// - PUT/POST /api/v1/admin/local-users/{username}/status
	// - DELETE /api/v1/admin/local-users/{username}
	if strings.HasSuffix(subPath, "/password") {
		if r.Method != http.MethodPut && r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		username := strings.TrimSuffix(subPath, "/password")
		var req struct {
			NewPassword string `json:"new_password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		newPass := strings.TrimSpace(req.NewPassword)
		if len(newPass) < 6 {
			writeJSONError(w, http.StatusBadRequest, "new_password must be at least 6 characters")
			return
		}
		user, err := s.store.GetLocalUser(r.Context(), username)
		if err != nil {
			writeJSONError(w, http.StatusNotFound, "local account not found")
			return
		}
		hash, err := auth.HashSecret(newPass)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		now := time.Now().UTC()
		user.PasswordHash = hash
		user.PasswordChangedAt = &now
		if err := s.store.UpsertLocalUser(r.Context(), user); err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"status":     "password_updated",
			"local_user": user.Sanitized(),
		})
		return
	}

	if strings.HasSuffix(subPath, "/status") {
		if r.Method != http.MethodPut && r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		username := strings.TrimSuffix(subPath, "/status")
		var req struct {
			Disabled bool `json:"disabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		user, err := s.store.GetLocalUser(r.Context(), username)
		if err != nil {
			writeJSONError(w, http.StatusNotFound, "local account not found")
			return
		}
		user.Disabled = req.Disabled
		if err := s.store.UpsertLocalUser(r.Context(), user); err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"status":     "status_updated",
			"local_user": user.Sanitized(),
		})
		return
	}

	if r.Method == http.MethodDelete {
		if err := s.store.DeleteLocalUser(r.Context(), subPath); err != nil {
			writeJSONError(w, http.StatusNotFound, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted", "username": subPath})
		return
	}

	writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
}

func (s *Server) handleAdminGrants(w http.ResponseWriter, r *http.Request) {
	p := auth.PrincipalFromContext(r.Context())
	if !p.EffectivePerm.IsAdmin {
		writeJSONError(w, http.StatusForbidden, "admin permission required to manage access grants")
		return
	}
	switch r.Method {
	case http.MethodGet:
		grants, err := s.store.ListAccessGrants(r.Context())
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"grants": grants})
	case http.MethodPost:
		var grant model.AccessGrant
		if err := json.NewDecoder(r.Body).Decode(&grant); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		if strings.TrimSpace(grant.SubjectID) == "" || grant.SubjectType == "" {
			writeJSONError(w, http.StatusBadRequest, "subject_type and subject_id are required")
			return
		}
		grant.UpdatedBy = p.ID
		if err := s.store.UpsertAccessGrant(r.Context(), &grant); err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, grant)
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleAdminGrantsByID(w http.ResponseWriter, r *http.Request) {
	p := auth.PrincipalFromContext(r.Context())
	if !p.EffectivePerm.IsAdmin {
		writeJSONError(w, http.StatusForbidden, "admin permission required")
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/admin/grants/")
	if r.Method != http.MethodDelete {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if err := s.store.DeleteAccessGrant(r.Context(), id); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted", "id": id})
}

func (s *Server) handleAdminGroups(w http.ResponseWriter, r *http.Request) {
	p := auth.PrincipalFromContext(r.Context())
	if !p.EffectivePerm.IsAdmin {
		writeJSONError(w, http.StatusForbidden, "admin permission required")
		return
	}
	switch r.Method {
	case http.MethodGet:
		groups, err := s.store.ListAppGroups(r.Context())
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"groups": groups})
	case http.MethodPost:
		var group model.AppGroup
		if err := json.NewDecoder(r.Body).Decode(&group); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		if strings.TrimSpace(group.Name) == "" {
			writeJSONError(w, http.StatusBadRequest, "group name is required")
			return
		}
		group.UpdatedBy = p.ID
		if err := s.store.UpsertAppGroup(r.Context(), &group); err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, group)
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleAdminGroupsByName(w http.ResponseWriter, r *http.Request) {
	p := auth.PrincipalFromContext(r.Context())
	if !p.EffectivePerm.IsAdmin {
		writeJSONError(w, http.StatusForbidden, "admin permission required")
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/api/v1/admin/groups/")
	if r.Method != http.MethodDelete {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if err := s.store.DeleteAppGroup(r.Context(), name); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted", "name": name})
}

func (s *Server) handleAdminServiceAccounts(w http.ResponseWriter, r *http.Request) {
	p := auth.PrincipalFromContext(r.Context())
	if !p.EffectivePerm.IsAdmin {
		writeJSONError(w, http.StatusForbidden, "admin permission required")
		return
	}
	switch r.Method {
	case http.MethodGet:
		accounts, err := s.store.ListServiceAccounts(r.Context())
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"service_accounts": accounts})
	case http.MethodPost:
		var req struct {
			AccountID   string   `json:"account_id"`
			Name        string   `json:"name"`
			Description string   `json:"description"`
			Prefixes    []string `json:"prefixes"`
			CanRead     bool     `json:"can_read"`
			CanUpload   bool     `json:"can_upload"`
			CanDelete   bool     `json:"can_delete"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		req.AccountID = strings.TrimSpace(req.AccountID)
		if req.AccountID == "" {
			writeJSONError(w, http.StatusBadRequest, "account_id is required")
			return
		}
		if req.Name == "" {
			req.Name = req.AccountID
		}
		rawSecret, err := auth.GenerateToken()
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		hash, err := auth.HashSecret(rawSecret)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		sa := &model.ServiceAccount{
			AccountID:   req.AccountID,
			Name:        req.Name,
			Description: req.Description,
			SecretHash:  hash,
			CreatedBy:   p.ID,
			CreatedAt:   time.Now().UTC(),
		}
		if err := s.store.UpsertServiceAccount(r.Context(), sa); err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		// Automatically create a corresponding In-App Access Grant for this Service Account
		if len(req.Prefixes) == 0 {
			req.Prefixes = []string{"*"}
		}
		grant := &model.AccessGrant{
			ID:          "grant-sa-" + req.AccountID,
			Description: "Service Account Grant for " + req.Name,
			SubjectType: model.SubjectServiceAccount,
			SubjectID:   req.AccountID,
			Prefixes:    req.Prefixes,
			CanRead:     req.CanRead,
			CanUpload:   req.CanUpload,
			CanDelete:   req.CanDelete,
			UpdatedBy:   p.ID,
		}
		_ = s.store.UpsertAccessGrant(r.Context(), grant)

		writeJSON(w, http.StatusCreated, map[string]interface{}{
			"service_account": sa,
			"secret":          rawSecret,
			"basic_auth_user": sa.AccountID,
			"bearer_header":   fmt.Sprintf("Authorization: Bearer %s:%s", sa.AccountID, rawSecret),
		})
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleAdminServiceAccountsByID(w http.ResponseWriter, r *http.Request) {
	p := auth.PrincipalFromContext(r.Context())
	if !p.EffectivePerm.IsAdmin {
		writeJSONError(w, http.StatusForbidden, "admin permission required")
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/admin/service-accounts/")
	if r.Method != http.MethodDelete {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if err := s.store.DeleteServiceAccount(r.Context(), id); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.store.DeleteAccessGrant(r.Context(), "grant-sa-"+id)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted", "account_id": id})
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	p := auth.PrincipalFromContext(r.Context())

	switch r.Method {
	case http.MethodGet:
		s.settingsMu.RLock()
		cur := s.settings
		s.settingsMu.RUnlock()
		writeJSON(w, http.StatusOK, cur)

	case http.MethodPost, http.MethodPut:
		if !p.EffectivePerm.IsAdmin {
			writeJSONError(w, http.StatusForbidden, "admin permission required to modify settings")
			return
		}
		var req struct {
			RepositoryTitle         string `json:"repository_title"`
			DefaultTreeState        string `json:"default_tree_state"`
			EnableHTMLAutoindex     bool   `json:"enable_html_autoindex"`
			EnableChecksumSidecars  bool   `json:"enable_checksum_sidecars"`
			DefaultRestoreDays      int    `json:"default_restore_days"`
			DefaultRestoreTier      string `json:"default_restore_tier"`
			AccessLogRetentionDays  int    `json:"access_log_retention_days"`
			OIDCEnabled             bool                      `json:"oidc_enabled"`
			OIDCIssuerURL           string                    `json:"oidc_issuer_url"`
			OIDCClientID            string                    `json:"oidc_client_id"`
			OIDCGroupsClaim         string                    `json:"oidc_groups_claim"`
			BootstrapAdminOIDCGroup string                    `json:"bootstrap_admin_oidc_group"`
			GitHubOIDCEnabled       bool                      `json:"github_oidc_enabled"`
			GitHubOIDCIssuerURL     string                    `json:"github_oidc_issuer_url"`
			GitHubOIDCAudience      string                    `json:"github_oidc_audience"`
			SSOProviders            []model.SSOProviderConfig `json:"sso_providers"`
			JWTProviders            []model.JWTProviderConfig `json:"jwt_providers"`
			Buckets                 []model.BucketMount       `json:"buckets"`
			NewAdminPassword        string                    `json:"new_admin_password,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}

		s.settingsMu.Lock()
		if len(req.Buckets) > 0 {
			var cleaned []model.BucketMount
			for idx, b := range req.Buckets {
				bName := strings.TrimSpace(b.BucketName)
				fName := strings.TrimSpace(b.FriendlyName)
				if bName == "" {
					continue
				}
				if fName == "" {
					fName = bName
				}
				region := strings.TrimSpace(b.Region)
				if region == "" {
					region = s.cfg.AWSRegion
				}
				id := strings.TrimSpace(b.ID)
				if id == "" {
					id = fmt.Sprintf("bucket-%d", idx+1)
				}
				cleaned = append(cleaned, model.BucketMount{
					ID:           id,
					FriendlyName: fName,
					BucketName:   bName,
					Region:       region,
				})
			}
			if len(cleaned) > 0 {
				s.settings.Buckets = cleaned
			}
		}
		if len(req.SSOProviders) > 0 {
			var cleanedSSO []model.SSOProviderConfig
			for idx, pCfg := range req.SSOProviders {
				name := strings.TrimSpace(pCfg.Name)
				issuer := strings.TrimSpace(pCfg.IssuerURL)
				if name == "" && issuer == "" {
					continue
				}
				if name == "" {
					name = fmt.Sprintf("SSO Provider %d", idx+1)
				}
				groupsClaim := strings.TrimSpace(pCfg.GroupsClaim)
				if groupsClaim == "" {
					groupsClaim = "groups"
				}
				adminGroup := strings.TrimSpace(pCfg.AdminGroup)
				if adminGroup == "" {
					adminGroup = "platform-admins"
				}
				id := strings.TrimSpace(pCfg.ID)
				if id == "" {
					id = fmt.Sprintf("sso-%d", idx+1)
				}
				cleanedSSO = append(cleanedSSO, model.SSOProviderConfig{
					ID:          id,
					Name:        name,
					Enabled:     pCfg.Enabled,
					IssuerURL:   issuer,
					ClientID:    strings.TrimSpace(pCfg.ClientID),
					GroupsClaim: groupsClaim,
					AdminGroup:  adminGroup,
				})
			}
			if len(cleanedSSO) > 0 {
				s.settings.SSOProviders = cleanedSSO
				primary := cleanedSSO[0]
				for _, item := range cleanedSSO {
					if item.Enabled {
						primary = item
						break
					}
				}
				s.settings.OIDCEnabled = primary.Enabled
				s.settings.OIDCIssuerURL = primary.IssuerURL
				s.settings.OIDCClientID = primary.ClientID
				s.settings.OIDCGroupsClaim = primary.GroupsClaim
				s.settings.BootstrapAdminOIDCGroup = primary.AdminGroup
			}
		}
		if len(req.JWTProviders) > 0 {
			var cleanedJWT []model.JWTProviderConfig
			for idx, jCfg := range req.JWTProviders {
				name := strings.TrimSpace(jCfg.Name)
				issuer := strings.TrimSpace(jCfg.IssuerURL)
				if name == "" && issuer == "" {
					continue
				}
				if name == "" {
					name = fmt.Sprintf("JWT Issuer %d", idx+1)
				}
				id := strings.TrimSpace(jCfg.ID)
				if id == "" {
					id = fmt.Sprintf("jwt-%d", idx+1)
				}
				cleanedJWT = append(cleanedJWT, model.JWTProviderConfig{
					ID:            id,
					Name:          name,
					Enabled:       jCfg.Enabled,
					IssuerURL:     issuer,
					Audience:      strings.TrimSpace(jCfg.Audience),
					SubjectPrefix: strings.TrimSpace(jCfg.SubjectPrefix),
				})
			}
			if len(cleanedJWT) > 0 {
				s.settings.JWTProviders = cleanedJWT
				primary := cleanedJWT[0]
				anyEnabled := false
				for _, item := range cleanedJWT {
					if item.Enabled {
						if !anyEnabled {
							primary = item
						}
						anyEnabled = true
					}
				}
				s.settings.GitHubOIDCEnabled = anyEnabled
				s.settings.GitHubOIDCIssuerURL = primary.IssuerURL
				s.settings.GitHubOIDCAudience = primary.Audience
			}
		}
		if strings.TrimSpace(req.RepositoryTitle) != "" {
			s.settings.RepositoryTitle = strings.TrimSpace(req.RepositoryTitle)
		}
		if req.DefaultTreeState == "collapsed" || req.DefaultTreeState == "expanded" {
			s.settings.DefaultTreeState = req.DefaultTreeState
		}
		s.settings.EnableHTMLAutoindex = req.EnableHTMLAutoindex
		s.settings.EnableChecksumSidecars = req.EnableChecksumSidecars
		if req.DefaultRestoreDays > 0 && req.DefaultRestoreDays <= 30 {
			s.settings.DefaultRestoreDays = req.DefaultRestoreDays
		}
		if req.DefaultRestoreTier == "Standard" || req.DefaultRestoreTier == "Expedited" || req.DefaultRestoreTier == "Bulk" {
			s.settings.DefaultRestoreTier = req.DefaultRestoreTier
		}
		if req.AccessLogRetentionDays > 0 {
			s.settings.AccessLogRetentionDays = req.AccessLogRetentionDays
		}
		if strings.TrimSpace(req.NewAdminPassword) != "" {
			newAdminPass := strings.TrimSpace(req.NewAdminPassword)
			if adminUser, err := s.store.GetLocalUser(r.Context(), s.cfg.BootstrapAdminUsername); err == nil && adminUser != nil {
				if hash, hashErr := auth.HashSecret(newAdminPass); hashErr == nil {
					now := time.Now().UTC()
					adminUser.PasswordHash = hash
					adminUser.PasswordChangedAt = &now
					_ = s.store.UpsertLocalUser(r.Context(), adminUser)
				}
			}
		}
		s.authn.UpdateAuthConfig(
			s.settings.BootstrapAdminOIDCGroup,
			s.settings.GitHubOIDCEnabled,
			s.settings.GitHubOIDCIssuerURL,
			s.settings.GitHubOIDCAudience,
			s.settings.JWTProviders,
		)
		s.settings.UpdatedBy = p.ID
		s.settings.UpdatedAt = time.Now().UTC()
		updated := s.settings
		s.settingsMu.Unlock()

		writeJSON(w, http.StatusOK, updated)

	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func detectContentType(key string) string {
	ext := strings.ToLower(filepath.Ext(key))
	switch ext {
	case ".iso":
		return "application/x-iso9660-image"
	case ".zst":
		return "application/zstd"
	case ".qcow2":
		return "application/x-qemu-disk"
	case ".gz", ".tgz":
		return "application/gzip"
	case ".xz":
		return "application/x-xz"
	case ".zip":
		return "application/zip"
	}
	if ct := mime.TypeByExtension(ext); ct != "" {
		return ct
	}
	return "application/octet-stream"
}

func extractClientIP(r *http.Request) string {
	if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
		candidate := strings.TrimSpace(strings.Split(xff, ",")[0])
		if ip := net.ParseIP(candidate); ip != nil {
			return ip.String()
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(payload)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

