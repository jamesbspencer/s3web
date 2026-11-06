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
	"time"

	"s3web/internal/auth"
	"s3web/internal/config"
	"s3web/internal/model"
	"s3web/internal/rbac"
	"s3web/internal/storage"
	"s3web/internal/store"
	"s3web/internal/ui"
)

// Server wires together the Web UI, REST API, Sonatype Nexus /raw Proxy, In-App RBAC, and Access Logger.
type Server struct {
	cfg         *config.Config
	store       store.MetadataStore
	storage     storage.ObjectStorage
	evaluator   *rbac.Evaluator
	authn       *auth.Authenticator
	mux         *http.ServeMux
	uiAssets    http.FileSystem
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

	// Authentication & Persona / Token Endpoints
	s.mux.HandleFunc("/auth/login", s.handleAuthLogin)
	s.mux.HandleFunc("/auth/logout", s.handleAuthLogout)
	s.mux.HandleFunc("/api/v1/auth/session", s.handleSwitchSession)
	s.mux.HandleFunc("/api/v1/auth/github-test-jwt", s.withAuth(s.handleMintTestGitHubJWT))

	// Sonatype Nexus Raw Proxy & Apache/Nginx autoindex Repository Endpoint
	s.mux.HandleFunc("/raw", s.withRawAuth(s.handleRawProxy))
	s.mux.HandleFunc("/raw/", s.withRawAuth(s.handleRawProxy))

	// Web UI API Endpoints
	s.mux.HandleFunc("/api/v1/me", s.withAuth(s.handleMe))
	s.mux.HandleFunc("/api/v1/browse", s.withAuth(s.handleBrowse))
	s.mux.HandleFunc("/api/v1/search", s.withAuth(s.handleSearch))
	s.mux.HandleFunc("/api/v1/objects/", s.withAuth(s.handleObjectsRouter))

	// In-App Permission Management, App Groups & Service Accounts (Admin Console)
	s.mux.HandleFunc("/api/v1/admin/grants", s.withAuth(s.handleAdminGrants))
	s.mux.HandleFunc("/api/v1/admin/grants/", s.withAuth(s.handleAdminGrantsByID))
	s.mux.HandleFunc("/api/v1/admin/groups", s.withAuth(s.handleAdminGroups))
	s.mux.HandleFunc("/api/v1/admin/groups/", s.withAuth(s.handleAdminGroupsByName))
	s.mux.HandleFunc("/api/v1/admin/service-accounts", s.withAuth(s.handleAdminServiceAccounts))
	s.mux.HandleFunc("/api/v1/admin/service-accounts/", s.withAuth(s.handleAdminServiceAccountsByID))

	// Embedded Self-Contained Web UI Assets (Zero external CDN calls)
	s.mux.Handle("/", http.FileServer(s.uiAssets))
}

func (s *Server) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, err := s.authn.AuthenticateRequest(r)
		if err != nil {
			writeJSONError(w, http.StatusUnauthorized, err.Error())
			return
		}
		next(w, r.WithContext(auth.WithPrincipal(r.Context(), p)))
	}
}

func (s *Server) withRawAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, err := s.authn.AuthenticateRequest(r)
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Basic realm="s3web Sonatype Nexus Raw Proxy"`)
			http.Error(w, "401 Unauthorized: "+err.Error(), http.StatusUnauthorized)
			return
		}
		next(w, r.WithContext(auth.WithPrincipal(r.Context(), p)))
	}
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
	if r.Method == http.MethodPost {
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
		if !s.authn.AuthenticateAdminLogin(req.Username, req.Password) {
			writeJSONError(w, http.StatusUnauthorized, "invalid bootstrap admin username or password")
			return
		}
		if err := s.authn.IssueSessionCookie(w, s.cfg.BootstrapAdminEmail, "Bootstrap Admin ("+s.cfg.BootstrapAdminEmail+")", []string{s.cfg.BootstrapAdminOIDCGroup}); err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{
			"status": "authenticated",
			"email":  s.cfg.BootstrapAdminEmail,
		})
		return
	}

	// Supports quick SSO login or persona simulation when OIDC IdP is not reachable locally
	email := strings.TrimSpace(r.URL.Query().Get("email"))
	if email == "" {
		email = s.cfg.BootstrapAdminEmail
	}
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		name = email
	}
	groupsRaw := strings.TrimSpace(r.URL.Query().Get("groups"))
	var groups []string
	if groupsRaw != "" {
		for _, g := range strings.Split(groupsRaw, ",") {
			if trimmed := strings.TrimSpace(g); trimmed != "" {
				groups = append(groups, trimmed)
			}
		}
	}
	if err := s.authn.IssueSessionCookie(w, email, name, groups); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	s.authn.ClearSessionCookie(w)
	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) handleSwitchSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
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
	results, err := s.store.SearchObjects(r.Context(), q, tier)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
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
	meta := &model.ObjectMeta{
		Key:             putRes.Key,
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
	if err := s.storage.Restore(r.Context(), key, 7); err != nil {
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
	if !p.EffectivePerm.IsAdmin && !p.EffectivePerm.CanUpload {
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

// handleRawProxy serves /raw/{key...} for Sonatype Nexus Raw Proxy repositories, curl/wget, and browser direct links:
// 1. HTML Directory Index ("autoindex" style from aws-samples/public-file-browser-for-amazon-s3) when path is a folder.
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

	// 1. Check if request is for a virtual sidecar (.sha256 or .sha1)
	if strings.HasSuffix(rawKey, ".sha256") || strings.HasSuffix(rawKey, ".sha1") {
		s.serveVirtualChecksumSidecar(w, r, rawKey)
		return
	}

	// 2. If rawKey is empty or ends with "/", or doesn't exist as a file but has directory children, render HTML autoindex
	if rawKey == "" || strings.HasSuffix(r.URL.Path, "/") {
		s.serveRawDirectoryIndex(w, r, rawKey)
		return
	}

	if _, err := s.store.GetObjectMeta(r.Context(), rawKey); errors.Is(err, store.ErrNotFound) {
		entries, listErr := s.store.ListDirectory(r.Context(), rawKey+"/", "")
		if listErr == nil && len(entries) > 0 {
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
	fmt.Fprintf(&buf, "</pre>\n<hr>\n<small>s3web Repository Proxy &bull; Bucket: %s (S3 Intelligent-Tiering)</small>\n</body>\n</html>\n", html.EscapeString(s.cfg.S3Bucket))

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

	// Set Sonatype Nexus & S3 Intelligent-Tiering headers
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

// --- In-App Admin Endpoints (Access Grants, App Groups, Service Accounts) ---

func (s *Server) handleAdminGrants(w http.ResponseWriter, r *http.Request) {
	p := auth.PrincipalFromContext(r.Context())
	switch r.Method {
	case http.MethodGet:
		grants, err := s.store.ListAccessGrants(r.Context())
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"grants": grants})
	case http.MethodPost:
		if !p.EffectivePerm.IsAdmin {
			writeJSONError(w, http.StatusForbidden, "admin permission required to manage access grants")
			return
		}
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
	switch r.Method {
	case http.MethodGet:
		groups, err := s.store.ListAppGroups(r.Context())
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"groups": groups})
	case http.MethodPost:
		if !p.EffectivePerm.IsAdmin {
			writeJSONError(w, http.StatusForbidden, "admin permission required")
			return
		}
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
	switch r.Method {
	case http.MethodGet:
		accounts, err := s.store.ListServiceAccounts(r.Context())
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"service_accounts": accounts})
	case http.MethodPost:
		if !p.EffectivePerm.IsAdmin {
			writeJSONError(w, http.StatusForbidden, "admin permission required")
			return
		}
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
			CanRead:     req.CanRead || true,
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
		return strings.TrimSpace(strings.Split(xff, ",")[0])
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

