package server_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"s3web/internal/config"
	"s3web/internal/model"
	"s3web/internal/server"
	"s3web/internal/storage"
	"s3web/internal/store"
)

func setupTestServer(t *testing.T) (*server.Server, *config.Config) {
	t.Helper()
	tmpDir := t.TempDir()
	cfg := config.Load()
	cfg.LocalDataDir = tmpDir
	cfg.BackendMode = "local"
	cfg.BootstrapNexusAccountID = "svc-raw-access"
	cfg.BootstrapNexusAccountKey = "raw-secret-123"
	cfg.BootstrapAdminEmail = "admin@example.com"
	cfg.BootstrapAdminOIDCGroup = "platform-admins"

	metaStore, err := store.NewLocalStore(tmpDir)
	if err != nil {
		t.Fatalf("NewLocalStore: %v", err)
	}
	objStorage, err := storage.NewLocalFSStorage(tmpDir)
	if err != nil {
		t.Fatalf("NewLocalFSStorage: %v", err)
	}
	srv, err := server.New(cfg, metaStore, objStorage)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	return srv, cfg
}

func TestHTMLRawAccessAndVirtualChecksums(t *testing.T) {
	srv, cfg := setupTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	client := ts.Client()

	// 1. Unauthenticated request with Basic Auth wrong password should return 401
	req, _ := http.NewRequest(http.MethodHead, ts.URL+"/raw/linux/ubuntu/24.04/ubuntu-24.04.1-live-server-amd64.iso", nil)
	req.SetBasicAuth(cfg.BootstrapNexusAccountID, "wrong-secret")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("HEAD request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for invalid Basic Auth, got %d", resp.StatusCode)
	}

	// 2. Valid HTML Raw Access HEAD request returns ETag, X-Checksum-Sha256, X-Checksum-Sha1, and X-Amz-Intelligent-Tier
	req, _ = http.NewRequest(http.MethodHead, ts.URL+"/raw/linux/ubuntu/24.04/ubuntu-24.04.1-live-server-amd64.iso", nil)
	req.SetBasicAuth(cfg.BootstrapNexusAccountID, cfg.BootstrapNexusAccountKey)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("HEAD request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK on HEAD, got %d", resp.StatusCode)
	}
	sha256Hdr := resp.Header.Get("X-Checksum-Sha256")
	sha1Hdr := resp.Header.Get("X-Checksum-Sha1")
	tierHdr := resp.Header.Get("X-Amz-Intelligent-Tier")
	if len(sha256Hdr) != 64 || len(sha1Hdr) != 40 {
		t.Fatalf("expected valid SHA-256 and SHA-1 headers, got sha256=%q sha1=%q", sha256Hdr, sha1Hdr)
	}
	if tierHdr != "FA" {
		t.Fatalf("expected X-Amz-Intelligent-Tier=FA, got %q", tierHdr)
	}

	// 3. Virtual .sha256 sidecar endpoint matches X-Checksum-Sha256
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/raw/linux/ubuntu/24.04/ubuntu-24.04.1-live-server-amd64.iso.sha256", nil)
	req.SetBasicAuth(cfg.BootstrapNexusAccountID, cfg.BootstrapNexusAccountKey)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("GET .sha256: %v", err)
	}
	bodyBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if strings.TrimSpace(string(bodyBytes)) != sha256Hdr {
		t.Fatalf("expected .sha256 sidecar %q to match header %q", strings.TrimSpace(string(bodyBytes)), sha256Hdr)
	}

	// 4. HTML Directory autoindex on /raw/linux/ubuntu/24.04/
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/raw/linux/ubuntu/24.04/", nil)
	req.SetBasicAuth(cfg.BootstrapNexusAccountID, cfg.BootstrapNexusAccountKey)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("GET autoindex: %v", err)
	}
	indexHTML, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(indexHTML), "ubuntu-24.04.1-live-server-amd64.iso") {
		t.Fatalf("expected autoindex HTML to list ubuntu ISO, got: %s", string(indexHTML))
	}
}

func TestGitHubActionsOIDCJWTUploadAndAccessLogs(t *testing.T) {
	srv, _ := setupTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()
	client := ts.Client()

	// 1. Mint a signed GitHub Actions OIDC JWT for repo:my-org/iso-builder:ref:refs/heads/main
	mintReqBody := `{"repository":"my-org/iso-builder","ref":"refs/heads/main","environment":"production"}`
	resp, err := client.Post(ts.URL+"/api/v1/auth/github-test-jwt", "application/json", strings.NewReader(mintReqBody))
	if err != nil {
		t.Fatalf("mint jwt: %v", err)
	}
	var mintRes struct {
		JWT string `json:"jwt"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&mintRes)
	resp.Body.Close()
	if mintRes.JWT == "" {
		t.Fatalf("expected non-empty JWT")
	}

	// 2. Upload a new ISO via GitHub Actions OIDC JWT to allowed prefix "isos/nightly/fedora-41.iso"
	isoPayload := []byte("ISO9660-FEDORA-41-CUSTOM-PAYLOAD-FOR-HASHING")
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/objects/isos/nightly/fedora-41.iso", bytes.NewReader(isoPayload))
	req.Header.Set("Authorization", "Bearer "+mintRes.JWT)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("PUT upload with GitHub JWT: %v", err)
	}
	var uploadedMeta model.ObjectMeta
	_ = json.NewDecoder(resp.Body).Decode(&uploadedMeta)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d", resp.StatusCode)
	}
	if uploadedMeta.IntelligentTier != model.TierFrequentAccess || len(uploadedMeta.SHA256) != 64 || len(uploadedMeta.SHA1) != 40 {
		t.Fatalf("unexpected uploaded metadata: %+v", uploadedMeta)
	}

	// 3. GitHub workflow does NOT have delete permission -> DELETE should return 403 Forbidden
	delReq, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/objects/isos/nightly/fedora-41.iso", nil)
	delReq.Header.Set("Authorization", "Bearer "+mintRes.JWT)
	delResp, err := client.Do(delReq)
	if err != nil {
		t.Fatalf("DELETE request: %v", err)
	}
	delResp.Body.Close()
	if delResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden when GitHub workflow attempts DELETE without delete grant, got %d", delResp.StatusCode)
	}

	// 4. Verify Per-Item Access Log recorded the GitHub Actions OIDC upload
	logResp, err := client.Get(ts.URL + "/api/v1/objects/isos/nightly/fedora-41.iso/logs")
	if err != nil {
		t.Fatalf("GET logs: %v", err)
	}
	var logData struct {
		Logs []model.AccessLogEntry `json:"logs"`
	}
	_ = json.NewDecoder(logResp.Body).Decode(&logData)
	logResp.Body.Close()
	if len(logData.Logs) == 0 || logData.Logs[0].PrincipalType != model.PrincipalGitHubWorkflow {
		t.Fatalf("expected GITHUB_WORKFLOW upload log entry, got %+v", logData.Logs)
	}
}

