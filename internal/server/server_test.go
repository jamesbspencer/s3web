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
	cfg.BootstrapAdminPassword = "" // Ensure random password is generated on install
	cfg.BootstrapDemoPassword = ""  // Ensure random demo password is generated on install
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

func TestAnonymousAccessDisabledAndLocalAccountsLifecycle(t *testing.T) {
	srv, cfg := setupTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()
	client := ts.Client()

	// 1. Verify default admin and demo local accounts had random passwords generated on install
	if len(cfg.BootstrapAdminPassword) < 16 {
		t.Fatalf("expected random generated admin password on install, got %q", cfg.BootstrapAdminPassword)
	}
	if len(cfg.BootstrapDemoPassword) < 12 {
		t.Fatalf("expected random generated demo password on install, got %q", cfg.BootstrapDemoPassword)
	}

	// 2. Verify anonymous access is strictly disabled across API and /raw/
	for _, path := range []string{"/api/v1/me", "/api/v1/browse", "/api/v1/search", "/raw/"} {
		resp, err := client.Get(ts.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized for anonymous GET %s, got %d", path, resp.StatusCode)
		}
	}

	// 3. Demo local user can log in and update their own password
	loginBody := `{"username":"demo","password":"` + cfg.BootstrapDemoPassword + `"}`
	loginResp, err := client.Post(ts.URL+"/auth/login", "application/json", strings.NewReader(loginBody))
	if err != nil {
		t.Fatalf("demo login: %v", err)
	}
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for demo login, got %d", loginResp.StatusCode)
	}
	cookies := loginResp.Cookies()
	loginResp.Body.Close()
	if len(cookies) == 0 {
		t.Fatalf("expected session cookie on demo login")
	}

	// Demo user updates own password
	changeOwnBody := `{"current_password":"` + cfg.BootstrapDemoPassword + `","new_password":"demo-new-self-pass-123"}`
	changeReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/auth/password", strings.NewReader(changeOwnBody))
	changeReq.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		changeReq.AddCookie(c)
	}
	changeResp, err := client.Do(changeReq)
	if err != nil {
		t.Fatalf("demo change own password: %v", err)
	}
	changeResp.Body.Close()
	if changeResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK when demo user updates own password, got %d", changeResp.StatusCode)
	}

	// Verify demo user can log in with the new password
	reloginResp, err := client.Post(ts.URL+"/auth/login", "application/json", strings.NewReader(`{"username":"demo","password":"demo-new-self-pass-123"}`))
	if err != nil || reloginResp.StatusCode != http.StatusOK {
		t.Fatalf("expected demo user to log in with updated password, got status=%v err=%v", reloginResp.StatusCode, err)
	}
	reloginResp.Body.Close()

	// 3b. Verify non-admin demo user receives 403 Forbidden on admin endpoints and write/delete operations
	for _, adminPath := range []string{
		"/api/v1/admin/local-users",
		"/api/v1/admin/grants",
		"/api/v1/admin/groups",
		"/api/v1/admin/service-accounts",
	} {
		reqForbidden, _ := http.NewRequest(http.MethodGet, ts.URL+adminPath, nil)
		reqForbidden.SetBasicAuth("demo", "demo-new-self-pass-123")
		respForbidden, reqErr := client.Do(reqForbidden)
		if reqErr != nil {
			t.Fatalf("GET %s as demo: %v", adminPath, reqErr)
		}
		respForbidden.Body.Close()
		if respForbidden.StatusCode != http.StatusForbidden {
			t.Fatalf("expected 403 Forbidden for non-admin demo user on GET %s, got %d", adminPath, respForbidden.StatusCode)
		}
	}
	putUploadAsDemo, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/objects/isos/demo-unauthorized.iso", strings.NewReader("unauthorized"))
	putUploadAsDemo.SetBasicAuth("demo", "demo-new-self-pass-123")
	respUploadDemo, err := client.Do(putUploadAsDemo)
	if err != nil {
		t.Fatalf("PUT object as demo: %v", err)
	}
	respUploadDemo.Body.Close()
	if respUploadDemo.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden when read-only demo user attempts upload, got %d", respUploadDemo.StatusCode)
	}

	// 3c. Verify duplicate local account creation returns 409 Conflict
	dupReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/admin/local-users", strings.NewReader(`{"username":"admin","password":"another-password-123"}`))
	dupReq.SetBasicAuth("admin", cfg.BootstrapAdminPassword)
	dupReq.Header.Set("Content-Type", "application/json")
	dupResp, err := client.Do(dupReq)
	if err != nil {
		t.Fatalf("POST duplicate local user: %v", err)
	}
	dupResp.Body.Close()
	if dupResp.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409 Conflict when creating duplicate username 'admin', got %d", dupResp.StatusCode)
	}

	// 4. Admin can change the password of any local account (e.g., demo)
	adminChangeBody := `{"new_password":"admin-reset-demo-pass-999"}`
	adminPassReq, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/admin/local-users/demo/password", strings.NewReader(adminChangeBody))
	adminPassReq.SetBasicAuth("admin", cfg.BootstrapAdminPassword)
	adminPassReq.Header.Set("Content-Type", "application/json")
	adminPassResp, err := client.Do(adminPassReq)
	if err != nil {
		t.Fatalf("admin change demo password: %v", err)
	}
	adminPassResp.Body.Close()
	if adminPassResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK when admin changes demo password, got %d", adminPassResp.StatusCode)
	}

	// Verify demo can log in with admin-assigned password
	demoLogin2, err := client.Post(ts.URL+"/auth/login", "application/json", strings.NewReader(`{"username":"demo","password":"admin-reset-demo-pass-999"}`))
	if err != nil || demoLogin2.StatusCode != http.StatusOK {
		t.Fatalf("expected demo login with admin-set password to succeed, got %v", demoLogin2.StatusCode)
	}
	demoCookies2 := demoLogin2.Cookies()
	demoLogin2.Body.Close()

	// 5. Admin can disable individual local account AND disable all local accounts
	disableAllReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/admin/local-users/disable-all", strings.NewReader(`{"disabled":true}`))
	disableAllReq.SetBasicAuth("admin", cfg.BootstrapAdminPassword)
	disableAllReq.Header.Set("Content-Type", "application/json")
	disableAllResp, err := client.Do(disableAllReq)
	if err != nil {
		t.Fatalf("admin disable all local users: %v", err)
	}
	disableAllResp.Body.Close()
	if disableAllResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for disable-all, got %d", disableAllResp.StatusCode)
	}

	// Verify disabled demo account's existing session cookie is immediately rejected (401)
	meReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/me", nil)
	for _, c := range demoCookies2 {
		meReq.AddCookie(c)
	}
	meResp, err := client.Do(meReq)
	if err != nil {
		t.Fatalf("GET /api/v1/me with disabled session: %v", err)
	}
	meResp.Body.Close()
	if meResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for disabled local account session, got %d", meResp.StatusCode)
	}
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

	// 5. Archived object (AA) returns 409 Conflict before restore, and 200 OK after POST .../restore
	archKey := "isos/legacy/centos-7.9-2009-x86_64-minimal.iso"
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/raw/"+archKey, nil)
	req.SetBasicAuth(cfg.BootstrapNexusAccountID, cfg.BootstrapNexusAccountKey)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("GET archived ISO: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409 Conflict when downloading un-restored AA object, got %d", resp.StatusCode)
	}

	restoreReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/objects/"+archKey+"/restore", nil)
	restoreReq.SetBasicAuth(cfg.BootstrapNexusAccountID, cfg.BootstrapNexusAccountKey)
	restoreResp, err := client.Do(restoreReq)
	if err != nil {
		t.Fatalf("POST restore: %v", err)
	}
	restoreResp.Body.Close()
	if restoreResp.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted on restore, got %d", restoreResp.StatusCode)
	}

	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/raw/"+archKey, nil)
	req.SetBasicAuth(cfg.BootstrapNexusAccountID, cfg.BootstrapNexusAccountKey)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("GET restored ISO: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK after restoring AA object, got %d", resp.StatusCode)
	}
}

func TestGitHubActionsOIDCJWTUploadAndAccessLogs(t *testing.T) {
	srv, cfg := setupTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()
	client := ts.Client()

	// 1. Mint a signed GitHub Actions OIDC JWT for repo:my-org/iso-builder:ref:refs/heads/main (authenticated as admin)
	mintReqBody := `{"repository":"my-org/iso-builder","ref":"refs/heads/main","environment":"production"}`
	mintReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/auth/github-test-jwt", strings.NewReader(mintReqBody))
	mintReq.SetBasicAuth("admin", cfg.BootstrapAdminPassword)
	mintReq.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(mintReq)
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
	logReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/objects/isos/nightly/fedora-41.iso/logs", nil)
	logReq.SetBasicAuth("admin", cfg.BootstrapAdminPassword)
	logResp, err := client.Do(logReq)
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

