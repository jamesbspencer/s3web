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
	cfg.BootstrapRawAccountID = "svc-raw-access"
	cfg.BootstrapRawAccountKey = "raw-secret-123"
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
	req.SetBasicAuth(cfg.BootstrapRawAccountID, "wrong-secret")
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
	req.SetBasicAuth(cfg.BootstrapRawAccountID, cfg.BootstrapRawAccountKey)
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
	req.SetBasicAuth(cfg.BootstrapRawAccountID, cfg.BootstrapRawAccountKey)
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
	req.SetBasicAuth(cfg.BootstrapRawAccountID, cfg.BootstrapRawAccountKey)
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
	req.SetBasicAuth(cfg.BootstrapRawAccountID, cfg.BootstrapRawAccountKey)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("GET archived ISO: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409 Conflict when downloading un-restored AA object, got %d", resp.StatusCode)
	}

	restoreReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/objects/"+archKey+"/restore", nil)
	restoreReq.SetBasicAuth(cfg.BootstrapRawAccountID, cfg.BootstrapRawAccountKey)
	restoreResp, err := client.Do(restoreReq)
	if err != nil {
		t.Fatalf("POST restore: %v", err)
	}
	restoreResp.Body.Close()
	if restoreResp.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted on restore, got %d", restoreResp.StatusCode)
	}

	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/raw/"+archKey, nil)
	req.SetBasicAuth(cfg.BootstrapRawAccountID, cfg.BootstrapRawAccountKey)
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

func TestServiceAccountsLifecycleAndAuth(t *testing.T) {
	srv, cfg := setupTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()
	client := ts.Client()

	// 1. Non-admin user (demo) is rejected with 403 Forbidden when managing service accounts
	demoReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/admin/service-accounts", nil)
	demoReq.SetBasicAuth("demo", cfg.BootstrapDemoPassword)
	demoResp, err := client.Do(demoReq)
	if err != nil {
		t.Fatalf("demo GET service-accounts: %v", err)
	}
	demoResp.Body.Close()
	if demoResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for non-admin, got %d", demoResp.StatusCode)
	}

	// 2. Admin creates a new service account with scoped upload permissions
	createPayload := map[string]interface{}{
		"account_id":  "svc-build-agent",
		"name":        "CI Build Agent",
		"description": "Automated build uploader",
		"prefixes":    []string{"builds/*"},
		"can_read":    true,
		"can_upload":  true,
		"can_delete":  false,
	}
	body, _ := json.Marshal(createPayload)
	createReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/admin/service-accounts", bytes.NewReader(body))
	createReq.Header.Set("Content-Type", "application/json")
	createReq.SetBasicAuth("admin", cfg.BootstrapAdminPassword)
	createResp, err := client.Do(createReq)
	if err != nil {
		t.Fatalf("admin POST service-accounts: %v", err)
	}
	var created struct {
		ServiceAccount model.ServiceAccount `json:"service_account"`
		Secret         string               `json:"secret"`
		BearerHeader   string               `json:"bearer_header"`
	}
	if err := json.NewDecoder(createResp.Body).Decode(&created); err != nil {
		t.Fatalf("decode create service-account: %v", err)
	}
	createResp.Body.Close()
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d", createResp.StatusCode)
	}
	if created.Secret == "" || !strings.HasPrefix(created.Secret, "s3w_") {
		t.Fatalf("expected s3w_ prefixed secret, got %q", created.Secret)
	}

	// 3. Attempting to create duplicate service account returns 409 Conflict
	dupReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/admin/service-accounts", bytes.NewReader(body))
	dupReq.Header.Set("Content-Type", "application/json")
	dupReq.SetBasicAuth("admin", cfg.BootstrapAdminPassword)
	dupResp, err := client.Do(dupReq)
	if err != nil {
		t.Fatalf("duplicate POST service-accounts: %v", err)
	}
	dupResp.Body.Close()
	if dupResp.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409 Conflict for duplicate service account, got %d", dupResp.StatusCode)
	}

	// 4. Authenticate using HTTP Basic Auth (account_id : secret)
	meBasicReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/me", nil)
	meBasicReq.SetBasicAuth("svc-build-agent", created.Secret)
	meBasicResp, err := client.Do(meBasicReq)
	if err != nil {
		t.Fatalf("GET /api/v1/me with service account Basic Auth: %v", err)
	}
	var meBasic struct {
		Principal model.Principal `json:"principal"`
	}
	_ = json.NewDecoder(meBasicResp.Body).Decode(&meBasic)
	meBasicResp.Body.Close()
	if meBasicResp.StatusCode != http.StatusOK || meBasic.Principal.Type != model.PrincipalServiceAccount {
		t.Fatalf("expected 200 OK and SERVICE_ACCOUNT, got status=%d, principal=%+v", meBasicResp.StatusCode, meBasic.Principal)
	}

	// 5. Authenticate using HTTP Bearer Token ("Authorization: Bearer <account_id>:<secret>")
	uploadReq, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/objects/builds/artifact-v1.tar.gz", strings.NewReader("sample build content"))
	uploadReq.Header.Set("Authorization", "Bearer svc-build-agent:"+created.Secret)
	uploadResp, err := client.Do(uploadReq)
	if err != nil {
		t.Fatalf("PUT object with Bearer token: %v", err)
	}
	uploadResp.Body.Close()
	if uploadResp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 Created for authorized upload, got %d", uploadResp.StatusCode)
	}

	// 6. Delete without delete permission returns 403 Forbidden
	delObjReq, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/objects/builds/artifact-v1.tar.gz", nil)
	delObjReq.Header.Set("Authorization", "Bearer svc-build-agent:"+created.Secret)
	delObjResp, err := client.Do(delObjReq)
	if err != nil {
		t.Fatalf("DELETE object with Bearer token: %v", err)
	}
	delObjResp.Body.Close()
	if delObjResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden when service account lacks delete permission, got %d", delObjResp.StatusCode)
	}

	// 7. Admin revokes the service account
	delSaReq, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/admin/service-accounts/svc-build-agent", nil)
	delSaReq.SetBasicAuth("admin", cfg.BootstrapAdminPassword)
	delSaResp, err := client.Do(delSaReq)
	if err != nil {
		t.Fatalf("DELETE service account: %v", err)
	}
	delSaResp.Body.Close()
	if delSaResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK on revocation, got %d", delSaResp.StatusCode)
	}

	// 8. Subsequent requests with revoked service account credentials fail with 401 Unauthorized
	revokedReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/me", nil)
	revokedReq.SetBasicAuth("svc-build-agent", created.Secret)
	revokedResp, err := client.Do(revokedReq)
	if err != nil {
		t.Fatalf("GET /api/v1/me with revoked service account: %v", err)
	}
	revokedResp.Body.Close()
	if revokedResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized after service account deletion, got %d", revokedResp.StatusCode)
	}
}

func TestAccessGrantsAndSettingsLifecycle(t *testing.T) {
	srv, cfg := setupTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()
	client := ts.Client()

	// 1. Non-admin rejected with 403 on grants endpoint
	demoGrantsReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/admin/grants", nil)
	demoGrantsReq.SetBasicAuth("demo", cfg.BootstrapDemoPassword)
	demoGrantsResp, err := client.Do(demoGrantsReq)
	if err != nil {
		t.Fatalf("demo GET grants: %v", err)
	}
	demoGrantsResp.Body.Close()
	if demoGrantsResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for non-admin on grants, got %d", demoGrantsResp.StatusCode)
	}

	// 2. Admin creates an Access Grant
	grantPayload := map[string]interface{}{
		"subject_type": model.SubjectLocalUser,
		"subject_id":   "demo",
		"description":  "Demo user upload access to demos prefix",
		"prefixes":     []string{"demos/*"},
		"can_read":     true,
		"can_upload":   true,
		"can_delete":   false,
	}
	grantBody, _ := json.Marshal(grantPayload)
	createGrantReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/admin/grants", bytes.NewReader(grantBody))
	createGrantReq.Header.Set("Content-Type", "application/json")
	createGrantReq.SetBasicAuth("admin", cfg.BootstrapAdminPassword)
	createGrantResp, err := client.Do(createGrantReq)
	if err != nil {
		t.Fatalf("admin POST grants: %v", err)
	}
	var createdGrant model.AccessGrant
	if err := json.NewDecoder(createGrantResp.Body).Decode(&createdGrant); err != nil {
		t.Fatalf("decode created grant: %v", err)
	}
	createGrantResp.Body.Close()
	if createGrantResp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 Created for grant, got %d", createGrantResp.StatusCode)
	}
	if createdGrant.ID == "" {
		t.Fatal("expected non-empty generated grant ID in response")
	}

	// 3. Admin updates settings
	settingsPayload := map[string]interface{}{
		"repository_title":         "Custom Corporate Repository",
		"default_tree_state":       "collapsed",
		"enable_html_autoindex":    true,
		"enable_checksum_sidecars": true,
		"default_restore_days":     14,
		"default_restore_tier":     "Expedited",
		"buckets": []map[string]interface{}{
			{"id": "primary", "friendly_name": "Primary Bucket", "bucket_name": "corp-artifacts", "region": "us-east-1"},
		},
	}
	settingsBody, _ := json.Marshal(settingsPayload)
	updateSettingsReq, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/settings", bytes.NewReader(settingsBody))
	updateSettingsReq.Header.Set("Content-Type", "application/json")
	updateSettingsReq.SetBasicAuth("admin", cfg.BootstrapAdminPassword)
	updateSettingsResp, err := client.Do(updateSettingsReq)
	if err != nil {
		t.Fatalf("PUT settings: %v", err)
	}
	updateSettingsResp.Body.Close()
	if updateSettingsResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK updating settings, got %d", updateSettingsResp.StatusCode)
	}

	// 4. Verify settings updated
	getSettingsReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/settings", nil)
	getSettingsReq.SetBasicAuth("admin", cfg.BootstrapAdminPassword)
	getSettingsResp, err := client.Do(getSettingsReq)
	if err != nil {
		t.Fatalf("GET settings: %v", err)
	}
	var updatedSettings model.AppSettings
	_ = json.NewDecoder(getSettingsResp.Body).Decode(&updatedSettings)
	getSettingsResp.Body.Close()
	if updatedSettings.RepositoryTitle != "Custom Corporate Repository" || updatedSettings.DefaultTreeState != "collapsed" {
		t.Fatalf("unexpected settings: %+v", updatedSettings)
	}

	// 5. Admin deletes the grant
	delGrantReq, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/admin/grants/"+createdGrant.ID, nil)
	delGrantReq.SetBasicAuth("admin", cfg.BootstrapAdminPassword)
	delGrantResp, err := client.Do(delGrantReq)
	if err != nil {
		t.Fatalf("DELETE grant: %v", err)
	}
	delGrantResp.Body.Close()
	if delGrantResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK on deleting grant, got %d", delGrantResp.StatusCode)
	}
}

