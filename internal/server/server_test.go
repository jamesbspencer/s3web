package server_test

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
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

func TestAllowedFileExtensionsLimiting(t *testing.T) {
	srv, cfg := setupTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()
	client := ts.Client()

	// 1. Configure allowed extensions to: .iso, .img, .tar.gz
	setPayload := map[string]interface{}{
		"repository_title":        "Extension Limited Repo",
		"allowed_file_extensions": []string{".iso", ".img", ".tar.gz"},
	}
	body, _ := json.Marshal(setPayload)
	putReq, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/settings", bytes.NewReader(body))
	putReq.Header.Set("Content-Type", "application/json")
	putReq.SetBasicAuth("admin", cfg.BootstrapAdminPassword)
	putResp, err := client.Do(putReq)
	if err != nil {
		t.Fatalf("PUT settings: %v", err)
	}
	putResp.Body.Close()
	if putResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK configuring allowed extensions, got %d", putResp.StatusCode)
	}

	// 2. Upload valid extensions: .iso, .tar.gz, .img (should succeed)
	validFiles := []string{
		"isos/ubuntu-24.04.iso",
		"archives/build-123.tar.gz",
		"images/raw-disk.IMG", // case-insensitive
	}
	for _, k := range validFiles {
		upReq, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/objects/"+k, strings.NewReader("dummy payload content"))
		upReq.SetBasicAuth("admin", cfg.BootstrapAdminPassword)
		upResp, err := client.Do(upReq)
		if err != nil {
			t.Fatalf("upload %s: %v", k, err)
		}
		upResp.Body.Close()
		if upResp.StatusCode != http.StatusCreated {
			t.Fatalf("expected 201 Created for valid extension %s, got %d", k, upResp.StatusCode)
		}
	}

	// 3. Upload invalid extensions: .exe, .sh, .zip (should fail with 400 Bad Request)
	invalidFiles := []string{
		"payloads/malicious.exe",
		"scripts/deploy.sh",
		"packages/archive.zip",
	}
	for _, k := range invalidFiles {
		upReq, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/objects/"+k, strings.NewReader("dummy payload content"))
		upReq.SetBasicAuth("admin", cfg.BootstrapAdminPassword)
		upResp, err := client.Do(upReq)
		if err != nil {
			t.Fatalf("upload %s: %v", k, err)
		}
		var errResp struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(upResp.Body).Decode(&errResp)
		upResp.Body.Close()
		if upResp.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected 400 Bad Request for disallowed extension %s, got %d", k, upResp.StatusCode)
		}
		if !strings.Contains(strings.ToLower(errResp.Error), "not allowed") {
			t.Fatalf("expected 'not allowed' in error message for %s, got %q", k, errResp.Error)
		}
	}

	// 4. Update settings to allow wildcard "*" (unrestricted)
	wildPayload := map[string]interface{}{
		"allowed_file_extensions": []string{"*"},
	}
	body, _ = json.Marshal(wildPayload)
	putReq, _ = http.NewRequest(http.MethodPut, ts.URL+"/api/v1/settings", bytes.NewReader(body))
	putReq.Header.Set("Content-Type", "application/json")
	putReq.SetBasicAuth("admin", cfg.BootstrapAdminPassword)
	putResp, err = client.Do(putReq)
	if err != nil {
		t.Fatalf("PUT settings wildcard: %v", err)
	}
	putResp.Body.Close()
	if putResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK updating wildcard settings, got %d", putResp.StatusCode)
	}

	// Previously disallowed .zip and .exe should now succeed with wildcard
	for _, k := range []string{"packages/archive.zip", "binaries/tool.exe"} {
		upReq, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/objects/"+k, strings.NewReader("dummy payload content"))
		upReq.SetBasicAuth("admin", cfg.BootstrapAdminPassword)
		upResp, err := client.Do(upReq)
		if err != nil {
			t.Fatalf("upload %s with wildcard: %v", k, err)
		}
		upResp.Body.Close()
		if upResp.StatusCode != http.StatusCreated {
			t.Fatalf("expected 201 Created under wildcard for %s, got %d", k, upResp.StatusCode)
		}
	}

	// 5. In-App Access Grant with grant-specific allowed_extensions
	grantPayload := map[string]interface{}{
		"subject_type":       model.SubjectLocalUser,
		"subject_id":         "demo",
		"prefixes":           []string{"demo-only/*"},
		"allowed_extensions": []string{".iso"},
		"can_read":           true,
		"can_upload":         true,
	}
	gBody, _ := json.Marshal(grantPayload)
	gReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/admin/grants", bytes.NewReader(gBody))
	gReq.Header.Set("Content-Type", "application/json")
	gReq.SetBasicAuth("admin", cfg.BootstrapAdminPassword)
	gResp, err := client.Do(gReq)
	if err != nil {
		t.Fatalf("create grant: %v", err)
	}
	gResp.Body.Close()
	if gResp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 Created creating grant, got %d", gResp.StatusCode)
	}

	// Demo user uploading .iso -> succeeds
	demoIsoReq, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/objects/demo-only/test.iso", strings.NewReader("iso payload"))
	demoIsoReq.SetBasicAuth("demo", cfg.BootstrapDemoPassword)
	demoIsoResp, err := client.Do(demoIsoReq)
	if err != nil {
		t.Fatalf("demo upload iso: %v", err)
	}
	demoIsoResp.Body.Close()
	if demoIsoResp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 Created for demo .iso upload, got %d", demoIsoResp.StatusCode)
	}

	// Demo user uploading .tar.gz -> fails with 403 Forbidden because grant restricts to .iso
	demoTarReq, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/objects/demo-only/test.tar.gz", strings.NewReader("tar payload"))
	demoTarReq.SetBasicAuth("demo", cfg.BootstrapDemoPassword)
	demoTarResp, err := client.Do(demoTarReq)
	if err != nil {
		t.Fatalf("demo upload tar: %v", err)
	}
	demoTarResp.Body.Close()
	if demoTarResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for demo uploading .tar.gz when grant restricts to .iso, got %d", demoTarResp.StatusCode)
	}
}

func TestSecurityRemediationsAndEdgeCases(t *testing.T) {
	srv, cfg := setupTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()
	client := ts.Client()

	// 1. Multipart Form Upload Streaming & Validation
	var mpBuf bytes.Buffer
	mpWriter := multipart.NewWriter(&mpBuf)
	part, err := mpWriter.CreateFormFile("file", "image.iso")
	if err != nil {
		t.Fatalf("create multipart part: %v", err)
	}
	part.Write([]byte("multipart iso stream content"))
	mpWriter.Close()

	mpReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/objects/isos/image.iso", &mpBuf)
	mpReq.Header.Set("Content-Type", mpWriter.FormDataContentType())
	mpReq.SetBasicAuth("admin", cfg.BootstrapAdminPassword)
	mpResp, err := client.Do(mpReq)
	if err != nil {
		t.Fatalf("multipart upload: %v", err)
	}
	mpResp.Body.Close()
	if mpResp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 Created for multipart upload, got %d", mpResp.StatusCode)
	}

	// Multipart upload with disallowed filename extension
	var badMpBuf bytes.Buffer
	badMpWriter := multipart.NewWriter(&badMpBuf)
	badPart, _ := badMpWriter.CreateFormFile("file", "malicious.sh")
	badPart.Write([]byte("#!/bin/sh\n"))
	badMpWriter.Close()

	badMpReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/objects/isos/script.iso", &badMpBuf)
	badMpReq.Header.Set("Content-Type", badMpWriter.FormDataContentType())
	badMpReq.SetBasicAuth("admin", cfg.BootstrapAdminPassword)
	badMpResp, err := client.Do(badMpReq)
	if err != nil {
		t.Fatalf("bad multipart upload: %v", err)
	}
	badMpResp.Body.Close()
	if badMpResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for disallowed multipart filename, got %d", badMpResp.StatusCode)
	}

	// Multipart upload by non-admin with prefix-scoped grant (demo on scoped-dir/*)
	demoGrantPayload := map[string]interface{}{
		"subject_type":       model.SubjectLocalUser,
		"subject_id":         "demo",
		"prefixes":           []string{"scoped-dir/*"},
		"allowed_extensions": []string{".iso"},
		"can_upload":         true,
	}
	dgBody, _ := json.Marshal(demoGrantPayload)
	dgReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/admin/grants", bytes.NewReader(dgBody))
	dgReq.Header.Set("Content-Type", "application/json")
	dgReq.SetBasicAuth("admin", cfg.BootstrapAdminPassword)
	dgResp, err := client.Do(dgReq)
	if err != nil {
		t.Fatalf("create scoped grant: %v", err)
	}
	dgResp.Body.Close()

	var scopedMpBuf bytes.Buffer
	scopedMpWriter := multipart.NewWriter(&scopedMpBuf)
	scopedPart, _ := scopedMpWriter.CreateFormFile("file", "test-scoped.iso")
	scopedPart.Write([]byte("scoped iso payload"))
	scopedMpWriter.Close()

	scopedMpReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/objects/scoped-dir/test-scoped.iso", &scopedMpBuf)
	scopedMpReq.Header.Set("Content-Type", scopedMpWriter.FormDataContentType())
	scopedMpReq.SetBasicAuth("demo", cfg.BootstrapDemoPassword)
	scopedMpResp, err := client.Do(scopedMpReq)
	if err != nil {
		t.Fatalf("scoped multipart upload: %v", err)
	}
	scopedMpResp.Body.Close()
	if scopedMpResp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 Created for demo scoped multipart upload, got %d", scopedMpResp.StatusCode)
	}

	// 2. Trailing Slash Upload Rejection
	slashReq, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/objects/isos/trailing.iso/", strings.NewReader("content"))
	slashReq.SetBasicAuth("admin", cfg.BootstrapAdminPassword)
	slashResp, err := client.Do(slashReq)
	if err != nil {
		t.Fatalf("trailing slash upload: %v", err)
	}
	slashResp.Body.Close()
	if slashResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for trailing slash upload, got %d", slashResp.StatusCode)
	}

	// 3. Object Download Read Authorization
	// Upload an object to confidential/data.iso as admin
	upReq, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/objects/confidential/data.iso", strings.NewReader("secret payload"))
	upReq.SetBasicAuth("admin", cfg.BootstrapAdminPassword)
	upResp, err := client.Do(upReq)
	if err != nil {
		t.Fatalf("upload confidential: %v", err)
	}
	upResp.Body.Close()
	if upResp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d", upResp.StatusCode)
	}

	// Create service account without read grants
	saPayload := map[string]interface{}{
		"account_id":  "upload-bot",
		"description": "Upload-only bot",
	}
	saBody, _ := json.Marshal(saPayload)
	saReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/admin/service-accounts", bytes.NewReader(saBody))
	saReq.Header.Set("Content-Type", "application/json")
	saReq.SetBasicAuth("admin", cfg.BootstrapAdminPassword)
	saResp, err := client.Do(saReq)
	if err != nil {
		t.Fatalf("create service account: %v", err)
	}
	var saCreated struct {
		Secret string `json:"secret"`
	}
	json.NewDecoder(saResp.Body).Decode(&saCreated)
	saResp.Body.Close()
	if saResp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 Created creating service account, got %d", saResp.StatusCode)
	}

	// Service account attempts to download confidential/data.iso without read grant -> 403 Forbidden
	saDlReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/objects/confidential/data.iso/download", nil)
	saDlReq.Header.Set("Authorization", "Bearer upload-bot:"+saCreated.Secret)
	saDlResp, err := client.Do(saDlReq)
	if err != nil {
		t.Fatalf("sa download: %v", err)
	}
	saDlResp.Body.Close()
	if saDlResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for unauthorized download, got %d", saDlResp.StatusCode)
	}

	// Admin downloads confidential/data.iso -> 200 OK
	adminDlReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/objects/confidential/data.iso/download", nil)
	adminDlReq.SetBasicAuth("admin", cfg.BootstrapAdminPassword)
	adminDlResp, err := client.Do(adminDlReq)
	if err != nil {
		t.Fatalf("admin download: %v", err)
	}
	dlContent, _ := io.ReadAll(adminDlResp.Body)
	adminDlResp.Body.Close()
	if adminDlResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for admin download, got %d", adminDlResp.StatusCode)
	}
	if string(dlContent) != "secret payload" {
		t.Fatalf("download content mismatch: got %q", string(dlContent))
	}

	// 4. Scoped is_admin Grant Creation Rejection
	badGrantPayload := map[string]interface{}{
		"subject_type": model.SubjectLocalUser,
		"subject_id":   "demo",
		"prefixes":     []string{"demo-only/*"},
		"is_admin":     true,
	}
	bgBody, _ := json.Marshal(badGrantPayload)
	bgReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/admin/grants", bytes.NewReader(bgBody))
	bgReq.Header.Set("Content-Type", "application/json")
	bgReq.SetBasicAuth("admin", cfg.BootstrapAdminPassword)
	bgResp, err := client.Do(bgReq)
	if err != nil {
		t.Fatalf("create bad grant: %v", err)
	}
	bgResp.Body.Close()
	if bgResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for scoped is_admin grant, got %d", bgResp.StatusCode)
	}

	// 5. Settings Information Disclosure Redaction
	demoSetReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/settings", nil)
	demoSetReq.SetBasicAuth("demo", cfg.BootstrapDemoPassword)
	demoSetResp, err := client.Do(demoSetReq)
	if err != nil {
		t.Fatalf("demo get settings: %v", err)
	}
	var demoSettings map[string]interface{}
	json.NewDecoder(demoSetResp.Body).Decode(&demoSettings)
	demoSetResp.Body.Close()
	if demoSetResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for demo get settings, got %d", demoSetResp.StatusCode)
	}
	if _, ok := demoSettings["dynamodb_table"]; ok {
		t.Fatalf("expected dynamodb_table to be redacted for non-admin, found %v", demoSettings["dynamodb_table"])
	}
	if _, ok := demoSettings["sqs_queue_url"]; ok {
		t.Fatalf("expected sqs_queue_url to be redacted for non-admin, found %v", demoSettings["sqs_queue_url"])
	}
	if _, ok := demoSettings["bootstrap_admin_oidc_group"]; ok {
		t.Fatalf("expected bootstrap_admin_oidc_group to be redacted for non-admin, found %v", demoSettings["bootstrap_admin_oidc_group"])
	}
	if _, ok := demoSettings["allowed_file_extensions"]; !ok {
		t.Fatalf("expected allowed_file_extensions to be present in public settings")
	}
}

