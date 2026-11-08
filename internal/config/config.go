package config

import (
	"crypto/rand"
	"encoding/base64"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds the runtime configuration for s3web.
type Config struct {
	ListenAddr string
	BaseURL    string

	// Storage & Metadata Backend ("aws" or "memory"/"local" for local dev/testing)
	BackendMode   string
	AWSRegion     string
	S3Bucket      string
	S3Endpoint    string // Optional custom endpoint (e.g., S3 VPC Gateway / LocalStack / MinIO)
	DynamoDBTable string
	SQSQueueURL   string
	LocalDataDir  string

	// Session & Security
	SessionSecret          string
	CookieSecure           bool
	AnonymousAccessEnabled bool

	// Human OIDC SSO Configuration
	OIDCEnabled      bool
	OIDCIssuerURL    string
	OIDCClientID     string
	OIDCClientSecret string
	OIDCRedirectURL  string
	OIDCGroupsClaim  string

	// GitHub Actions OIDC JWT Configuration
	GitHubOIDCEnabled   bool
	GitHubOIDCIssuerURL string
	GitHubOIDCAudience  string
	GitHubPinnedJWKSJSON string // Optional pinned JWKS JSON for air-gapped private VPCs

	// Bootstrap Admin, Demo Local User & Default HTML Raw Access Service Account (seeded on first boot)
	BootstrapAdminUsername   string
	BootstrapAdminEmail      string
	BootstrapAdminPassword   string
	BootstrapAdminOIDCGroup  string
	BootstrapDemoUsername    string
	BootstrapDemoEmail       string
	BootstrapDemoPassword    string
	BootstrapRawAccountID    string
	BootstrapRawAccountKey   string

	// File Extensions Whitelist
	AllowedExtensions []string

	// Slack Notifications
	SlackNotificationsEnabled bool
	SlackWebhookURL           string

	// Log Retention
	AccessLogRetentionDays int
	WorkerPollInterval     time.Duration
}

// Load reads configuration from environment variables with sensible defaults.
func Load() *Config {
	baseURL := getEnv("S3WEB_BASE_URL", "http://localhost:8080")
	return &Config{
		ListenAddr:               getEnv("S3WEB_LISTEN_ADDR", ":8080"),
		BaseURL:                  strings.TrimRight(baseURL, "/"),
		BackendMode:              strings.ToLower(getEnv("S3WEB_BACKEND_MODE", "local")), // "aws" or "local"
		AWSRegion:                getEnv("AWS_REGION", "us-east-1"),
		S3Bucket:                 getEnv("S3WEB_S3_BUCKET", "corp-iso-artifacts"),
		S3Endpoint:               getEnv("S3WEB_S3_ENDPOINT", ""),
		DynamoDBTable:            getEnv("S3WEB_DYNAMODB_TABLE", "s3web-metadata"),
		SQSQueueURL:              getEnv("S3WEB_SQS_QUEUE_URL", ""),
		LocalDataDir:             getEnv("S3WEB_LOCAL_DATA_DIR", "/tmp/s3web-data"),
		SessionSecret:            getEnv("S3WEB_SESSION_SECRET", randomFallbackSecret(32, "")),
		CookieSecure:             getEnvBool("S3WEB_COOKIE_SECURE", false),
		AnonymousAccessEnabled:   getEnvBool("S3WEB_ANONYMOUS_ACCESS_ENABLED", false),
		OIDCEnabled:              getEnvBool("S3WEB_OIDC_ENABLED", false),
		OIDCIssuerURL:            getEnv("S3WEB_OIDC_ISSUER_URL", ""),
		OIDCClientID:             getEnv("S3WEB_OIDC_CLIENT_ID", ""),
		OIDCClientSecret:         getEnv("S3WEB_OIDC_CLIENT_SECRET", ""),
		OIDCRedirectURL:          getEnv("S3WEB_OIDC_REDIRECT_URL", baseURL+"/auth/callback"),
		OIDCGroupsClaim:          getEnv("S3WEB_OIDC_GROUPS_CLAIM", "groups"),
		GitHubOIDCEnabled:        getEnvBool("S3WEB_GITHUB_OIDC_ENABLED", true),
		GitHubOIDCIssuerURL:      getEnv("S3WEB_GITHUB_OIDC_ISSUER", "https://token.actions.githubusercontent.com"),
		GitHubOIDCAudience:       getEnv("S3WEB_GITHUB_OIDC_AUDIENCE", baseURL),
		GitHubPinnedJWKSJSON:     getEnv("S3WEB_GITHUB_PINNED_JWKS_JSON", ""),
		BootstrapAdminUsername:   getEnv("S3WEB_BOOTSTRAP_ADMIN_USERNAME", "admin"),
		BootstrapAdminEmail:      getEnv("S3WEB_BOOTSTRAP_ADMIN_EMAIL", "admin@example.com"),
		BootstrapAdminPassword:   getEnv("S3WEB_BOOTSTRAP_ADMIN_PASSWORD", ""),
		BootstrapAdminOIDCGroup:  getEnv("S3WEB_BOOTSTRAP_ADMIN_GROUP", "platform-admins"),
		BootstrapDemoUsername:    getEnv("S3WEB_BOOTSTRAP_DEMO_USERNAME", "demo"),
		BootstrapDemoEmail:       getEnv("S3WEB_BOOTSTRAP_DEMO_EMAIL", "demo@example.com"),
		BootstrapDemoPassword:    getEnv("S3WEB_BOOTSTRAP_DEMO_PASSWORD", ""),
		BootstrapRawAccountID:    getEnv("S3WEB_BOOTSTRAP_RAW_ID", "svc-raw-access"),
		BootstrapRawAccountKey:   getEnv("S3WEB_BOOTSTRAP_RAW_SECRET", randomFallbackSecret(24, "s3w_")),
		AllowedExtensions:        ParseExtensionList(getEnv("S3WEB_ALLOWED_EXTENSIONS", ".iso,.img,.tar.gz,.tgz,.zip,.qcow2,.raw")),
		SlackNotificationsEnabled: getEnvBool("S3WEB_SLACK_NOTIFICATIONS_ENABLED", false),
		SlackWebhookURL:           getEnv("S3WEB_SLACK_WEBHOOK_URL", ""),
		AccessLogRetentionDays:   getEnvInt("S3WEB_LOG_RETENTION_DAYS", 90),
		WorkerPollInterval:       time.Duration(getEnvInt("S3WEB_WORKER_POLL_SECONDS", 15)) * time.Second,
	}
}

// ParseExtensionList parses a comma-separated list of extensions (e.g. ".iso, .img, .tar.gz" or "iso, img, tar.gz")
// and returns cleaned, lowercase extensions with leading dots. An empty string or "*" returns an empty slice (unrestricted).
func ParseExtensionList(s string) []string {
	parts := strings.Split(s, ",")
	return CleanExtensionSlice(parts)
}

// CleanExtensionSlice normalizes a slice of extension strings to lowercase with leading dots.
// An empty slice, "*", "all", or ".*" returns an empty slice (unrestricted).
func CleanExtensionSlice(exts []string) []string {
	cleaned := make([]string, 0)
	seen := make(map[string]bool)
	for _, raw := range exts {
		e := strings.ToLower(strings.TrimSpace(raw))
		if e == "" {
			continue
		}
		if e == "*" || e == "all" || e == ".*" {
			return []string{} // unrestricted
		}
		e = strings.TrimPrefix(e, "*")
		e = strings.TrimRight(e, ".")
		if e == "" || e == "." || strings.ContainsAny(e, "/\\ \t") {
			continue
		}
		if !strings.HasPrefix(e, ".") {
			e = "." + e
		}
		if len(e) > 1 && !seen[e] {
			seen[e] = true
			cleaned = append(cleaned, e)
		}
	}
	return cleaned
}

func randomFallbackSecret(byteLen int, prefix string) string {
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		return prefix + "fallback-ephemeral-secret"
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b)
}

func getEnv(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func getEnvBool(key string, fallback bool) bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	if v == "" {
		return fallback
	}
	return v == "1" || v == "true" || v == "yes"
}

func getEnvInt(key string, fallback int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	if n, err := strconv.Atoi(v); err == nil {
		return n
	}
	return fallback
}

