package model

import (
	"time"
)

// IntelligentTier represents the Amazon S3 Intelligent-Tiering access sub-tier.
type IntelligentTier string

const (
	TierFrequentAccess       IntelligentTier = "FA"  // Frequent Access (Hot, <30 days since last access)
	TierInfrequentAccess     IntelligentTier = "IA"  // Infrequent Access (Warm, 30-90 days unaccessed)
	TierArchiveInstantAccess IntelligentTier = "AIA" // Archive Instant Access (90+ days unaccessed, ms latency)
	TierArchiveAccess        IntelligentTier = "AA"  // Asynchronous Archive Access (3-5h restore required)
	TierDeepArchiveAccess    IntelligentTier = "DAA" // Asynchronous Deep Archive Access (12h restore required)
)

// RestoreStatus tracks asynchronous archive restoration state.
type RestoreStatus string

const (
	RestoreNone       RestoreStatus = "NONE"
	RestoreInProgress RestoreStatus = "IN_PROGRESS"
	RestoreRestored   RestoreStatus = "RESTORED"
)

// HashStatus tracks whether full-file linear SHA-256 and SHA-1 digests are ready.
type HashStatus string

const (
	HashReady     HashStatus = "READY"
	HashComputing HashStatus = "COMPUTING"
	HashFailed    HashStatus = "FAILED"
)

// ObjectMeta represents an S3 object's metadata, linear checksums, and Intelligent-Tiering state.
type ObjectMeta struct {
	Key             string          `json:"key"`
	Filename        string          `json:"filename"`
	ParentPrefix    string          `json:"parent_prefix"`
	BucketName      string          `json:"bucket_name,omitempty"`
	Size            int64           `json:"size"`
	ContentType     string          `json:"content_type"`
	StorageClass    string          `json:"storage_class"`
	IntelligentTier IntelligentTier `json:"intelligent_tier"`
	TierLabel       string          `json:"tier_label"`
	RestoreStatus   RestoreStatus   `json:"restore_status"`
	RestoreExpiry   *time.Time      `json:"restore_expiry,omitempty"`
	SHA256          string          `json:"sha256"`
	SHA1            string          `json:"sha1"`
	HashStatus      HashStatus      `json:"hash_status"`
	S3ETag          string          `json:"s3_etag,omitempty"`
	S3VersionID     string          `json:"s3_version_id,omitempty"`
	UploadedBy      string          `json:"uploaded_by"`
	UpdatedAt       time.Time       `json:"updated_at"`
	LastAccessedAt  time.Time       `json:"last_accessed_at"`
	DownloadCount   int64           `json:"download_count"`
}

// ComputeEffectiveTier resolves the S3 Intelligent-Tiering sub-tier based on explicit archive status
// and time elapsed since LastAccessedAt.
func (o *ObjectMeta) ComputeEffectiveTier(now time.Time) IntelligentTier {
	if o.RestoreStatus == RestoreRestored {
		return TierFrequentAccess
	}
	if o.IntelligentTier == TierArchiveAccess || o.IntelligentTier == TierDeepArchiveAccess {
		return o.IntelligentTier
	}
	ref := o.LastAccessedAt
	if ref.IsZero() {
		ref = o.UpdatedAt
	}
	age := now.Sub(ref)
	switch {
	case age >= 90*24*time.Hour:
		return TierArchiveInstantAccess
	case age >= 30*24*time.Hour:
		return TierInfrequentAccess
	default:
		return TierFrequentAccess
	}
}

// TierDisplayLabel returns a human-readable description for the UI.
func TierDisplayLabel(tier IntelligentTier) string {
	switch tier {
	case TierFrequentAccess:
		return "Frequent Access (FA)"
	case TierInfrequentAccess:
		return "Infrequent Access (IA)"
	case TierArchiveInstantAccess:
		return "Archive Instant Access (AIA)"
	case TierArchiveAccess:
		return "Archive Access (AA - Restore Req)"
	case TierDeepArchiveAccess:
		return "Deep Archive (DAA - Restore Req)"
	default:
		return "Frequent Access (FA)"
	}
}

// IsAsyncArchived returns true if the object requires an asynchronous RestoreObject call before streaming.
func (o *ObjectMeta) IsAsyncArchived() bool {
	if o.RestoreStatus == RestoreRestored {
		return false
	}
	return o.IntelligentTier == TierArchiveAccess || o.IntelligentTier == TierDeepArchiveAccess
}

// DirectoryEntry represents either a child folder or a file in a prefix listing.
type DirectoryEntry struct {
	Type            string          `json:"type"` // "DIR" or "FILE"
	Name            string          `json:"name"`
	Key             string          `json:"key"`
	Size            int64           `json:"size"`
	ContentType     string          `json:"content_type,omitempty"`
	StorageClass    string          `json:"storage_class,omitempty"`
	IntelligentTier IntelligentTier `json:"intelligent_tier,omitempty"`
	TierLabel       string          `json:"tier_label,omitempty"`
	RestoreStatus   RestoreStatus   `json:"restore_status,omitempty"`
	SHA256          string          `json:"sha256,omitempty"`
	SHA1            string          `json:"sha1,omitempty"`
	HashStatus      HashStatus      `json:"hash_status,omitempty"`
	UpdatedAt       time.Time       `json:"updated_at,omitempty"`
	LastAccessedAt  time.Time       `json:"last_accessed_at,omitempty"`
	DownloadCount   int64           `json:"download_count,omitempty"`
}

// PrincipalType identifies how the caller authenticated.
type PrincipalType string

const (
	PrincipalLocalUser      PrincipalType = "LOCAL_USER"
	PrincipalSSOUser        PrincipalType = "SSO_USER"
	PrincipalGitHubWorkflow PrincipalType = "GITHUB_WORKFLOW"
	PrincipalServiceAccount PrincipalType = "SERVICE_ACCOUNT"
)

// AccessAction identifies the action logged against an object.
type AccessAction string

const (
	ActionDownload AccessAction = "DOWNLOAD"
	ActionUpload   AccessAction = "UPLOAD"
	ActionDelete   AccessAction = "DELETE"
	ActionRestore  AccessAction = "RESTORE"
	ActionHead     AccessAction = "HEAD"
)

// AccessLogEntry represents a single per-item access log event.
type AccessLogEntry struct {
	ID            string        `json:"id"`
	ObjectKey     string        `json:"object_key"`
	Timestamp     time.Time     `json:"timestamp"`
	Action        AccessAction  `json:"action"`
	PrincipalType PrincipalType `json:"principal_type"`
	PrincipalID   string        `json:"principal_id"`
	Groups        []string      `json:"groups,omitempty"`
	ClientIP      string        `json:"client_ip"`
	UserAgent     string        `json:"user_agent"`
	BytesSent     int64         `json:"bytes_sent"`
	StatusCode    int           `json:"status_code"`
	RangeRequest  bool          `json:"range_request"`
	DurationMs    int64         `json:"duration_ms"`
}

// SubjectType identifies the target of an In-App Access Grant.
type SubjectType string

const (
	SubjectBuiltin        SubjectType = "BUILTIN"
	SubjectOIDCGroup      SubjectType = "OIDC_GROUP"
	SubjectAppGroup       SubjectType = "APP_GROUP"
	SubjectSSOUser        SubjectType = "SSO_USER"
	SubjectLocalUser      SubjectType = "LOCAL_USER"
	SubjectGitHubWorkflow SubjectType = "GITHUB_WORKFLOW"
	SubjectServiceAccount SubjectType = "SERVICE_ACCOUNT"
)

// AccessGrant defines an in-app permission rule managed inside s3web.
type AccessGrant struct {
	ID          string      `json:"id"`
	Description string      `json:"description"`
	SubjectType SubjectType `json:"subject_type"`
	SubjectID   string      `json:"subject_id"` // e.g. "release-engineering", "alice@corp.com", "repo:my-org/iso-builder:ref:refs/heads/main"
	Prefixes    []string    `json:"prefixes"`   // e.g. ["*"], ["linux/*", "isos/*"]
	CanRead     bool        `json:"can_read"`
	CanUpload   bool        `json:"can_upload"`
	CanDelete   bool        `json:"can_delete"`
	IsAdmin     bool        `json:"is_admin"`
	UpdatedBy   string      `json:"updated_by"`
	UpdatedAt   time.Time   `json:"updated_at"`
}

// AppGroup represents an in-app group of SSO users managed directly inside s3web.
type AppGroup struct {
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Members     []string  `json:"members"` // List of user emails / IDs
	UpdatedBy   string    `json:"updated_by"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// LocalUser represents a local user account managed inside s3web.
type LocalUser struct {
	Username          string     `json:"username"`
	Email             string     `json:"email"`
	DisplayName       string     `json:"display_name"`
	PasswordHash      string     `json:"password_hash,omitempty"` // PBKDF2 hash stored at rest, stripped in API responses
	IsAdmin           bool       `json:"is_admin"`
	Disabled          bool       `json:"disabled"`
	CreatedBy         string     `json:"created_by"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
	PasswordChangedAt *time.Time `json:"password_changed_at,omitempty"`
	LastLoginAt       *time.Time `json:"last_login_at,omitempty"`
}

// Sanitized returns a copy of LocalUser with PasswordHash removed for safe API serialization.
func (u LocalUser) Sanitized() LocalUser {
	u.PasswordHash = ""
	return u
}

// ServiceAccount represents a machine identity for HTML Raw Access or automation scripts.
type ServiceAccount struct {
	AccountID   string     `json:"account_id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	SecretHash  string     `json:"-"` // PBKDF2 / Argon2 hash stored at rest
	CreatedBy   string     `json:"created_by"`
	CreatedAt   time.Time  `json:"created_at"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	Revoked     bool       `json:"revoked"`
}

// Principal represents the authenticated caller attached to the request context.
type Principal struct {
	Type          PrincipalType        `json:"type"`
	ID            string               `json:"id"`
	Username      string               `json:"username,omitempty"`
	DisplayName   string               `json:"display_name"`
	Email         string               `json:"email,omitempty"`
	IsLocalAdmin  bool                 `json:"is_local_admin,omitempty"`
	OIDCGroups    []string             `json:"oidc_groups,omitempty"`
	AppGroups     []string             `json:"app_groups,omitempty"`
	GitHubClaims  map[string]string    `json:"github_claims,omitempty"` // e.g., repository, ref, environment, workflow_ref
	EffectivePerm EffectivePermissions `json:"effective_permissions"`
}

// EffectivePermissions summarizes a caller's resolved permissions across the bucket or a specific prefix.
type EffectivePermissions struct {
	CanRead   bool     `json:"can_read"`
	CanUpload bool     `json:"can_upload"`
	CanDelete bool     `json:"can_delete"`
	IsAdmin   bool     `json:"is_admin"`
	Grants    []string `json:"matched_grants,omitempty"`
}

// BucketMount configures an S3 bucket and its friendly display name in the Artifact Browser tree view.
type BucketMount struct {
	ID           string `json:"id"`
	FriendlyName string `json:"friendly_name"`
	BucketName   string `json:"bucket_name"`
	Region       string `json:"region"`
}

// SSOProviderConfig configures a human OIDC SSO identity provider.
type SSOProviderConfig struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Enabled     bool   `json:"enabled"`
	IssuerURL   string `json:"issuer_url"`
	ClientID    string `json:"client_id"`
	GroupsClaim string `json:"groups_claim"`
	AdminGroup  string `json:"admin_group"`
}

// JWTProviderConfig configures a machine / CI OIDC JWT issuer (e.g. GitHub Actions, GitLab CI, Buildkite).
type JWTProviderConfig struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Enabled       bool   `json:"enabled"`
	IssuerURL     string `json:"issuer_url"`
	Audience      string `json:"audience"`
	SubjectPrefix string `json:"subject_prefix"`
}

// AppSettings holds configurable runtime settings for the s3web instance.
type AppSettings struct {
	RepositoryTitle          string              `json:"repository_title"`
	DefaultTreeState         string              `json:"default_tree_state"` // "expanded" or "collapsed"
	EnableHTMLAutoindex      bool                `json:"enable_html_autoindex"`
	EnableChecksumSidecars   bool                `json:"enable_checksum_sidecars"`
	DefaultRestoreDays       int                 `json:"default_restore_days"`
	DefaultRestoreTier       string              `json:"default_restore_tier"` // "Standard", "Expedited", "Bulk"
	AccessLogRetentionDays   int                 `json:"access_log_retention_days"`
	OIDCEnabled              bool                `json:"oidc_enabled"`
	OIDCIssuerURL            string              `json:"oidc_issuer_url"`
	OIDCClientID             string              `json:"oidc_client_id"`
	OIDCGroupsClaim          string              `json:"oidc_groups_claim"`
	BootstrapAdminOIDCGroup  string              `json:"bootstrap_admin_oidc_group"`
	GitHubOIDCEnabled        bool                `json:"github_oidc_enabled"`
	GitHubOIDCIssuerURL      string              `json:"github_oidc_issuer_url"`
	GitHubOIDCAudience       string              `json:"github_oidc_audience"`
	SSOProviders             []SSOProviderConfig `json:"sso_providers"`
	JWTProviders             []JWTProviderConfig `json:"jwt_providers"`
	BackendMode              string              `json:"backend_mode"`
	AWSRegion                string              `json:"aws_region"`
	S3Bucket                 string              `json:"s3_bucket"`
	Buckets                  []BucketMount       `json:"buckets"`
	DynamoDBTable            string              `json:"dynamodb_table"`
	SQSQueueURL              string              `json:"sqs_queue_url"`
	BootstrapRawAccountID    string              `json:"bootstrap_raw_account_id"`
	UpdatedBy                string              `json:"updated_by,omitempty"`
	UpdatedAt                time.Time           `json:"updated_at,omitempty"`
}


