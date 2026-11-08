# `s3web` — Large File Archive Frontend for AWS S3 Intelligent-Tiering (Go)

`s3web` is a high-performance, single-binary Go large file archive frontend and HTML Raw Access server for Amazon S3 buckets with AWS S3 Intelligent-Tiering (large ISO images, VM disk images, database dumps, tarballs, and compressed archives). Designed with **zero external CDN dependencies** and built to be **private VPC capable** for air-gapped or VPN-only enterprise environments.

## Documentation
- [User Guide](docs/user-guide.md): Browsing large file archives, S3 Intelligent-Tiering tier navigation, checksum verification, S3 restore with Slack notifications, and HTML Raw Access.
- [Administrator Guide](docs/admin-guide.md): In-app RBAC, local accounts, prefix grants, service accounts, Slack incoming webhook configuration, and global audit logging.
- [Installation & Deployment Guide](docs/installation.md): Standalone binary, systemd service, Docker container, AWS ECS Fargate Private VPC via Terraform, and environment variables reference.
- [S3 Authentication & Security Architecture](docs/s3-authentication.md): IAM task role execution, VPC endpoints, and decoupled RBAC.
- [System Architecture Specification (`DESIGN.md`)](DESIGN.md): DynamoDB data model, API endpoints, and component designs.
- [AI Agent Guidelines (`AGENTS.md`)](AGENTS.md): Operational guidelines, security invariants, build/test commands, and conventions for AI coding agents.

## Key Capabilities
- **Zero External CDN Dependencies**: 100% self-contained embedded frontend (`//go:embed` static UI with inline SVG assets, zero runtime internet access or external fonts/scripts required).
- **Private VPC Capable (VPN Access Only)**: Runs securely inside private subnets behind an Internal ALB with S3 & DynamoDB VPC Gateway Endpoints; no public IP addresses or Internet Gateways required.
- **Embedded Swagger API Explorer**: Built-in dark-themed OpenAPI 3.0.3 documentation and interactive API testing client at `/swagger/` and `/api/v1/openapi.json`.
- **Configurable Anonymous Access**: Toggleable anonymous access control across the Web UI (`/api/v1/*`) and HTML Raw Access (`/raw/*`). It is disabled by default; set `S3WEB_ANONYMOUS_ACCESS=true` to enable.
- **Slack Notifications & Restore Completion Alerts**: Team-wide operational alerts via incoming webhook and user-specific Slack notifications when S3 Intelligent-Tiering archive restores complete.
- **Local User Accounts & Lifecycle Management**:
  - On initial install, `s3web` automatically seeds a default `admin` account with a cryptographically random generated password and a `demo` local user account (writing initial credentials to `<S3WEB_LOCAL_DATA_DIR>/bootstrap-credentials.txt` or AWS Secrets Manager via Terraform).
  - Local accounts can update their own passwords (`POST /api/v1/auth/password`).
  - Administrators can reset the password of any local account (`PUT /api/v1/admin/local-users/{username}/password`) and disable individual or all local accounts (`PUT /api/v1/admin/local-users/{username}/status`, `POST /api/v1/admin/local-users/disable-all`).
- **In-App Upload & Delete Permission Management**: All users default to **Read-Only**. Administrators manage **Upload**, **Delete**, and **Admin** Access Grants and **App-Managed Groups** directly in the web interface.
- **Multi-Auth Support**:
  - **Local Accounts**: Built-in local users (`admin`, `demo`, and custom local accounts) with PBKDF2-SHA256 salted password hashes.
  - **Human SSO**: Multiple configurable OIDC SSO providers with group and user-level in-app grants.
  - **CI OIDC JWT Issuers**: Multiple configurable OIDC JWT issuers (`Authorization: Bearer <JWT>`) matched against repository/branch/environment claim patterns.
  - **Service Accounts**: HTTP Basic Auth & Bearer tokens for automated HTML Raw Access and CLI scripts.
- **HTML Raw Access (`/raw/*`)**: Uses the exact same access control as the default UI and supports `GET`, `HEAD`, `Range` requests, `ETag`, `X-Checksum-Sha256`, `X-Checksum-Sha1`, Apache/Nginx-style HTML directory listing, and virtual `.sha256` / `.sha1` checksum sidecars.
- **Streaming Linear Dual-Hashing (`SHA-256` + `SHA-1`)**: Computes full-file linear `SHA-256` and `SHA-1` in a single streaming pass during upload (`internal/hashstream`).
- **File Extension Limiting (Upload Whitelist)**: Configurable repository-level and grant-scoped allowed extension policy (e.g., `.iso`, `.img`, `.tar.gz`, `.tgz`, `.zip`, `.qcow2`, `.raw`) preventing unauthorized file types from being uploaded.
- **S3 Intelligent-Tiering Visibility**: Displays each object's current Intelligent-Tiering sub-tier (`FA`, `IA`, `AIA`, `AA`, `DAA`) and supports one-click archive restoration (`RestoreObject`).
- **Centralized Audit & Per-Item Access Logs**: Real-time per-object access log drawer and global administrator audit log console (`/api/v1/admin/logs`) tracking logins, logouts, downloads, uploads, restores, and deletes.

## Quick Start

### Run with Go
```bash
go run ./cmd/s3web
# Web UI: http://localhost:8080
# HTML Raw Access: http://localhost:8080/raw/
# Swagger API Docs: http://localhost:8080/swagger/
```

### Essential Environment Variables
- `S3WEB_ALLOWED_EXTENSIONS`: Comma-separated upload extension whitelist (default: `.iso,.img,.tar.gz,.tgz,.zip,.qcow2,.raw`; use `*` for unrestricted).
- `S3WEB_S3_BUCKET`: Amazon S3 bucket name.
- `S3WEB_DYNAMODB_TABLE`: Amazon DynamoDB table name for metadata and settings.
- `S3WEB_BOOTSTRAP_ADMIN_USERNAME`: Default admin username (default: `admin`).
- `S3WEB_BOOTSTRAP_RAW_ID`: Default service account ID for automated raw access (default: `svc-raw-access`).
- `S3WEB_ANONYMOUS_ACCESS`: Enable or disable unauthenticated access (`true`/`false`; default: `false`). The legacy `S3WEB_ANONYMOUS_ACCESS_ENABLED` spelling is also accepted when the documented variable is unset.
- `S3WEB_SLACK_WEBHOOK_URL`: Slack incoming webhook URL for notifications and restore alerts.

### Run Tests
```bash
go test -race -v ./...
```

### Build Container Image
```bash
docker build -t s3web:latest .
docker run --rm -p 8080:8080 s3web:latest
```
