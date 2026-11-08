# AGENTS.md — AI Agent Guidelines for `s3web`

This document defines core architectural principles, workflows, build/test commands, security invariants, and coding guidelines for AI coding agents operating on the `s3web` codebase.

---

## 1. Project Overview

`s3web` is a high-performance, single-binary Go application providing a private Web UI and an Apache/Nginx-style `/raw/` HTML directory index for Amazon S3 buckets storing large ISO images and compressed archives.

- **Primary Architecture Specification**: [`DESIGN.md`](DESIGN.md)
- **S3 Authentication & Security Architecture**: [`docs/s3-authentication.md`](docs/s3-authentication.md)
- **Embedded Frontend**: Self-contained HTML/CSS/JS bundled via `//go:embed` in [`internal/ui/`](internal/ui/) (zero external CDN or runtime internet access).

---

## 2. Environment & Essential Commands

### Go Toolchain & Build Environment
If running in environments where Go is extracted to `/tmp/go`, ensure the path is exported:
```bash
export PATH="/tmp/go/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"
```

### Running Tests
Always run the complete test suite before committing changes:
```bash
# Standard test run
go test -v ./...

# Race detection test run
go test -race -v ./...
```

### Compiling & Building Binaries
```bash
# Local development build
go build -o bin/s3web ./cmd/s3web

# Linux arm64 production build (Fargate target)
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o /tmp/s3web-linux-arm64 ./cmd/s3web
```

### Running Locally
```bash
go run ./cmd/s3web
# Listens on http://localhost:8080
# Admin UI: http://localhost:8080/
# HTML Raw Access: http://localhost:8080/raw/
```

---

## 3. Terraform & AWS Deployment Conventions

The infrastructure lives in [`terraform/`](terraform/).

### AWS Credentials in Shell Sessions
When executing AWS CLI or Terraform commands from a non-interactive shell, export AWS profile credentials first:
```bash
eval "$(aws configure export-credentials --format env)"
```

### Strict Git Ignore Rules
**Never stage or commit the following files to git**:
- `terraform/client_vpn.local.tf`
- `terraform/*.ovpn`
- `terraform/terraform.tfstate*`
- `terraform/terraform.tfvars`

---

## 4. Architecture & Security Invariants

When modifying or adding features, preserve these invariants:

1. **Zero External CDN Dependencies**:
   - The UI runs inside a completely private network with no internet access.
   - Do **not** link to external CDNs (`cdnjs`, `unpkg`, `jsdelivr`, Google Fonts). All CSS, JavaScript, and icons must remain inline or embedded.
2. **Zero Direct Client Access to S3**:
   - Never generate or return presigned S3 URLs to clients.
   - All object downloads and uploads must be reverse-proxied through `s3web` to enforce in-app prefix-scoped RBAC and per-item access logging.
3. **Dual-Hashing in a Single Pass**:
   - Streaming uploads must compute linear `SHA-256` and `SHA-1` concurrently during upload using [`internal/hashstream`](internal/hashstream/). Avoid buffering multi-GB objects into memory or disk before hashing.
4. **Zero Static AWS Credentials**:
   - Do not pass static AWS access keys or secrets to the container. In AWS ECS Fargate, authentication must use the ECS Task IAM Role (`AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`).
5. **Decoupled In-App RBAC**:
   - All permissions (`READ`, `UPLOAD`, `DELETE`, `ADMIN`) are managed within the application and persisted in the metadata store (DynamoDB / local store), not mapped to AWS IAM roles.
6. **Authentication Methods**:
   - Web UI: OIDC SSO (Google Workspace, Okta, Keycloak) or Local User Accounts (PBKDF2-HMAC-SHA256 salted hashes).
   - `/raw/` HTML Raw Access: Bearer tokens (`Authorization: Bearer <id>:s3w_<token>`) or HTTP Basic Auth.
7. **Strict Anonymity Rule**:
   - Anonymous access is strictly prohibited across all endpoints (both `/api/v1/*` and `/raw/*`).

---

## 5. Coding & Repository Rules

- **Terminology Constraint**: Never mention or include proprietary third-party company or vendor product names anywhere in the repository, commit messages, or documentation.
- **Go Conventions**:
  - Keep standard library dependencies minimal.
  - Preserve clear separation of concerns across packages:
    - [`internal/auth`](internal/auth/): Passwords, JWT, OIDC tokens, session cookies, service accounts.
    - [`internal/rbac`](internal/rbac/): Permission evaluation and access grants.
    - [`internal/server`](internal/server/): HTTP router, handlers, reverse proxy, `/raw/` HTML autoindex.
    - [`internal/storage`](internal/storage/): Object storage interface (`PutStream`, `GetStream`, `Delete`, `Restore`).
    - [`internal/store`](internal/store/): Metadata, users, grants, logs, and settings persistence.
- **Preserve Documentation & Comments**: Do not delete existing comments or docstrings unless directly superseded by updated logic.
