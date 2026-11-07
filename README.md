# `s3web` — Private S3 Artifact Browser & HTML Raw Access (Go)

`s3web` is a single-binary Go web interface and HTML Raw Access server for Amazon S3 buckets storing ISOs and compressed archives. See [DESIGN.md](DESIGN.md) for the complete system architecture.

## Key Capabilities
- **Private-Only VPC (VPN Access Only)**: Zero external CDN dependencies (`//go:embed` static UI), designed for private subnets behind an Internal ALB with S3 & DynamoDB VPC Gateway Endpoints.
- **Zero Anonymous Access**: Anonymous access is strictly disabled across both the Web UI (`/api/v1/*`) and HTML Raw Access (`/raw/*`).
- **Local User Accounts & Lifecycle Management**:
  - On initial install, `s3web` automatically seeds a default `admin` account with a cryptographically random generated password and a `demo` local user account (writing initial credentials to `<S3WEB_LOCAL_DATA_DIR>/bootstrap-credentials.txt` or AWS Secrets Manager via Terraform).
  - Local accounts can update their own passwords (`POST /api/v1/auth/password`).
  - Administrators can reset the password of any local account (`PUT /api/v1/admin/local-users/{username}/password`) and disable individual or all local accounts (`PUT /api/v1/admin/local-users/{username}/status`, `POST /api/v1/admin/local-users/disable-all`).
- **In-App Upload & Delete Permission Management**: All users default to **Read-Only**. Administrators manage **Upload**, **Delete**, and **Admin** Access Grants and **App-Managed Groups** directly in the UI.
- **Multi-Auth Support**:
  - **Local Accounts**: Built-in local users (`admin`, `demo`, and custom local accounts) with PBKDF2-SHA256 salted password hashes.
  - **Human SSO**: Multiple configurable OIDC SSO providers with group and user-level in-app grants.
  - **CI OIDC JWT Issuers**: Multiple configurable OIDC JWT issuers (`Authorization: Bearer <JWT>`) matched against repository/branch/environment claim patterns.
  - **Service Accounts**: HTTP Basic Auth & Bearer tokens for automated HTML Raw Access and CLI scripts.
- **HTML Raw Access (`/raw/*`)**: Uses the exact same access control as the default UI and supports `GET`, `HEAD`, `Range` requests, `ETag`, `X-Checksum-Sha256`, `X-Checksum-Sha1`, Apache/Nginx-style HTML `autoindex` directory listings, and virtual `.sha256` / `.sha1` sidecar files.
- **Streaming Linear Dual-Hashing (`SHA-256` + `SHA-1`)**: Computes full-file linear `SHA-256` and `SHA-1` in a single streaming pass during upload (`internal/hashstream`).
- **S3 Intelligent-Tiering Visibility**: Displays each object's current Intelligent-Tiering sub-tier (`FA`, `IA`, `AIA`, `AA`, `DAA`) and supports one-click archive restoration (`RestoreObject`).
- **Per-Item Access Logs**: Real-time per-object access log drawer showing downloads, uploads, restores, and deletes with principal attribution.

## Quick Start

### Run with Go
```bash
go run ./cmd/s3web
# Open http://localhost:8080
```

### Run Tests
```bash
go test -v ./...
```

### Build Container Image
```bash
docker build -t s3web:latest .
docker run --rm -p 8080:8080 s3web:latest
```
