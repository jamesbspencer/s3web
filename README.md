# `s3web` — Private S3 Artifact Browser & Sonatype Nexus Proxy (Go)

`s3web` is a single-binary Go web interface and HTTP artifact proxy for Amazon S3 buckets storing ISOs and compressed archives. See [DESIGN.md](DESIGN.md) for the complete system architecture.

## Key Capabilities
- **Private-Only VPC (VPN Access Only)**: Zero external CDN dependencies (`//go:embed` static UI), designed for private subnets behind an Internal ALB with S3 & DynamoDB VPC Gateway Endpoints.
- **In-App Upload & Delete Permission Management**: All users default to **Read-Only**. Administrators manage **Upload**, **Delete**, and **Admin** Access Grants and **App-Managed Groups** directly in the UI.
- **Multi-Auth Support**:
  - **Human SSO**: OIDC / Session cookies with group and user-level in-app grants.
  - **GitHub Actions Workflows**: Secretless OIDC JWT authentication (`Authorization: Bearer <GH_JWT>`) matched against repository/branch/environment claim patterns.
  - **Service Accounts**: HTTP Basic Auth & Bearer tokens for **Sonatype Nexus Raw Proxy** repositories.
- **Sonatype Nexus Raw Proxy (`/raw/*`)**: Supports `GET`, `HEAD`, `Range` requests, `ETag`, `X-Checksum-Sha256`, `X-Checksum-Sha1`, Apache/Nginx-style HTML `autoindex` directory listings, and virtual `.sha256` / `.sha1` sidecar files.
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
