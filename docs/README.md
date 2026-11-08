# `s3web` Documentation

Comprehensive documentation covering architecture, operations, user workflows, administration, and deployment for `s3web`.

## Guides
- [User Guide](user-guide.md): Complete guide for end-users covering authentication, browsing large file archives, S3 Intelligent-Tiering filters, global search, checksum verification, downloads, S3 restore with Slack completion alerts, user profile management, and HTML Raw Access (`/raw/`).
- [Administrator Guide](admin-guide.md): Operational guide for administrators detailing in-app RBAC, local user lifecycle management, prefix-scoped access grants, app-managed groups, service account automation tokens, CI/CD workload OIDC issuers, global settings, Slack incoming webhook configuration, and centralized audit/access log monitoring.
- [Installation & Deployment Guide](installation.md): Step-by-step instructions for building standalone single binaries, running on bare-metal Linux VMs with systemd, Docker container deployment, AWS ECS Fargate Private VPC infrastructure with Terraform, and the environment variables reference.
- [S3 Authentication & Data-Plane Security](s3-authentication.md): In-depth security architecture detailing AWS ECS Task IAM roles, S3 Gateway VPC Endpoints, and decoupled application-level RBAC.

## Architecture & Specifications
- [System Architecture Specification (`DESIGN.md`)](../DESIGN.md): Architectural specification, DynamoDB data model, API endpoints, and component designs.
- [AI Agent Guidelines (`AGENTS.md`)](../AGENTS.md): Operational guidelines, security invariants, build/test commands, and conventions for AI coding agents.

## API Documentation
- **Interactive Swagger UI source**: [`internal/ui/static/swagger/index.html`](../internal/ui/static/swagger/index.html). In a running application, access the UI at `/swagger/` (zero external CDN dependencies, fully offline-capable).
- **OpenAPI 3.0 Specification**: [`internal/ui/static/swagger/openapi.json`](../internal/ui/static/swagger/openapi.json). In a running application, it is available at `/api/v1/openapi.json` and `/api/v1/swagger.json`.
