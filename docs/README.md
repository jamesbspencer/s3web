# `s3web` Documentation

Comprehensive documentation covering architecture, operations, user workflows, administration, and deployment for `s3web`:

## Guides
- [User Guide](file:///Users/jspencer/projects/s3web/docs/user-guide.md): Complete guide for end-users covering authentication, browsing large file archives, S3 Intelligent-Tiering filters, global search, checksum verification, downloads, S3 restore with Slack completion alerts, user profile management, and HTML Raw Access (`/raw/`).
- [Administrator Guide](file:///Users/jspencer/projects/s3web/docs/admin-guide.md): Operational guide for administrators detailing in-app RBAC, local user lifecycle management, prefix-scoped access grants, app-managed groups, service account automation tokens, CI/CD workload OIDC issuers, global settings, Slack incoming webhook configuration, and centralized audit/access log monitoring.
- [Installation & Deployment Guide](file:///Users/jspencer/projects/s3web/docs/installation.md): Step-by-step instructions for building standalone single binaries, running on bare-metal Linux VMs with systemd, Docker container deployment, AWS ECS Fargate Private VPC infrastructure with Terraform, and a complete environment variables reference.
- [S3 Authentication & Data-Plane Security](file:///Users/jspencer/projects/s3web/docs/s3-authentication.md): In-depth security architecture detailing AWS ECS Task IAM roles, S3 Gateway VPC Endpoints, and decoupled application-level RBAC.

## Architecture & Specifications
- [System Architecture Specification (`DESIGN.md`)](file:///Users/jspencer/projects/s3web/DESIGN.md): Architectural specification, DynamoDB data model, API endpoints, and component designs.
- [AI Agent Guidelines (`AGENTS.md`)](file:///Users/jspencer/projects/s3web/AGENTS.md): Operational guidelines, security invariants, build/test commands, and conventions for AI coding agents.

## API Documentation
- **Interactive Swagger UI**: Hosted directly inside the application at `/swagger/` (zero external CDN dependencies, fully offline-capable).
- **OpenAPI 3.0 Specification**: Accessible programmatically at `/api/v1/openapi.json` and `/api/v1/swagger.json`.
