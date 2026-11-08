# s3web — User Guide

Welcome to **s3web**, the high-performance large file archive frontend and private repository for Amazon S3 with AWS S3 Intelligent-Tiering.

This guide explains how to navigate the repository, search for files, stream downloads, verify linear cryptographic checksums, trigger archive restores from Glacier tiers, and configure Slack notifications.

---

## 1. Getting Started & Signing In

`s3web` enforces strict authentication across all interfaces. Anonymous access is disabled by default unless explicitly enabled by an administrator.

### Signing In
1. Navigate to the `s3web` Web UI in your browser (e.g. `http://localhost:8080` or your internal VPN hostname).
2. If unauthenticated, the **Sign In** dialog will appear.
3. Sign in using:
   - **Local User Account**: Enter your assigned username (e.g. `demo` or your personal local user) and password.
   - **Corporate Single Sign-On (SSO)**: If your organization uses OIDC SSO, select your identity provider and complete authentication.
4. Once signed in, your **Display Name** or **Username** appears in the top-right corner with a drop-down menu.

---

## 2. Navigating Artifacts & S3 Tree Browser

The **Artifact Browser** presents an interactive directory tree of all configured S3 buckets and folder prefixes.

### Folder Hierarchy & Actions
- **Expanding & Collapsing Folders**: Click the folder chevron or folder row to toggle contents. Use **Expand All** or **Collapse All** in the toolbar to adjust all folders at once.
- **Breadcrumb Navigation**: The top breadcrumb bar tracks your current position. Click **All Buckets** or any parent folder in the crumb trail to jump up the hierarchy.
- **Folder Artifact Count & Total Size**: Each folder displays the cumulative number of artifacts and total aggregated byte size.

### Filtering by S3 Intelligent-Tiering Sub-Tier
AWS S3 Intelligent-Tiering monitors access patterns and automatically transitions large objects between access tiers:
- **FA (Frequent Access)**: Low latency, active artifacts.
- **IA (Infrequent Access)**: Objects untouched for 30+ consecutive days.
- **AIA (Archive Instant Access)**: Objects untouched for 90+ consecutive days; immediate millisecond retrieval.
- **AA (Archive Access)**: Objects untouched for 90–180+ days; asynchronous Glacier tier requiring restoration before download.
- **DAA (Deep Archive Access)**: Objects untouched for 180+ days; asynchronous retrieval requiring restoration.

Use the **Intelligent-Tiering Filter** dropdown in the toolbar to filter artifacts by their tier (e.g. filter to `Archive Access (AA)` to inspect items requiring restoration).

---

## 3. Searching Artifacts

The search bar at the top of the interface provides instant search across the entire repository:
1. **Filename Search**: Type any substring of a file name (e.g. `debian-12`, `kernel-6.1`, `.iso`).
2. **Prefix Search**: Search by folder or path (e.g. `isos/linux`).
3. **Checksum Hex Digest**: Paste a full 64-character `SHA-256` or 40-character `SHA-1` hex digest to look up the exact corresponding artifact.
4. **Keyboard Shortcut**: Press <kbd>/</kbd> anywhere in the browser to immediately focus the search input. Press <kbd>Enter</kbd> to search or click **Reset** to clear.

---

## 4. Downloading Artifacts & Verifying Checksums

All downloads are reverse-proxied through `s3web` to ensure strict prefix-scoped RBAC and per-item access auditing.

### Downloading Files
- If an artifact is in a synchronous millisecond tier (**FA**, **IA**, or **AIA**), click the blue **Download** button in the artifact row or inside the metadata drawer.
- Downloads support HTTP Range requests for resuming interrupted transfers or multi-part downloads.

### Linear Cryptographic Checksums
During upload, `s3web` computes full-file linear `SHA-256` and `SHA-1` concurrently in a single streaming pass without buffering to disk.
- **Copy Checksums**: Click the **SHA-256** button in any row to copy the verified hash directly to your clipboard.
- **Virtual Sidecars**: Append `.sha256` or `.sha1` to any artifact path under `/raw/` (e.g. `/raw/isos/debian-12.iso.sha256`) to retrieve standard GNU `coreutils` formatted checksum sidecars.
- **Verifying Downloads Locally**:
  ```bash
  # Download file and sidecar
  curl -O http://<s3web-host>/raw/isos/debian.iso
  curl -O http://<s3web-host>/raw/isos/debian.iso.sha256

  # Verify integrity
  sha256sum -c debian.iso.sha256
  # Output: debian.iso: OK
  ```

---

## 5. S3 Archive Restoration & Slack Alerts

When an artifact transitions to an asynchronous archive tier (**AA** or **DAA**), direct download is disabled until a temporary retrieval copy is restored to Frequent Access.

### Restoring an Archived Artifact
1. Click **Restore** on the artifact row or inside the slide-over details drawer.
2. The **Restore from Archive** modal appears, displaying:
   - Target artifact name and key
   - Current archive tier (**Archive Access** or **Deep Archive Access**)
   - File size and retrieval duration guidance
3. **Slack Notification Option**:
   - Check `[x] Send me a Slack message when restore is complete`.
   - The modal automatically pre-fills your Slack Member ID or handle from your profile. You may also specify an alternate handle or channel mention.
4. Click **Initiate Restore**.
5. Once initiated, S3 hydrates a temporary copy back to **Frequent Access (FA)**. If Slack notifications are enabled, a Slack webhook alert will be sent with direct download links when the restore is ready.

---

## 6. HTML Raw Access (`/raw/`)

For automated CLI pipelines, server provisioning scripts, and PXE boot environments, `s3web` provides an Apache/Nginx-style `/raw/` autoindex.

### Using `/raw/` in Scripts
```bash
# Using HTTP Basic Authentication (Local Account or Service Account)
curl -u "demo:password" http://<s3web-host>/raw/isos/linux/

# Using Bearer Token (Service Account)
curl -H "Authorization: Bearer <account-id>:s3w_<token>" \
     http://<s3web-host>/raw/isos/linux/debian-12.iso -o debian-12.iso
```

---

## 7. Profile Management & Slack Handle

Click your name in the top-right corner and select **Profile & Notifications**:
- **Display Name**: Set your friendly name (e.g. `Jane Doe`). This name appears in the top navigation bar and restore notices. Leave empty to use your username.
- **Email Address**: View or update your email address.
- **Slack Member ID or Link**: Enter your Slack Member ID (e.g. `U01234567`) or handle (`@jdoe`). Used by the archive restoration system to notify you when warm copies are available.
- **Change Password**: Local account users can self-service update their password by clicking **Change Password** in the account menu.

---

## 8. Interactive Swagger API Documentation

For API integration, automation scripts, and SDK development, `s3web` bundles an interactive Swagger UI:
- Open the user menu in the top-right and select **Swagger API Docs**, or navigate directly to `/swagger/`.
- The interactive explorer allows you to authenticate, inspect all endpoints, view schemas, and run live requests against the repository.

