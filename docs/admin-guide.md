# s3web Administrator Guide

This guide covers operational administration, access governance, security policies, storage settings, and audit monitoring for `s3web`.

For end-user instructions, refer to the [User Guide](user-guide.md). For deployment and infrastructure setup, refer to the [Installation Guide](installation.md).

---

## 1. Overview of Administrative Capabilities

`s3web` implements a decoupled, in-app role-based access control (RBAC) engine that operates independently of underlying cloud provider IAM policies. All administrative features are accessible through the web UI under the **Admin** panel (visible exclusively to principals with `ADMIN` privileges) and via programmatic endpoints detailed in the embedded [Swagger API Explorer](/swagger/) (`/swagger/`).

Key administrative responsibilities include:

- Managing local user accounts, passwords, and account statuses.
- Granting prefix-scoped permissions (`READ`, `UPLOAD`, `DELETE`, `ADMIN`).
- Organizing users into app-managed groups and mapping OIDC SSO groups.
- Provisioning service accounts and secure automation tokens (`<id>:s3w_<token>`).
- Authorizing CI/CD workload OIDC JWT issuers.
- Configuring repository branding, default tree expansion, anonymous access, and archive restore defaults.
- Setting up Slack incoming webhook notifications and testing connectivity.
- Reviewing global audit and data-plane access logs.

---

## 2. Accessing the Admin Console

1. Sign in as a user with the `ADMIN` role (such as the initial bootstrap `admin` account).
2. Click the **Admin** button in the top navigation bar.
3. The Admin modal provides tabbed navigation:
   - **Local Users**: User account creation, password resets, and account disabling.
   - **Access Grants**: Path-prefix permission rules for users, groups, and service accounts.
   - **App-Managed Groups**: Group definitions and membership management.
   - **Service Accounts**: Non-human identities for automation and `/raw/` HTML access.
   - **CI OIDC Issuers**: Workload identity federation for automated build pipelines.
   - **Repositories / Roots**: Bucket roots, display names, and storage path mappings.
   - **Settings**: System policies, anonymous access toggle, Slack webhooks, and restore defaults.
   - **All Logs**: Centralized real-time audit and access log viewer.

---

## 3. Local User Account Management

`s3web` provides full lifecycle management for built-in local user accounts. Passwords are encrypted using PBKDF2-HMAC-SHA256 with cryptographically random per-user salts.

### Creating a Local User Account

1. Open **Admin** &rarr; **Local Users**.
2. Click **Add Local User**.
3. Specify:
   - **Username**: Unique alphanumeric identifier (e.g., `jsmith`).
   - **Display Name**: Friendly full name (e.g., `Jane Smith`).
   - **Email**: Notification email address.
   - **Password**: Initial account password.
4. Click **Create User**.

### Resetting Passwords

Administrators can override and set a new password for any local account:

1. Locate the user in the **Local Users** table.
2. Click **Reset Password**.
3. Enter the new temporary or permanent password and confirm.

> [!NOTE]
> Users can also change their own passwords at any time from the top-right user menu &rarr; **Change Password**.

### Disabling Accounts & Emergency Kill-Switch

- **Individual Account**: Click **Disable** next to any user row. Disabled accounts are rejected during login with `401 Unauthorized` and any existing sessions are invalidated.
- **Bulk Disable All Local Users**: In enterprise environments where identity is migrated to OIDC SSO, click **Disable All Local Accounts**. This immediately disables all local accounts except the active administrator session, preventing any local password logins.

---

## 4. Prefix-Scoped Access Grants (In-App RBAC)

All users default to **no access** or **read-only** depending on configuration. Explicit access rights are granted using **Access Grants**.

### Permissions Matrix

- `READ`: Allows browsing directories, viewing file metadata, calculating checksums, downloading files, and initiating S3 Intelligent-Tiering restores.
- `UPLOAD`: Allows uploading new objects, subject to repository-level and grant-level file extension whitelists. Dual-hashing (`SHA-256` and `SHA-1`) is computed automatically in a single streaming pass.
- `DELETE`: Allows permanently deleting objects and folders from the S3 bucket.
- `ADMIN`: Full administrative control over users, grants, settings, and logs.

### Grant Scoping

Access Grants can be bound to:

1. **User**: A specific local or SSO username (e.g., `user:jsmith`).
2. **Group**: An app-managed group or OIDC SSO directory group (e.g., `group:devops`).
3. **Service Account**: An automated bot or CI/CD account (e.g., `service:svc-raw-access`).

### Prefix Paths & Extension Restrictions

- **Path Prefix**: Restricts the grant to a specific subfolder (e.g., `isos/linux/` or `backups/db/`). To grant access across the entire repository, use `/` or `*`.
- **Allowed Extensions**: Restricts uploads for this grant to specific extensions (e.g., `.iso,.img`). Leave blank or set to `*` to inherit repository defaults.

---

## 5. App-Managed Groups & OIDC SSO Mappings

Groups allow assigning permissions to multiple users simultaneously:

1. Navigate to **Admin** &rarr; **App-Managed Groups**.
2. Click **Create Group** and provide a name and description (e.g., `release-engineers`).
3. Click **Members** to add or remove local usernames.
4. When OIDC SSO is enabled, external directory groups sent in the `groups` token claim can be referenced directly in **Access Grants** using the syntax `group:<oidc-group-name>`.

---

## 6. Service Accounts & Automation Tokens

Service accounts are designed for headless systems, shell scripts, curl/wget downloads, and CI/CD pipelines accessing the `/raw/` HTML directory index.

### Provisioning a Service Account

1. Open **Admin** &rarr; **Service Accounts**.
2. Click **Create Service Account**.
3. Specify an Account ID (e.g., `build-server-01`) and description.
4. Click **Generate Token**.
5. Copy the generated secret key. The full Bearer token format is:

   ```
   <account-id>:s3w_<random-secret>
   ```

   *(e.g., `build-server-01:s3w_9a8b7c6d5e4f3a2b1c...`)*

> [!WARNING]
> The full token secret is only displayed once upon creation. Store it in your secrets manager or automation credentials vault.

### Using Service Accounts

Service accounts authenticate via HTTP Authorization headers:

```bash
# Bearer token authentication
curl -H "Authorization: Bearer build-server-01:s3w_secret..." \
     http://s3web.internal.example.com/raw/isos/rocky-linux.iso -O

# HTTP Basic Authentication (ID as username, token secret as password)
curl -u "build-server-01:s3w_secret..." \
     http://s3web.internal.example.com/raw/isos/rocky-linux.iso -O
```

---

## 7. CI/CD Workload OIDC JWT Issuers

For passwordless CI/CD automation, `s3web` supports federated OIDC token validation:

1. Open **Admin** &rarr; **CI OIDC Issuers**.
2. Click **Add Issuer**.
3. Configure:
   - **Issuer URL**: The discovery endpoint of your CI provider (e.g., `https://token.actions.githubusercontent.com`).
   - **Audience**: Expected JWT audience (`aud` claim).
   - **Subject / Claims Pattern**: Regexp or glob matching repository, branch, or workflow claims (e.g., `repo:org/infra:ref:refs/heads/main`).
   - **Role / Permissions**: Assigned permissions for matching workloads.

---

## 8. Global Settings & Security Policies

Navigate to **Admin** &rarr; **Settings** to configure global server parameters:

| Setting | Default | Description |
| :--- | :--- | :--- |
| **Repository Title** | `s3web archive` | Branding title displayed in the Web UI header and HTML `/raw/` autoindex titles. |
| **Default Tree State** | `collapsed` | Whether the object hierarchy tree defaults to `collapsed` or `expanded`. |
| **Anonymous Access** | `Disabled` | When disabled, all requests to `/api/v1/*` and `/raw/*` require valid credentials. When enabled, unauthenticated read access is permitted. |
| **HTML Autoindex** | `Enabled` | Enables Apache/Nginx-style directory listing at `/raw/`. |
| **Virtual Checksums** | `Enabled` | Synthesizes `.sha256` and `.sha1` sidecar files in `/raw/` derived from object metadata. |
| **Allowed Extensions** | `.iso,.img,.tar.gz,.tgz,.zip,.qcow2,.raw` | Repository-wide upload whitelist. Set to `*` to allow any extension. |
| **S3 Restore Days** | `7` | Default lifetime (in days) for temporary copies restored from Archive (`AA`) or Deep Archive (`DAA`). |
| **S3 Restore Tier** | `Standard` | Default retrieval speed (`Bulk`, `Standard`, `Expedited`) for Intelligent-Tiering restores. |

---

## 9. Slack Webhook Notifications & Restore Alerts

`s3web` supports automated team notifications and individual restore completion alerts via incoming Slack webhooks.

### Configuring Slack Integration

1. In your Slack workspace, create an Incoming Webhook app or custom integration.
2. Copy the Webhook URL.
3. Open **Admin** &rarr; **Settings**.
4. Paste the URL into **Slack Webhook URL**.
5. Optionally specify a **Default Slack Channel** (e.g., `#s3web-alerts`).
6. Click **Test Slack Connection** to verify end-to-end message delivery. A notification will appear in Slack confirming the integration.
7. Click **Save Settings**.

### How Restore Alerts Work

When a user initiates an S3 Intelligent-Tiering restore from Archive Access (`AA`) or Deep Archive Access (`DAA`), they can opt in to receive a Slack notification when the file is ready for download:

- The system tags the restore event with the user's configured Slack handle (set in **User Menu** &rarr; **Profile**).
- When the background tier-transition monitor detects that AWS S3 has completed the retrieval, a formatted alert is posted to Slack with the file name, size, restore duration, and a direct download link.

---

## 10. Audit & Access Logging (`/api/v1/admin/logs`)

The **All Logs** tab in the Admin console provides centralized visibility across all data-plane operations and administrative actions:

### Event Types Logged

- `login`: Successful user authentication events.
- `logout`: Explicit user session termination.
- `download`: File download events with byte counts and HTTP status codes.
- `upload`: File uploads, including computed `SHA-256` and `SHA-1` hashes.
- `delete`: Object deletion operations.
- `restore_init`: Intelligent-Tiering archive retrieval requests.
- `restore_complete`: Notification when an archived object becomes available.
- `admin_action`: Modifications to users, grants, groups, or settings.

### Filtering & Search

Administrators can filter logs by:

- **Principal**: Local username, SSO email, or service account ID.
- **Action**: Event type (`login`, `download`, `upload`, `delete`, etc.).
- **Prefix / Path**: S3 object key or folder path.
- **Time Window**: Relative ranges (last 1 hour, 24 hours, 7 days, 30 days) or custom ISO-8601 timestamps.

---

## 11. Programmatic Administration & Swagger UI

All administrative capabilities can be automated using the REST API:

- **Interactive Swagger UI**: Navigate to `http://<your-s3web-host>/swagger/` in any browser.
- **Raw OpenAPI 3.0 Specification**: Available at `/api/v1/openapi.json` or `/api/v1/swagger.json`.

For automated scripting, authenticate using an administrative service account token or admin session cookie:

```bash
# Query recent audit logs via API
curl -s -H "Authorization: Bearer admin-bot:s3w_secret..." \
     "http://localhost:8080/api/v1/admin/logs?limit=50&action=upload" | jq .
```
