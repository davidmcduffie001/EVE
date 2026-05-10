# Project Specification — EVE (Exploit Validation Engine)

---

**Version:** 0.6 (Draft)
**Status:** In Progress
**Classification:** Internal — Development Use Only

---

## § 1 — Project Overview

EVE (Exploit Validation Engine) is a professional, on-premises security platform designed for security practitioners. It aggregates vulnerability findings from multiple industry-standard security scanning tools, enriches those findings with publicly available exploit intelligence, and presents suggested exploits to the user within the web interface. Users can review exploit suggestions with their associated metadata and click through to the source in a browser.

EVE ships in two editions: a free **Community Edition (CE)** with core functionality, and a licensed **Enterprise Edition** with the full feature set. A valid license key imported through the Settings panel upgrades an installation to Enterprise mode.

This document is the authoritative specification for all design, architecture, and implementation decisions. All features, components, and behaviors described herein must be implemented in accordance with industry best practices for secure software development (OWASP Top 10, NIST SP 800-53) unless explicitly stated otherwise.

This specification is structured around two development phases:

- **Phase 1** covers the initial release: scanner integration, exploit intelligence aggregation, and the web UI. No exploit execution capability is included.
- **Phase 2** covers the exploit execution engine: ephemeral containerized execution, gVisor sandboxing, credential injection, and all associated safety and legal controls. Phase 2 content is documented in this spec for design continuity but must not be built during Phase 1 development.

---

## § 2 — Edition Tiers

### § 2.1 — Feature Comparison

| Feature | Community Edition (CE) | Enterprise Edition |
|---|---|---|
| Scanner integrations | **1 maximum** | Unlimited |
| Vulnerability enrichment sources | Built-in sources only (NVD) | All sources |
| Exploit intelligence sources | Built-in metadata sources only (SearchSploit metadata index) | All sources |
| Authentication | Local accounts only | Local accounts + SSO (SAML 2.0 / OIDC) |
| MFA | User-configurable; admin can enforce or disable platform-wide | User-configurable; admin can enforce or disable platform-wide |
| Target hosts | **16 maximum** | Unlimited |
| Report export formats | CSV and JSON only | CSV, JSON, and PDF |
| API key access | Not available (UI only) | Full API key management |
| Custom roles | Not available (built-in roles only) | Fully supported |
| Webhook / email notifications | Not available (in-app only) | Supported |
| *[Phase 2] Concurrent execution jobs* | *3 maximum* | *25 maximum* |
| *[Phase 2] Execution jobs per month* | *100 maximum* | *Unlimited* |
| *[Phase 2] Stored credential sets* | *5 maximum* | *Unlimited* |
| License required | No | Yes |

### § 2.2 — License Enforcement

- On startup, EVE checks for the presence of a valid license file. If none is found or the license is expired or invalid, the installation operates in CE mode with all CE limitations enforced.
- A valid license is imported via the Settings panel by an administrator. The license is validated against a cryptographic signature issued by the developer; tampered or forged licenses must be rejected.
- Phase 1 uses fully offline signed license files. The preferred signature scheme is Ed25519. The application stores only the public verification key; private signing keys are held outside the deployed product.
- License enforcement is applied at the API layer — CE limits cannot be bypassed by direct UI manipulation or API calls.
- On license import, the edition change takes effect immediately without requiring a restart.
- CE limits must be surfaced clearly in the UI in two ways. First, when a user *attempts* an action that exceeds a CE limit (e.g. adding a second scanner), they receive a blocking prompt explaining the limit and how to upgrade. Second, Enterprise-only features that are visible but unavailable in CE (e.g. the custom roles panel, SSO configuration, PDF export, webhook notifications) must display a non-intrusive inline upgrade nudge — a small badge or tooltip adjacent to the locked control — so CE users understand the feature exists and what tier unlocks it. Locked controls may be rendered in a visually subdued state but must remain visible; they must not be hidden entirely.
- The license file may encode expiry date, installation identifier (to prevent license sharing across installations), and entitled feature flags.
- CE scanner and target limits count active, non-archived records only. Disabled scanner integrations do not count toward the CE scanner limit. Archived targets do not count toward the CE target limit, but restoring an archived target must be blocked if it would exceed the active CE target limit.

---

## § 3 — Users & Roles

**Primary users:** Security teams, penetration testers, and vulnerability management professionals.

**Deployment model:** Single-tenant, on-premises installation. Each installation serves one organization.

### § 3.1 — Built-in Roles

| Role | Description | Key Capabilities |
|---|---|---|
| `Admin` | Installation administrator | Full configuration, user management, role management, scanner credential management, scope definition, license management |
| `Analyst` | Security practitioner | View findings, view exploit intelligence, initiate exploit lookups |
| `Read-Only` | Stakeholder / auditor | View findings and exploit intelligence; no write actions |

### § 3.2 — Custom Roles (Enterprise Only)

Administrators may create, edit, and delete custom roles with granular permission assignments drawn from the full permission registry. Built-in system roles cannot be deleted.

The permission registry covers at minimum:

`findings:read`, `findings:export`, `targets:manage`, `intel:manage`, `users:manage`, `roles:manage`, `audit:read`, `reports:export`, `scanners:manage`

*Phase 2 additions:* `executions:create`, `executions:approve`, `credentials:manage`

---

## § 4 — Functional Requirements

### § 4.1 — Phase 1: Scanner Integration

- FR-01: The platform must ingest vulnerability findings from supported scanners (§ 8) via modular, independently implemented connectors. The Phase 1 MVP must implement the Nessus / Tenable.sc connector first. Additional scanner connectors remain in Phase 1 scope only after the connector framework, normalization pipeline, and Nessus connector are complete and tested.
- FR-02: Each connector must implement a standard interface: `authenticate()`, `fetch_scans()`, `fetch_findings()`, `normalize()`, `sync()`.
- FR-03: All findings must be normalized into the platform's canonical data model (§ 9) upon ingestion.
- FR-04: Connectors must support both on-demand pulls and scheduled/automated syncing.
- FR-05: Scanner credentials are entered when configuring a scanner integration and stored encrypted at rest. They are never logged or exposed via the API.
- FR-06: Connector failures must be handled gracefully with structured error reporting and retry logic with exponential backoff.
- FR-07: CE installations are limited to one active scanner integration at a time. Attempting to add a second is rejected with a clear upgrade prompt.

### § 4.2 — Phase 1: Exploit Intelligence

- FR-08: For each confirmed finding with a CVE identifier, the platform must automatically query all active vulnerability enrichment and exploit intelligence sources (§ 8.2). The built-in immutable NVD enrichment source and SearchSploit metadata index are always queried on all editions.
- FR-09: Exploit lookup metadata must be cached in Redis with a configurable TTL.
- FR-10: The following exploit metadata must be stored and linked to the associated finding(s): source URL and provider, title/author/disclosure date, exploit type and reliability rating, CVE identifiers, and affected platform metadata.
- FR-11: CE installations have access only to the built-in immutable NVD enrichment source and SearchSploit metadata index. All other enrichment and intelligence sources are Enterprise-only.
- FR-12: Exploit suggestions are presented in the web UI with metadata and a link to the original source. Clicking a source link opens it in a new browser tab. No exploit code is fetched, bundled, indexed, stored, or executed in Phase 1.

### § 4.3 — Phase 1: Reporting & Export

- FR-13: All installations support report export in CSV and JSON formats.
- FR-14: PDF report export is available in Enterprise only.
- FR-15: Audit logs must be exportable in JSON, CEF, and syslog formats for SIEM integration (all editions).

### § 4.4 — Phase 1: Data Retention

- FR-16: Automated nightly purge jobs must enforce configured retention windows (§ 14).
- FR-17: Purge jobs must emit structured audit records including data type, retention rule, affected record counts, actor (`system` for scheduled jobs), start time, completion time, and outcome.
- FR-18: Administrators may request an on-demand data export at any time.

### § 4.5 — Phase 2: Exploit Execution (Deferred)

The following requirements are defined here for design continuity but must not be implemented during Phase 1. No scaffolding, stub code, data model entities, or API endpoints for execution should be created in Phase 1.

- FR-E1: Each execution job must run in a freshly provisioned, ephemeral container — never a shared or reused environment.
- FR-E2: All execution containers must be sandboxed using gVisor (`runsc`). This is mandatory and non-negotiable.
- FR-E3: Exploit execution must require explicit user authorization per job.
- FR-E4: The system must validate that the target is within the installation's authorized asset scope before initiating any execution job. Out-of-scope targets must be rejected at the API layer.
- FR-E5: Containers must be automatically destroyed after execution completes or after a configurable timeout (default: 5 minutes).
- FR-E6: Execution results must be written to `ExecutionResult` and surfaced in the UI.
- FR-E7: Users must re-acknowledge the AUP before initiating any exploit execution job. This acknowledgment must be logged as a discrete, tamper-evident audit record.
- FR-E8: Exploit code must never be stored persistently anywhere in the EVE environment. Its lifecycle is strictly bounded to the duration of an execution job.
- FR-E9: CE installations are limited to 3 concurrent execution jobs and 100 execution jobs per calendar month.

---

## § 5 — Non-Functional Requirements

- **Security:** OWASP Top 10 and NIST SP 800-53 compliance required throughout. Where MFA is enabled, privileged actions should prompt for step-up MFA re-authentication.
- **Encryption in transit:** TLS 1.2+ required; TLS 1.3 preferred.
- **Encryption at rest:** AES-256 minimum.
- **Authentication:** Local account authentication for all editions. SSO (SAML 2.0 / OIDC) for Enterprise only. MFA is user-configurable on both editions; each user may independently enrol or unenrol. Administrators may override this with a platform-wide enforce policy (requires MFA for all users) or a platform-wide disable policy (prevents users from enabling MFA); admin policy takes precedence over user preference.
- **Session management:** JWT-based tokens with ≤1 hour expiry; refresh token rotation enforced.
- **Performance:** Server-side pagination for large datasets; virtual scrolling for in-page lists exceeding ~200 rows.
- **Accessibility:** WCAG 2.1 AA color contrast compliance required for both light and dark themes.
- **Browser support:** Fully functional at 1280px+ desktop resolutions; graceful degradation to tablet. Mobile is not a requirement for initial release.
- **Test coverage:** Minimum 80% coverage target for backend logic. Unit, integration, and E2E tests required for all core features.
- **Input validation:** All user-supplied input validated and sanitized server-side. Client-side validation is supplementary only.
- **Injection prevention:** Parameterized queries and ORM-enforced queries exclusively — no raw SQL string construction.
- **API security:** All endpoints require authentication except `/health` and auth endpoints. API responses must never leak internal stack traces, database errors, or system paths.

---

## § 6 — Technical Architecture

### § 6.1 — Tech Stack

| Layer | Technology | Notes |
|---|---|---|
| Backend | Python 3.14+ / FastAPI | Async-native; Pydantic for validation; auto-generated OpenAPI docs |
| Frontend | React (TypeScript) | TanStack Table, Recharts, shadcn/ui or Mantine for components |
| Task Queue | Celery + Redis | Background jobs for scan sync and exploit lookup |
| Primary Database | PostgreSQL 15+ | JSONB for semi-structured scan data |
| Cache / Token State Store | Redis | Celery broker/result backend, exploit lookup cache, refresh-token family state, token revocation state, rate-limit counters |
| Container Runtime | Podman | Daemonless, rootless — used for application deployment and local dev services |
| Orchestration | Kubernetes (K8s) | Production deployments; k3s for local development |
| Image Builds | Buildah | Daemonless OCI image builder; pairs natively with Podman; used in CI/CD |
| IaC | Helm | Helm charts for K8s deployment |
| Secrets Management | Kubernetes Secrets + HashiCorp Vault | Vault recommended for production; Kubernetes Secrets as fallback |

> **Phase 2 additions to tech stack:** gVisor (`runsc`) as the mandatory execution sandbox runtime.

### § 6.2 — Phase 1 System Diagram

```
[React SPA]
     │
     ▼ HTTPS / TLS
[FastAPI Backend]
     │
     ├──► [PostgreSQL]          — primary persistent store
     ├──► [Redis]               — sessions, cache, job queue
     └──► [Celery Workers]      — async task processing
               │
               ├──► [Scanner Connectors]                  — Nessus first, then OpenVAS, Burp, etc.
               └──► [Enrichment & Exploit Metadata]       — NVD, SearchSploit metadata, VulnCheck, etc.
```

### § 6.3 — Phase 2 System Diagram (Deferred)

```
[React SPA]
     │
     ▼ HTTPS / TLS
[FastAPI Backend]
     │
     ├──► [PostgreSQL]
     ├──► [Redis]
     └──► [Celery Workers]
               │
               ├──► [Scanner Connectors]
               ├──► [Exploit Intelligence]
               └──► [Execution Engine]
                         │
                         └──► [Podman + gVisor ephemeral containers]
                                        │
                                        └──► [Target — network allowlisted]
```

### § 6.4 — Deployment Topology

- Containerized via Podman (daemonless, rootless); orchestrated with Kubernetes for production.
- Container images built using Buildah in CI/CD pipelines.
- Podman Compose is supported for local development only — never for production.
- A generic Kubernetes manifest set and Helm chart are provided for on-premises Linux deployments.
- Configuration managed via environment variables and secrets management (HashiCorp Vault or Kubernetes Secrets).
- No hardcoded credentials, API keys, or environment-specific values anywhere in source code.
- Developer workstations may use Docker locally if preferred (OCI image compatibility is identical); Podman is the documented and officially supported runtime.

### § 6.5 — Installation

EVE must support installation on generic Linux hosts (no distribution-specific assumptions in install scripts or documentation). The target installation method is a single-command installer delivered via HTTPS:

```
curl -sSL https://github.com/davidmcduffie001/EVE/install.sh | bash
```

The command above is a development placeholder and must not be used for production documentation as written. Production installation must use a versioned release URL, checksum verification, and a detached signature or signed checksum file before executing any installer content. Air-gapped installation must be supported through a downloadable release bundle containing container images, Helm charts, the installer, checksums, and signatures.

The installer is responsible for: verifying system prerequisites (CPU, RAM, disk, kernel version, container runtime availability), deploying the K8s manifests or Helm chart, initializing the database schema, and launching all services. The installer must be idempotent and must not require distribution-specific package managers beyond what is needed to satisfy prerequisites.

The installation script is hosted at `https://github.com/davidmcduffie001/EVE/install.sh`.

---

## § 7 — Phase 2: Exploit Execution Engine (Deferred)

This section documents the Phase 2 execution engine for design continuity. Nothing in this section should be built, scaffolded, or stubbed during Phase 1.

### § 7.1 — Architecture

- Each exploit execution runs in a freshly provisioned, ephemeral container managed by Podman.
- All execution containers are sandboxed using gVisor (`runsc`), which intercepts and mediates all syscalls via a user-space kernel.
- Containers are launched from a hardened, minimal base image with no unnecessary tooling, network access, or privileges.
- Execution containers have no access to the host network — network access is strictly limited to the specific target host/IP via Kubernetes network policy.
- Containers are automatically destroyed after execution completes or after a configurable timeout (default: 5 minutes).

### § 7.2 — Execution Workflow

1. User initiates an exploit validation job for a specific finding + target pair and re-acknowledges the AUP.
2. System validates the target is within the installation's authorized asset scope.
3. Exploit code is retrieved from the external source at job time and streamed directly into the ephemeral container — never written to persistent storage.
4. Container executes the exploit; stdout, stderr, and exit codes are captured.
5. Container is destroyed immediately on completion or timeout; all exploit code is destroyed with it.
6. Results are written to `ExecutionResult` and surfaced in the UI.
7. The only durable record is the `ExploitRecord` metadata entry — no exploit code is retained after step 5.

### § 7.3 — Safety Controls

- Execution against out-of-scope targets rejected at the API layer before any container is provisioned.
- Rate limiting applied to execution jobs at the installation level; CE limits enforced at the API layer.
- All execution containers subject to resource limits (CPU, memory, network bandwidth).
- Execution container network access strictly limited to the specific allowlisted target host/IP via Kubernetes network policy.
- All execution requests logged with user identity, timestamp, target, and exploit source URL reference.

### § 7.4 — Credentials Manager (Phase 2)

The Credentials tab provides a dedicated interface for managing credential sets used during authenticated exploit execution. Credentials are stored encrypted at rest and are never logged, displayed in plaintext after entry, or included in any export or report.

Credentials are scoped to one or more targets within the authorized scope. When an execution job is initiated against a target that has associated credentials, the appropriate credential set is injected into the execution container at job time and destroyed with the container on completion.

#### Supported Credential Types

| Type | Fields | Notes |
|---|---|---|
| **Windows Domain (Kerberos)** | Domain FQDN, username, password or keytab file | Keytab upload supported for ticketless workflows |
| **Windows Domain (NTLM)** | Domain, username, password or NTLM hash | Pass-the-hash supported; hash format: `LM:NTLM` |
| **Windows Local Account** | Username, password or NTLM hash | Scope-limited to specific target IPs |
| **SSH — Password** | Username, password, port (default: 22) | Used for Linux/Unix targets and any SSH-capable service |
| **SSH — Key-Based** | Username, private key file (PEM/OpenSSH), passphrase (optional), port | RSA, ECDSA, and Ed25519 supported; key material destroyed post-use |
| **HTTP Basic Auth** | Username, password, realm (optional) | For web application authenticated scanning |
| **HTTP Form / Cookie** | Login URL, field names, credentials, success indicator; or raw session cookie | For custom login forms and pre-authenticated sessions |
| **Database** | DB type (MSSQL / MySQL / PostgreSQL / Oracle), host, port, username, password, database name | For authenticated database checks |
| **SNMP** | Community string (v1/v2c) or username + auth/priv protocol + passwords (v3) | For network device authenticated scans |
| **API Key / Bearer Token** | Header name, token value | Generic token-based auth for REST APIs and custom services |

#### Credential Management Requirements

- Credentials require the `credentials:manage` permission to create, edit, or delete.
- Credential secrets are never displayed after initial entry — only name, type, associated targets, and last-used timestamp are shown.
- Credentials can be tested against their associated targets without initiating a full execution job.
- All credential lifecycle events are written to the audit log; credential values are never included in log entries.
- File uploads (keytab, private key) are validated for format before storage; maximum file size 64 KB per credential file.
- CE installations are limited to 5 stored credential sets. Enterprise has no limit.

---

## § 8 — Scanner & Intelligence Integrations

### § 8.1 — Supported Scanners

The platform uses a modular connector/plugin architecture. Each scanner is an independent connector, allowing new scanners to be added without modifying core business logic.

| Tool | Phase | Integration Method | Notes |
|---|---|---|---|
| Nessus / Tenable.sc | Phase 1 MVP | Tenable REST API | First connector implemented end to end; establishes connector interface, credential handling, normalization, sync scheduling, and test-fixture patterns |
| OpenVAS / Greenbone | Phase 1 follow-on | Greenbone Management Protocol (GMP) API via a maintained Python client | Implement after Nessus connector acceptance |
| Burp Suite Enterprise | Phase 1 follow-on | Burp Suite Enterprise REST API | Implement after Nessus connector acceptance |
| BloodHound (AD Attack Paths) | Phase 1 follow-on | BloodHound API / Neo4j query results import | Implement after Nessus connector acceptance |
| Qualys | Phase 1 follow-on | Qualys VMDR REST API | Implement after Nessus connector acceptance |
| Rapid7 InsightVM | Phase 1 follow-on | InsightVM REST API | Implement after Nessus connector acceptance |

### § 8.2 — Vulnerability Enrichment & Exploit Intelligence Sources

Two sources are built-in, immutable, and enabled on all installations regardless of edition. NVD provides vulnerability enrichment. SearchSploit provides exploit metadata through a metadata-only index derived from Exploit-DB. They appear in the intelligence settings view but cannot be edited, disabled, or removed. All remaining sources are Enterprise-only and require an API key or external service configuration.

| Source | Source Class | Edition | Integration Method | Notes |
|---|---|---|---|---|
| NVD (NIST) | Vulnerability enrichment | All (built-in, immutable) | NVD REST API | CVE enrichment, CVSS data, descriptions, references; primary enrichment source; always active |
| Exploit-DB (SearchSploit) | Exploit intelligence metadata | All (built-in, immutable) | Local metadata index generated from Exploit-DB | Metadata only; no exploit code, payload files, proof-of-concept scripts, or raw Exploit-DB repository content may be bundled or fetched in Phase 1 |
| MITRE CVE | Vulnerability enrichment | Enterprise | CVE REST API | Supplementary CVE data and CNA attribution |
| VulnCheck | Exploit intelligence metadata | Enterprise | VulnCheck REST API | Real-time exploit intelligence; API key required |
| Rapid7 Vulnerability & Exploit DB | Exploit intelligence metadata | Enterprise | Rapid7 public vuln/exploit DB + Metasploit Framework RPC API | Metadata and module ranking only in Phase 1; requires local or remote Metasploit Framework instance |
| Vulners | Exploit intelligence metadata | Enterprise | Vulners REST API (v3) | Aggregated exploit metadata and PoC references; commercial API key for automation |
| VulDB | Vulnerability enrichment + exploit intelligence metadata | Enterprise | VulDB REST API | Temporal CVSS scoring, exploit price estimation, APT actor correlation; commercial API key required |
| Armis Vulnerability Intelligence DB | Vulnerability enrichment | Enterprise | Armis REST API | AI-enriched vulnerability intelligence with IoT/OT/medical device coverage; commercial API key required |

### § 8.3 — Exploit Metadata Constraint (Phase 1)

In Phase 1, EVE retrieves and stores only vulnerability enrichment fields and exploit *metadata* from intelligence sources — source URL, provider, title, author, disclosure date, exploit type, reliability rating, affected platform metadata, and CVE linkage. No exploit code is fetched at any point. Source links are presented to the user as external references; clicking them opens the source in the user's browser. This constraint is architectural, not incidental — it defines the Phase 1 threat model.

The SearchSploit integration must use a generated metadata-only index. The update process may read upstream Exploit-DB data in a controlled build/update environment only long enough to extract approved metadata fields, but the shipped application, runtime containers, Redis cache, database, logs, and local update artifacts must never contain raw exploit files or executable proof-of-concept content. Tests must verify that SearchSploit fixtures and update artifacts exclude exploit body/content fields.

In Phase 2, the no-persistence constraint applies to exploit *code* specifically: code is streamed into ephemeral containers at execution time and never written to durable storage. Metadata continues to be stored as in Phase 1.

Provider-specific constraints:

- NVD requests must respect upstream rate limits. An NVD API key is optional in CE and Enterprise and may be configured to increase quota, but the source remains active even without a key.
- SearchSploit metadata comes from the locally bundled metadata-only index. The installer and update jobs must provide a controlled way to refresh the index, verify that it contains no exploit code fields, and surface index age in the UI.
- Enterprise sources that require API keys must fail closed when credentials are missing, invalid, expired, or rate limited. These failures must not block built-in NVD/SearchSploit enrichment.

---

## § 9 — Data Model

All scanner-specific output is normalized into the following canonical entities.

**Phase 1 referential integrity chain:** `User → ScannerIntegration → Scan → Finding → CVE → ExploitRecord`

**Phase 2 extension:** `... → ExploitRecord → ExecutionJob → ExecutionResult`

Finding identity is stable across repeated scanner syncs. Connectors must compute `dedupe_key` from normalized fields in this order of preference: scanner type, target locator, scanner-native plugin/finding ID when available, CVE ID set when available, port, protocol, service name, and normalized title. Re-importing the same vulnerability for the same target updates `last_seen_at`, severity, status metadata, and scanner-specific evidence instead of creating duplicate active findings.

Raw scanner output is not persisted by default. If an administrator enables raw-output retention for troubleshooting, connectors must redact credentials, bearer tokens, session cookies, private keys, authorization headers, and scanner secrets before storage. Redacted raw output is stored outside the main scan row behind `raw_output_ref`, encrypted at the application layer, subject to the scan retention window, and excluded from CSV/PDF/JSON user exports unless an administrator explicitly requests a diagnostic export.

```
User
  - id (uuid, PK)
  - email (string, unique)
  - display_name (string)
  - role_id (fk → Role)
  - mfa_enrolled (bool)           — true if this user has set up TOTP MFA
  - mfa_secret (string, encrypted)  — TOTP secret; null if not enrolled
  - theme_preference (enum: dark / light)
  - created_at (timestamp)

Role
  - id (uuid, PK)
  - name (string)
  - is_system_role (bool)
  - permissions (jsonb)             — list of permission strings

UserPreference
  - user_id (uuid, PK, fk → User)
  - timezone (string, default: UTC)
  - date_format (string)
  - default_landing_page (string)
  - table_state (jsonb)              — per-view table visibility, filters, sort, pagination
  - updated_at (timestamp)

Target
  - id (uuid, PK)
  - locator (string)                 — host, IP address, domain, URL, or CIDR entry
  - locator_type (enum: host / ip / domain / url / cidr)
  - tags (jsonb)
  - in_authorized_scope (bool)
  - archived_at (timestamp, nullable)
  - created_at (timestamp)

ScannerIntegration
  - id (uuid, PK)
  - name (string)
  - scanner_type (enum: nessus / tenable_sc / greenbone / burp_enterprise / bloodhound / qualys / insightvm)
  - edition_required (enum: ce / enterprise)
  - enabled (bool)
  - encrypted_credentials_ref (string) — reference to encrypted credential material; plaintext never stored
  - schedule (jsonb, nullable)         — cron/interval configuration for automated sync
  - last_sync_status (enum: never_run / queued / running / succeeded / failed)
  - last_sync_at (timestamp, nullable)
  - last_error (string, nullable)
  - created_by (fk → User)
  - created_at (timestamp)
  - updated_at (timestamp)

Scan
  - id (uuid, PK)
  - scanner_integration_id (fk → ScannerIntegration)
  - scanner_type (enum)
  - scanner_scan_id (string, nullable)       — scanner-native scan identifier when provided
  - status (enum: queued / running / succeeded / failed / canceled)
  - started_at / completed_at (timestamp, nullable)
  - raw_output_ref (string, nullable)         — optional reference to encrypted, redacted raw scanner output; disabled by default

ScanTarget
  - scan_id (fk → Scan)
  - target_id (fk → Target)
  - primary key (scan_id, target_id)

Finding
  - id (uuid, PK)
  - scan_id (fk → Scan)
  - target_id (fk → Target)
  - scanner_finding_id (string, nullable)     — scanner-native plugin/finding identifier when provided
  - dedupe_key (string, indexed)              — stable hash of scanner type, target, CVE/plugin identity, port, protocol, and normalized title
  - severity (enum: critical / high / medium / low / info)
  - status (enum: open / acknowledged / false_positive / remediated / risk_accepted)
  - title, description (string)
  - port (integer, nullable)
  - protocol (string, nullable)
  - service_name (string, nullable)
  - confidence (enum: confirmed / likely / potential / unknown)
  - assigned_to (fk → User, nullable)
  - tool_specific_data (jsonb)
  - first_seen_at / last_seen_at (timestamp)

FindingCVE
  - finding_id (fk → Finding)
  - cve_id (fk → CVE)
  - primary key (finding_id, cve_id)

CVE
  - id (string, PK — e.g. CVE-2024-12345)
  - cvss_score (float)
  - description (string)
  - affected_products (jsonb)
  - references (jsonb)
  - last_enriched_at (timestamp)

ExploitRecord                        ← metadata only; no exploit code stored
  - id (uuid, PK)
  - cve_id (fk → CVE)
  - source_url (string)
  - provider (enum: nvd / searchsploit / vulncheck / rapid7 / vulners / vuldb / armis / mitre)
  - title, author (string)
  - disclosure_date (date)
  - exploit_type (string)
  - reliability_rating (string)
  - created_at (timestamp)

ExploitIntelSource
  - id (uuid, PK)
  - provider (enum: nvd / searchsploit / vulncheck / rapid7 / vulners / vuldb / armis / mitre)
  - source_class (enum: vulnerability_enrichment / exploit_intelligence_metadata / combined)
  - edition_required (enum: ce / enterprise)
  - built_in (bool)
  - enabled (bool)
  - encrypted_api_key_ref (string, nullable)
  - last_health_status (enum: unknown / healthy / degraded / failed)
  - last_checked_at (timestamp, nullable)
  - last_error (string, nullable)
  - updated_at (timestamp)

License
  - id (uuid, PK)
  - edition (enum: ce / enterprise)
  - status (enum: active / expired / invalid / revoked)
  - issued_to (string)
  - issued_at (timestamp)
  - expires_at (timestamp, nullable)
  - installation_id (string)         ← bound to this installation
  - feature_flags (jsonb)
  - signature (string)               ← cryptographic signature for tamper detection
  - imported_at (timestamp)
  - imported_by (fk → User)

ReportExport
  - id (uuid, PK)
  - requested_by (fk → User)
  - format (enum: csv / json / pdf)
  - status (enum: queued / running / succeeded / failed / expired)
  - filters (jsonb)
  - storage_ref (string, nullable)
  - created_at / completed_at / expires_at (timestamp, nullable)

Notification
  - id (uuid, PK)
  - user_id (fk → User)
  - type (string)
  - title (string)
  - body (string)
  - read_at (timestamp, nullable)
  - created_at (timestamp)

AuditLog
  - id (uuid, PK)
  - occurred_at (timestamp UTC)
  - user_id (fk → User, nullable)
  - action (string)
  - resource_type (string)
  - resource_id (string, nullable)
  - outcome (enum: success / failure / denied)
  - source_ip (string, nullable)
  - metadata (jsonb)
  - previous_hash (string)
  - entry_hash (string)              — hash chain for tamper evidence

LegalAcknowledgment
  - id (uuid, PK)
  - user_id (fk → User)
  - document_type (enum: eula / acceptable_use_policy / privacy_policy / self_hosted_addendum)
  - document_version_hash (string)
  - acknowledged_at (timestamp UTC)
  - source_ip (string, nullable)
```

**Phase 2 additions to data model** (do not create these in Phase 1):

```
# Phase 2 only — do not scaffold in Phase 1
ExecutionJob
  - id (uuid, PK)
  - finding_id (fk → Finding)
  - target_id (fk → Target)
  - exploit_record_id (fk → ExploitRecord)
  - initiated_by (fk → User)
  - status (enum: pending / running / completed / failed / timed_out)
  - aup_acknowledged_at (timestamp)
  - started_at / completed_at (timestamp)

ExecutionResult
  - id (uuid, PK)
  - job_id (fk → ExecutionJob)
  - outcome (enum: success / failure / error / timeout)
  - stdout_summary (string)
  - stderr_summary (string)
  - created_at (timestamp)

Credential                           ← Phase 2 only
  - id (uuid, PK)
  - display_name (string)
  - credential_type (enum)
  - target_scope (jsonb)             — associated target IDs or CIDR ranges
  - encrypted_payload (bytea)        — AES-256 encrypted credential material
  - created_by (fk → User)
  - last_used_at (timestamp, nullable)
  - created_at (timestamp)
```

Note: `ExploitRecord` drops the `exploit_sha256` and `payload_sha256` fields that were present in earlier spec drafts. These were only meaningful in the context of Phase 2 execution (hashing code at retrieval time). They will be reintroduced in the Phase 2 data model update.

---

## § 10 — API Design

The EVE API is RESTful, implemented in FastAPI, and fully documented via auto-generated OpenAPI (Swagger) documentation accessible to authenticated users. All endpoints require authentication except `/health` and auth endpoints.

### § 10.1 — API Contract Conventions

- List endpoints must support server-side pagination with `page`, `page_size`, `sort`, and filter query parameters unless a documented endpoint-specific reason exists. Responses use the envelope `{ "items": [...], "page": 1, "page_size": 50, "total": 123 }`.
- Error responses use the envelope `{ "error": { "code": "string", "message": "safe user-facing message", "details": {} } }`. Error messages must not include stack traces, SQL errors, filesystem paths, secrets, scanner credentials, or raw upstream response bodies.
- State-changing endpoints must declare their required permission in the OpenAPI description and enforce it at the API layer. UI affordances are supplementary and are never the enforcement boundary.
- State-changing endpoints must emit audit events for success, denial, and validation/security failures. Audit metadata must include the acting user, target resource, outcome, source IP, and a redacted summary of meaningful request context.
- Endpoints that accept credentials, API keys, license files, legal acknowledgments, scanner configuration, scope changes, or report exports must include focused negative-path tests for authorization failure, CE/Enterprise gating, validation errors, and audit-log creation.

### § 10.2 — API Key Authentication (Enterprise Only)

- Users may generate named API keys scoped to their account and role permissions via the Settings panel.
- API keys presented as bearer tokens: `Authorization: Bearer <api_key>`.
- API keys shown to the user only once at creation time; stored as a hash (bcrypt or Argon2) — cannot be retrieved after creation.
- API keys inherit the permissions of the issuing user's role and cannot exceed those permissions.
- Keys may optionally be scoped to a restricted permission subset and/or an IP allowlist at creation time.
- Administrators may view, audit, and revoke any API key.
- Creation, use, and revocation are all audit-logged.

### § 10.3 — Phase 1 Core Endpoints (Representative)

```
# Auth
POST   /auth/login
POST   /auth/logout
POST   /auth/refresh
POST   /auth/mfa/enroll
POST   /auth/mfa/verify
POST   /auth/mfa/disable

# Targets
GET    /targets
POST   /targets
GET    /targets/{id}
PATCH  /targets/{id}
DELETE /targets/{id}

# Scans
GET    /scans
POST   /scans/sync               — trigger on-demand scanner sync
GET    /scans/{id}
GET    /scans/{id}/targets

# Findings
GET    /findings                 — filterable, sortable, paginated
GET    /findings/{id}
PATCH  /findings/{id}
POST   /findings/bulk            — bulk actions

# Exploit Intelligence
GET    /findings/{id}/exploits
POST   /findings/{id}/exploits/refresh
GET    /settings/intel-sources
PATCH  /settings/intel-sources/{provider}
POST   /settings/intel-sources/{provider}/test

# Reports
POST   /reports
GET    /reports
GET    /reports/{id}
GET    /reports/{id}/download

# Settings
GET    /settings/scanners
POST   /settings/scanners        — add scanner integration (credentials included in payload)
PATCH  /settings/scanners/{id}
DELETE /settings/scanners/{id}
POST   /settings/scanners/{id}/test
POST   /settings/scanners/{id}/sync
GET    /settings/scope
PUT    /settings/scope
GET    /settings/preferences
PUT    /settings/preferences

# License
GET    /license                  — current edition and status
POST   /license                  — import license file

# Admin
GET    /admin/users
POST   /admin/users
PATCH  /admin/users/{id}
GET    /admin/roles
POST   /admin/roles              — Enterprise only
GET    /admin/audit-log
GET    /admin/audit-log/export
GET    /admin/api-keys           — Enterprise only
POST   /admin/api-keys           — Enterprise only
DELETE /admin/api-keys/{id}      — Enterprise only

# Legal
GET    /legal/documents
POST   /legal/acknowledgments

# Notifications and search
GET    /notifications
PATCH  /notifications/{id}
GET    /search

# System
GET    /health                   — unauthenticated
```

### § 10.4 — Phase 2 Endpoint Additions (Deferred)

```
# Phase 2 only — do not implement in Phase 1
GET    /executions
POST   /executions               — initiate job (requires AUP re-ack payload)
GET    /executions/{id}
GET    /executions/{id}/stream   — live log streaming (SSE or WebSocket)
DELETE /executions/{id}          — cancel pending job

GET    /credentials
POST   /credentials
PATCH  /credentials/{id}
DELETE /credentials/{id}
POST   /credentials/{id}/test    — connectivity/auth test
```

---

## § 11 — Security Architecture

### § 11.1 — Authentication & Session Management

- Local account authentication on all editions. SSO (SAML 2.0 / OIDC) Enterprise only.
- MFA is user-configurable: each user may independently enrol or unenrol via their account preferences. TOTP (RFC 6238) is the supported method.
- Administrators have a platform-wide MFA policy setting with three states: **User-controlled** (default — each user decides), **Enforced** (all users must have MFA enabled; users without it are prompted to enrol on next login before accessing any functionality), and **Disabled** (MFA is turned off for all accounts regardless of user preference). Admin policy takes precedence over individual user settings.
- When a user has MFA active, privileged actions (scope changes, license import) prompt for step-up MFA re-authentication.
- JWT-based session tokens with ≤1 hour expiry; refresh token rotation enforced.
- Redis is not the browser session authority. Browser clients receive access and refresh JWTs in secure cookies. Redis stores refresh-token family state, token revocation markers, rate-limit counters, and short-lived server-side coordination data so logout, refresh-token reuse detection, and administrative revocation take effect before JWT expiry.
- Browser session tokens must be stored in `HttpOnly`, `Secure`, `SameSite` cookies. Access tokens and refresh tokens must not be stored in `localStorage` or readable JavaScript storage. API-key bearer tokens are supported only for Enterprise programmatic clients.
- CSRF protection is required for cookie-authenticated state-changing requests.

### § 11.2 — Data Security

- All data encrypted in transit via TLS 1.2+ (TLS 1.3 preferred).
- All data encrypted at rest (AES-256 minimum).
- Scanner credentials and API keys encrypted at the application layer using a key derived from a Vault-managed or Kubernetes-Secrets-managed master key — never stored in plaintext.
- Kubernetes Secrets are acceptable only when Kubernetes encryption at rest is enabled. Production deployments should use Vault or another external secret manager with auditable access and rotation support.
- Automated secrets rotation supported for all stored credentials.

### § 11.3 — Input Validation & Injection Prevention

- All user-supplied input validated and sanitized server-side; client-side validation is supplementary only.
- Parameterized queries / ORM-enforced queries exclusively — no raw SQL string construction.
- All external data (scanner output, intelligence API responses) treated as untrusted at all times — never rendered unsanitized in the UI.

### § 11.4 — Audit Logging

- Append-only audit log for all security-relevant events: logins, permission changes, scanner credential access, scope changes, data exports, AUP acknowledgments, license imports.
- Each log entry must include: timestamp (UTC), user identity, action, target resource, outcome, source IP.
- Audit logs must be tamper-evident and stored separately from application logs.
- Tamper evidence is implemented through an append-only hash chain: each entry stores the prior entry hash and a canonical hash of the current entry payload. Exported audit logs include the hash chain so integrity can be verified offline.
- Exportable in JSON, CEF, and syslog formats for SIEM integration.
- Audit logs are retained indefinitely on all editions, subject to available storage quota. Administrators may manually purge audit logs, but must export them first; purge without export is blocked by the UI and API.

---

## § 12 — Web Interface

### § 12.1 — General

- React TypeScript SPA. Branding "EVE" consistent throughout wordmarks, page titles, and reports.
- All displayed data escaped and sanitized to prevent XSS. CSP headers enforced.
- No sensitive data (tokens, credentials) rendered in the DOM or stored in `localStorage`.
- Edition and license status displayed persistently in the UI (e.g., "Community Edition" badge in navigation); CE limits surfaced as actionable prompts rather than silent failures.
- Enterprise-only UI controls visible to CE users must render with a small "Enterprise" badge or lock icon adjacent to the control. Hovering or clicking the badge displays a tooltip or inline callout: "This feature requires Enterprise Edition." The control itself is non-interactive in CE but remains visible. This applies to: custom role management, SSO configuration, PDF report export, webhook/email notification configuration, additional scanner integrations beyond the first, additional intelligence sources beyond the built-in pair, and *[Phase 2]* the Credentials tab and Execution Jobs view.

### § 12.2 — Theme & Appearance

- Dark mode is the default theme on first load and for all new accounts.
- Persistent theme toggle in the top navigation bar: 🌙 in dark mode, ☀️ in light mode.
- Theme preference persisted per user account (server-side) and restored on login; falls back to `localStorage` for unauthenticated states.
- Both themes must meet WCAG 2.1 AA color contrast requirements.
- Design language: clean, dense, data-forward — consistent with professional security tooling aesthetics.

### § 12.3 — Key Views (Phase 1)

| View | Description |
|---|---|
| Dashboard | Summary of findings by severity, recent scan activity, exploit intelligence hit counts, quick-action panel |
| Targets | Asset inventory with scan coverage, finding counts, risk scores, tagging and grouping |
| Findings | Filterable, sortable, searchable table with severity, CVE, status, exploit availability indicators, and bulk actions |
| Exploit Intelligence | Per-finding exploit suggestions with source metadata, reliability ratings, and external source links |
| Reports | Exportable reports (CSV/JSON for CE; CSV/JSON/PDF for Enterprise) with customizable templates |
| Settings | Scanner integrations (with inline credential entry), authorized scope, user management, role management (Enterprise), notification preferences (Enterprise), audit log viewer, license management |

**Phase 2 view additions:** Execution Jobs, Credentials tab.

### § 12.4 — Required QoL Features

- **Global search** — searchable command palette accessible from the navigation bar, covering findings, targets, CVEs, and navigation destinations. No hotkey binding required.
- **Notifications** — in-app notification center with badge indicator (all editions); email and webhook notifications for key events (Enterprise only).
- **Breadcrumb navigation** — consistent on all nested views.
- **Persistent table state** — column visibility, sort order, filters, and pagination position persisted per user per view.
- **Contextual help** — inline tooltips for CVSS score breakdowns, exploit reliability ratings, and status indicators.
- **Inline status indicators** — color-coded severity badges, exploit-available indicators; consistent iconography and color system throughout.
- **Bulk actions** — multi-select with bulk operations on findings (acknowledge, assign, export, tag).
- **Activity feed** — per-target and per-finding timeline of scan history, status changes, and exploit intelligence updates.
- **Empty states** — all views render actionable empty states guiding the user toward next steps; no blank screens.
- **Loading skeletons** — skeleton screens instead of spinners wherever structured data is loading.
- **Confirmation dialogs** — all destructive or irreversible actions require a confirmation dialog describing consequences.
- **Session expiry warning** — users warned 5 minutes before expiry with option to extend; graceful re-auth that preserves current location.
- **Responsive layout** — fully functional at 1280px+; graceful degradation to tablet.
- **User preferences panel** — timezone, date format, theme, and default landing page. Notification preferences available in Enterprise only.
- **Pagination and virtual scrolling** — server-side pagination with configurable page size; virtual scrolling for lists exceeding ~200 rows.
- **Copyable values** — CVE IDs, IPs, and hostnames display a copy-to-clipboard icon on hover.

---

## § 13 — Development Standards

### § 13.1 — Secure Coding

- All code must follow OWASP Secure Coding Practices.
- All third-party libraries pinned to specific versions; automated dependency vulnerability scanning (Dependabot or Snyk) required in CI/CD.
- SAST integrated into CI pipeline (Bandit for Python, ESLint security plugin for TypeScript).
- Container images scanned for vulnerabilities before deployment (Trivy).
- Secrets must never be committed to version control — enforced via pre-commit hooks (`trufflehog`, `detect-private-key`).
- All code changes require peer review before merge to `main`.

### § 13.2 — Documentation Standards

- All Python functions, classes, Pydantic models, SQLAlchemy models, Celery tasks, and connector interfaces must include docstrings describing purpose, parameters, return values, and any notable side effects or security considerations.
- All React components must include JSDoc-style comments describing purpose and props.
- Inline comments should explain non-obvious logic, security decisions, and architectural constraints — not merely restate what the code does.
- A `docs/` directory maintained for ADRs, scanner integration guides, API key usage examples, and deployment runbooks.
- All public API endpoints documented via FastAPI's auto-generated OpenAPI spec; endpoint descriptions, request/response schemas, and error codes must be complete.

### § 13.3 — Pre-Commit Hook Requirements

| Hook | Purpose |
|---|---|
| `ruff` | Python linting and import sorting |
| `black` | Python code formatting |
| `bandit` | Python SAST |
| `trufflehog` | Scans commits for accidentally included secrets |
| `eslint` | TypeScript linting (security plugin enabled) |
| `prettier` | Frontend code formatting |
| `check-added-large-files` | Prevents accidental large file commits |
| `detect-private-key` | Catches accidentally committed private keys |

---

## § 14 — Data Retention

Data retention is admin-configurable via the Settings panel. Automated purge jobs run nightly to enforce configured retention windows.

| Data Type | Retention | Notes |
|---|---|---|
| Findings & scan data | Configurable by admin (default: 12 months) | Applies to all editions |
| Exploit metadata records | Linked to finding retention | Source URLs and descriptive fields only — no exploit code in any phase |
| Audit logs | Indefinite (subject to storage quota) | Must be exported before manual purge; purge without export blocked |
| Scanner credentials & API keys | Until manually deleted | Purged immediately on uninstall |
| *[Phase 2] Execution job output* | *Configurable by admin (default: 90 days)* | *Captured output summaries only* |

- Automated purge jobs must produce a structured log entry for each operation, including record counts and data types affected.

---

## § 15 — Legal & Compliance

EVE is a closed-source, commercial software product. All draft legal language must be reviewed by a licensed attorney before any commercial release.

### § 15.1 — Required Legal Documents

| Document | Filename | When Presented |
|---|---|---|
| End User License Agreement | `EULA.md` | At first launch / installation; re-acknowledged on major updates |
| Acceptable Use Policy | `ACCEPTABLE_USE_POLICY.md` | At first launch; *[Phase 2]* again before any exploit execution job |
| Privacy Policy | `PRIVACY_POLICY.md` | At first launch; linked in application footer at all times |
| Self-Hosted License Addendum | `SELF_HOSTED_ADDENDUM.md` | During installation process |

All documents stored under `docs/legal/` in the repository.

### § 15.2 — In-Application Implementation Requirements

- On first launch, users must acknowledge the EULA and AUP with distinct checkboxes per document before accessing any functionality.
- Acknowledgment events (user identity, timestamp, document title, document version hash) must be written to the audit log as immutable records.
- The current version of each document must be accessible from the application footer at all times.
- The installer must gate on acknowledgment of the EULA and Self-Hosted License Addendum before the application becomes operational.
- *[Phase 2]* The exploit execution confirmation dialog must include an inline AUP summary and a dedicated checkbox affirming authorization to test the specific target. This acknowledgment is separate from the initial AUP acknowledgment and must be logged independently.

### § 15.3 — Operational Evidence Scope

- All activity logs must be suitable for use as evidence in authorized penetration testing engagements.
- *[Phase 2]* EVE's exploit execution functionality may be subject to U.S. EAR. Specialist attorney review is required before distribution to international customers.

---

## § 16 — Development Environment Setup

This section is directed at the AI coding assistant. The following steps must be completed in order on a fresh Linux development host before any application code is written. The developer will independently configure all external services (scanner APIs, intelligence API keys).

### § 16.1 — Environment Overview

| Concern | Approach |
|---|---|
| Host OS | Generic Linux (no distribution-specific assumptions) |
| Source control | Git + GitHub; monorepo layout |
| Secret management (local) | HashiCorp Vault as a local Podman container; `direnv` for per-project env var injection |
| Local services | PostgreSQL and Redis as Podman containers |
| Local K8s | k3s for full-stack local testing |

**Note on k3s vs. production K8s:** k3s is a fully CNCF-conformant Kubernetes distribution and all standard K8s primitives (Deployments, Services, NetworkPolicies, PVCs, RBAC) behave identically. To minimize dev/prod drift: k3s is installed with Flannel disabled and Calico as the CNI, Traefik disabled and nginx-ingress installed instead, and all ingress class and storage class names parameterized in Helm values rather than hardcoded.

**Note on Phase 2 K8s requirements:** gVisor RuntimeClass registration and the NetworkPolicy-based execution container isolation are Phase 2 concerns. They are not required for Phase 1 development, but the Calico CNI installed here will support them when Phase 2 begins.

### § 16.2 — Step 1: System Dependencies

Install the following tools using the package manager available on the host system. The specific install commands will vary by Linux distribution.

Required tools: `git`, `curl`, `wget`, `jq`, `gcc`, `make`, `openssl` (devel headers), `podman`, `buildah`, `kubectl`, `direnv`, `pre-commit`, `gh` (GitHub CLI)

Remote installer scripts used during development must be treated as untrusted until verified. Prefer distribution packages or pinned release artifacts with published checksums/signatures. If a bootstrap script is used for developer convenience, pin the version where possible, review the script before execution, and document the checksum/signature verification path in `docs/runbooks/dev-environment.md`.

### § 16.3 — Step 2: Python Environment

Use `pyenv` to manage Python versions independently of the system Python.

```bash
# Development convenience path; verify the fetched script before executing on a production-like host.
curl https://pyenv.run | bash

# Add to shell profile (~/.bashrc or equivalent)
echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.bashrc
echo 'export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.bashrc
echo 'eval "$(pyenv init -)"' >> ~/.bashrc
source ~/.bashrc

pyenv install 3.14
pyenv global 3.14
python --version  # Should report Python 3.14.x

pip install --upgrade pip pipx
pipx ensurepath
pipx install ruff black bandit alembic
```

### § 16.4 — Step 3: Node.js Environment

Use `nvm` to manage Node versions.

```bash
# Development convenience path; prefer a pinned nvm release and verify the fetched script before execution.
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash
source ~/.bashrc

nvm install 20
nvm use 20
nvm alias default 20
node --version  # Should report v20.x.x
```

### § 16.5 — Step 4: Local Services via Podman

```bash
podman network create eve-dev-net

# PostgreSQL
podman run -d --name eve-postgres --network eve-dev-net \
  -e POSTGRES_USER=eve \
  -e POSTGRES_PASSWORD=eve_dev_password \
  -e POSTGRES_DB=eve_dev \
  -p 5432:5432 \
  -v eve-postgres-data:/var/lib/postgresql/data \
  postgres:15

# Redis
podman run -d --name eve-redis --network eve-dev-net \
  -p 6379:6379 \
  redis:7

# HashiCorp Vault (dev mode — not for production)
podman run -d --name eve-vault --network eve-dev-net \
  -e VAULT_DEV_ROOT_TOKEN_ID=eve-dev-root-token \
  -e VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200 \
  -p 8200:8200 \
  --cap-add IPC_LOCK \
  hashicorp/vault:latest server -dev

podman ps  # Verify all three are running
```

Configure Vault for local dev:

```bash
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='eve-dev-root-token'

podman exec eve-vault vault secrets enable -path=eve kv-v2
podman exec eve-vault vault kv put eve/dev/db password="eve_dev_password"
podman exec eve-vault vault kv get eve/dev/db  # Verify
```

### § 16.6 — Step 5: k3s for Local Kubernetes

k3s ships with Flannel as its default CNI. Flannel does not enforce Kubernetes `NetworkPolicy` objects. While this is not a Phase 1 concern, installing Calico now avoids a CNI migration when Phase 2 begins. k3s must be installed with Flannel disabled and Calico installed as the CNI instead.

```bash
# Install k3s with Flannel disabled
# Development convenience path; production-like installs must use a pinned k3s release and checksum/signature verification.
curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="--flannel-backend=none --disable-network-policy --disable=traefik" sh -

mkdir -p ~/.kube
sudo cp /etc/rancher/k3s/k3s.yaml ~/.kube/config
sudo chown $USER ~/.kube/config

# Install Calico
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.27.0/manifests/calico.yaml

kubectl wait --for=condition=ready pod -l k8s-app=calico-node -n kube-system --timeout=120s

kubectl get nodes  # Should show a single node in Ready state
```

Traefik is disabled above. Install nginx-ingress to match production:

```bash
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.10.0/deploy/static/provider/baremetal/deploy.yaml
```

### § 16.7 — Step 6: direnv Setup

```bash
echo 'eval "$(direnv hook bash)"' >> ~/.bashrc
source ~/.bashrc
```

The project `.envrc` file (git-ignored) references Vault for secrets rather than storing values directly. The AI coding assistant will scaffold this file during project initialization.

### § 16.8 — Step 7: GitHub & Git Configuration

```bash
git config --global user.name "Your Name"
git config --global user.email "you@example.com"
git config --global init.defaultBranch main
gh auth login
```

Required GitHub repository settings after repo creation: branch protection on `main` (PR review required, CI must pass, no direct pushes), Dependabot alerts for Python and npm, secret scanning, GitHub Actions for CI.

### § 16.9 — Step 8: pre-commit Hooks

The AI coding assistant will scaffold `.pre-commit-config.yaml` at project root (hooks defined in § 13.3). After scaffolding:

```bash
pre-commit install
pre-commit install --hook-type commit-msg
pre-commit run --all-files  # Must pass cleanly before feature development begins
```

### § 16.10 — Monorepo Structure

```
eve/
├── README.md
├── .env.example
├── .envrc                         # git-ignored
├── .gitignore
├── .pre-commit-config.yaml
├── backend/
│   ├── alembic/
│   ├── app/
│   │   ├── api/
│   │   ├── core/                  # Config, security, middleware
│   │   ├── models/                # SQLAlchemy ORM models
│   │   ├── schemas/               # Pydantic request/response schemas
│   │   ├── services/
│   │   │   ├── scanners/          # Scanner connector modules
│   │   │   └── exploit_intel/     # Exploit lookup services
│   │   ├── tasks/                 # Celery task definitions
│   │   └── main.py
│   ├── tests/
│   ├── Containerfile
│   └── pyproject.toml
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── hooks/
│   │   ├── api/
│   │   ├── store/
│   │   └── main.tsx
│   ├── Containerfile
│   └── package.json
├── helm/
│   └── eve/
├── install.sh                     # curl-pipe-bash installer (see § 6.5)
├── docs/
│   ├── architecture/              # ADRs and diagrams
│   ├── integrations/              # Scanner and API integration guides
│   ├── runbooks/
│   └── legal/                     # EULA, AUP, Privacy Policy, Addendum
└── .github/
    ├── workflows/                 # GitHub Actions CI pipeline
    ├── PULL_REQUEST_TEMPLATE.md
    └── ISSUE_TEMPLATE/
```

> Note the absence of `services/execution/` in the Phase 1 structure. That directory is a Phase 2 addition. Do not create it or any execution-related stubs during Phase 1.

> Backend container definitions use `Containerfile` (the Podman/Buildah convention). Syntactically identical to Dockerfiles but named `Containerfile` for toolchain consistency.

### § 16.11 — First Session Checklist

Issue the following to the AI coding assistant in order. Do not proceed to feature development until all items pass cleanly.

1. **Scaffold the monorepo** — full directory structure from § 16.10 with placeholder files and `.gitignore`.
2. **Initialize the FastAPI backend** — `pyproject.toml` with pinned dependencies, Pydantic settings model reading from environment, FastAPI app skeleton with health check endpoint, CORS middleware, and structured logging.
3. **Initialize the React frontend** — Vite + React + TypeScript, TanStack Router, shadcn/ui or Mantine, dark mode default, theme toggle with 🌙/☀️ icons wired up.
4. **Create the initial Alembic migration** — baseline schema covering the Phase 1 data model entities from § 9 only. Do not include `ExecutionJob`, `ExecutionResult`, or `Credential` tables.
5. **Scaffold `.pre-commit-config.yaml`** and run a clean baseline pass.
6. **Create the GitHub Actions CI workflow** — lint, SAST (Bandit + ESLint), tests, and Trivy container scan on every PR.
7. **Create `.env.example`** with all environment variables grouped and commented by concern (database, Redis, Vault, external APIs, app config).
8. **Create the initial `README.md` skeleton** following the structure defined in § 13.2.

---

## § 17 — Open Questions

| # | Question | Status |
|---|---|---|
| 1 | Licensing model and Enterprise tier pricing | Open — deferred to go-to-market |
| 2 | Attorney review of all documents in `docs/legal/` | Open — required before commercial release |
| 3 | *[Phase 2]* Export control compliance review for exploit execution functionality | Open — specialist attorney required before international distribution |
| 4 | Disaster recovery and backup strategy | Open — deferred to pre-launch |
| 5 | Appliance packaging (hardened OS image) | Deferred — potential future release |
| 6 | Privacy contact email address (required in Privacy Policy before launch) | Open |
| 7 | Governing law jurisdiction for EULA | Open — attorney to advise |
| 8 | Dispute resolution mechanism (arbitration vs. litigation) | Open — attorney to advise |
| 9 | License signing operations — key custody, rotation process, and operator workflow for issuing Enterprise licenses | Open |
| 10 | License server architecture — Phase 1 resolved as fully offline signed license files; optional online validation remains a future consideration | Resolved for Phase 1 |
| 11 | Installation URL | Resolved — `https://github.com/davidmcduffie001/EVE/install.sh` |

---

## § 18 — Decisions & Rationale

| Decision | Rationale |
|---|---|
| Phase 1 ships intelligence aggregation only, no execution | Delivers the core value proposition (find and surface exploits) while deferring the highest-risk, highest-complexity component (sandboxed execution engine). Reduces initial legal exposure and infrastructure requirements significantly. |
| Community / Enterprise split rather than trial model | Gives security teams a usable free tool, builds ecosystem familiarity, and creates a clear upgrade path. Limits are chosen to be meaningful for individual practitioners but insufficient for team-scale operations. |
| MFA user-controlled with admin override | Users managing their own MFA state reduces friction for individual deployments. The admin enforce/disable policy gives security-conscious teams the ability to mandate or prohibit MFA platform-wide, accommodating both high-security and restricted-credential environments. |
| CE limits enforced at the API layer | Prevents bypass via direct API calls or UI manipulation. UI prompts are UX; API enforcement is the actual gate. |
| Scanner credentials entered inline at integration config, not in a separate Credentials tab | Simpler UX for Phase 1; credentials are specific to the integration they authenticate. A separate Credentials tab is appropriate only in Phase 2 when credentials need to be associated with execution jobs across multiple contexts. |
| No execution scaffolding in Phase 1 | Avoids building dead code and forces a clean Phase 2 interface design without legacy constraints from prematurely scaffolded stubs. |
| Offline signed license files (preferred direction) | Avoids requiring outbound connectivity from air-gapped or restricted on-prem environments, which are the primary target deployment. See open question #10. |
| Podman over Docker as primary runtime | Daemonless, rootless architecture reduces attack surface; no persistent privileged daemon. |
| *[Phase 2]* gVisor (`runsc`) mandatory for execution containers | Syscall interception via user-space kernel provides strong isolation without full VM overhead. Non-negotiable given exploit execution risk. |
| Celery + Redis for async tasks | Scan syncs and exploit lookups are inherently async and long-running. Celery provides mature retry, scheduling, and observability primitives. |
| Buildah for CI/CD image builds | Daemonless; no privileged Docker socket required in CI runners. Pairs natively with Podman. |
| Monorepo layout | Simplifies cross-component refactoring, shared type definitions, and a unified CI pipeline. |
| k3s + Calico + nginx-ingress for local development K8s | Calico is installed now (not deferred to Phase 2) to avoid a CNI migration when execution NetworkPolicy enforcement is needed. nginx-ingress replaces k3s's default Traefik to match production. |
| Generic Linux target for installer | Avoids distribution-specific assumptions and maximizes deployment flexibility. |

---

## § 19 — Glossary

- **AUP:** Acceptable Use Policy — the agreement governing what users may and may not do with EVE.
- **CE:** Community Edition — the free tier of EVE with core functionality and enforced limits.
- **CVE:** Common Vulnerabilities and Exposures — a standardized identifier for a publicly known security vulnerability.
- **CVSS:** Common Vulnerability Scoring System — a numeric score (0–10) representing the severity of a vulnerability.
- **Enterprise Edition:** The licensed, full-feature tier of EVE. Unlocked by importing a valid signed license.
- **Exploit:** Code or technique that takes advantage of a vulnerability to achieve unauthorized access or behavior on a target system.
- **ExploitRecord:** EVE's internal metadata record for a known exploit. Contains source URL, provider, and descriptive fields — never exploit code itself.
- **Finding:** A single vulnerability discovered by a connected scanner tool on a specific target.
- **Phase 1:** The initial release scope — scanner integration, exploit intelligence aggregation, and web UI. No execution capability.
- **Phase 2:** The deferred execution scope — sandboxed exploit execution engine, credentials management, per-job AUP acknowledgment, and associated safety and legal controls.
- **gVisor:** A user-space kernel from Google that intercepts and mediates syscalls made by containerized processes, providing strong sandboxing without full VM overhead. Phase 2 dependency.
- **PoC:** Proof of Concept — a demonstration exploit proving a vulnerability is exploitable.
- **Scan:** A discrete assessment job performed by a connected scanner tool against one or more targets.
- **Target:** A host, IP address, domain, URL, or other asset being assessed within EVE.
- **TTL:** Time to Live — the duration for which a cached entry remains valid before expiry.
