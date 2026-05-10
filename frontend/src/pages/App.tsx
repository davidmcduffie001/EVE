import {
  Activity,
  AlertTriangle,
  Bell,
  CheckCircle2,
  Database,
  Eye,
  Gauge,
  KeyRound,
  LogOut,
  Moon,
  Plus,
  Radar,
  Save,
  Search,
  Settings,
  ShieldCheck,
  ShieldEllipsis,
  SlidersHorizontal,
  Siren,
  Sun,
  Target,
  Trash2,
  UserCog,
  UserPlus,
  UserRound,
} from "lucide-react";
import {
  FormEvent,
  FormEventHandler,
  type Dispatch,
  type SetStateAction,
  useCallback,
  useEffect,
  useMemo,
  useState,
} from "react";
import QRCode from "qrcode";

import eveLogo from "../assets/eve-logo.png";
import { getPreviewUser } from "../auth/preview";
import { buildAuthHeaders } from "../auth/session";

const API_BASE_URL = import.meta.env.VITE_EVE_API_BASE_URL ?? "http://localhost:8001";
const OIDC_REDIRECT_URI = `${API_BASE_URL}/auth/sso/oidc/callback`;
const SSO_LOGIN_URL = `${API_BASE_URL}/auth/sso/login`;

export type AuthenticatedUser = {
  id: string;
  email: string;
  display_name: string;
  role: string;
  permissions?: string[];
};

type AppProps = {
  initialUser?: AuthenticatedUser | null;
  initialView?: WorkspaceView;
  initialToast?: ToastMessage | null;
  initialAdminUsers?: AdminUser[];
  initialAdminRoles?: AdminRole[];
  initialAuditLogEntries?: AuditLogEntry[];
  initialSsoSettings?: SsoSettings;
};

type LoginState = "idle" | "submitting" | "failed" | "disabled" | "mfa" | "mfa-submitting";
type WorkspaceView = "dashboard" | "settings" | "admin";
type SaveState = "idle" | "saving" | "saved" | "failed";
type ThemePreference = "dark" | "light";
type ToastTone = "success" | "error";

type ToastMessage = {
  id: number;
  tone: ToastTone;
  message: string;
};
type NotifyPayload = {
  message: string;
  tone?: ToastTone;
};
type NotifyHandler = Dispatch<NotifyPayload>;

type UserProfile = AuthenticatedUser & {
  mfa_enrolled: boolean;
  created_at: string;
};

type MfaEnrollment = {
  secret: string;
  otpauth_uri: string;
};

type UserPreferences = {
  theme_preference: ThemePreference;
  timezone: string;
  date_format: string;
  table_state: Record<string, unknown>;
};

type AdminRole = {
  id: string;
  name: string;
  is_system_role: boolean;
  permissions: string[];
};

type AdminUser = {
  id: string;
  email: string;
  display_name: string;
  role: {
    id: string;
    name: string;
  };
  disabled: boolean;
  mfa_enrolled: boolean;
  created_at: string;
};

type AdminListResponse<T> = {
  items: T[];
  page: number;
  page_size: number;
  total: number;
};

type AuditLogEntry = {
  id: string;
  occurred_at: string;
  user_id: string | null;
  action: string;
  resource_type: string;
  resource_id: string | null;
  outcome: string;
  source_ip: string | null;
  metadata: Record<string, unknown>;
  previous_hash: string;
  entry_hash: string;
};

type SsoSettings = {
  enabled: boolean;
  provider: "oidc" | "saml";
  display_name: string;
  issuer_url: string;
  client_id: string;
  metadata_url: string;
  auto_provision: boolean;
  default_role: string;
  client_secret_configured: boolean;
};

const emptyAdminUsers: AdminUser[] = [];
const emptyAdminRoles: AdminRole[] = [];
const emptyAuditLogEntries: AuditLogEntry[] = [];
const defaultSsoSettings: SsoSettings = {
  enabled: false,
  provider: "oidc",
  display_name: "",
  issuer_url: "",
  client_id: "",
  metadata_url: "",
  auto_provision: false,
  default_role: "Analyst",
  client_secret_configured: false,
};

type NavItem = {
  label: string;
  icon: typeof Gauge;
  view?: WorkspaceView;
};

const navItems: NavItem[] = [
  { label: "Dashboard", icon: Gauge, view: "dashboard" },
  { label: "Targets", icon: Target },
  { label: "Findings", icon: Siren },
  { label: "Intelligence", icon: Database },
  { label: "Scanners", icon: Radar },
  { label: "Administration", icon: UserCog, view: "admin" },
  { label: "Settings", icon: Settings, view: "settings" },
];

const metrics = [
  { label: "Critical", value: "12", delta: "+3 since sync", tone: "critical" },
  { label: "High", value: "38", delta: "9 newly observed", tone: "high" },
  { label: "Assets In Scope", value: "184", delta: "27 unaudited", tone: "neutral" },
  { label: "Scanner Sync", value: "18m", delta: "Nessus completed", tone: "good" },
];

const findings = [
  {
    severity: "Critical",
    finding: "OpenSSL remote memory disclosure",
    target: "10.20.4.18",
    cve: "CVE-2026-1842",
    confidence: "Confirmed",
    status: "Open",
    lastSeen: "18 min ago",
  },
  {
    severity: "High",
    finding: "Apache path traversal exposure",
    target: "portal.internal",
    cve: "CVE-2025-6110",
    confidence: "Likely",
    status: "Acknowledged",
    lastSeen: "42 min ago",
  },
  {
    severity: "High",
    finding: "TLS certificate weak signature",
    target: "vpn.edge.local",
    cve: "CVE-2024-3981",
    confidence: "Potential",
    status: "Open",
    lastSeen: "1 hr ago",
  },
  {
    severity: "Medium",
    finding: "SMB signing not required",
    target: "10.20.8.44",
    cve: "CVE pending",
    confidence: "Likely",
    status: "Risk review",
    lastSeen: "2 hr ago",
  },
];

const activityFeed = [
  "Nessus scan imported 72 findings from Production Edge.",
  "SearchSploit metadata linked 6 public references.",
  "Scope validation marked 184 assets as authorized.",
  "Admin User refreshed the browser session.",
];

const timezoneOptions = [
  { value: "UTC", label: "UTC" },
  { value: "America/New_York", label: "Eastern Time" },
  { value: "America/Chicago", label: "Central Time" },
  { value: "America/Denver", label: "Mountain Time" },
  { value: "America/Los_Angeles", label: "Pacific Time" },
  { value: "Europe/London", label: "London" },
  { value: "Europe/Berlin", label: "Central Europe" },
  { value: "Asia/Tokyo", label: "Tokyo" },
];

const dateFormatOptions = [
  { value: "YYYY-MM-DD", label: "YYYY-MM-DD" },
  { value: "MM/DD/YYYY", label: "MM/DD/YYYY" },
  { value: "DD/MM/YYYY", label: "DD/MM/YYYY" },
  { value: "MMM D, YYYY", label: "MMM D, YYYY" },
];

const permissionOptions = [
  "findings:read",
  "findings:export",
  "targets:manage",
  "intel:manage",
  "users:manage",
  "roles:manage",
  "audit:read",
  "reports:export",
  "scanners:manage",
  "executions:create",
  "executions:approve",
  "credentials:manage",
];

const builtInAdminEmail = "admin@example.test";
const statusCodeAccepted = 202;
const statusCodeForbidden = 403;

export function App({
  initialUser = null,
  initialView = "dashboard",
  initialToast = null,
  initialAdminUsers = emptyAdminUsers,
  initialAdminRoles = emptyAdminRoles,
  initialAuditLogEntries = emptyAuditLogEntries,
  initialSsoSettings = defaultSsoSettings,
}: AppProps) {
  const [user, setUser] = useState<AuthenticatedUser | null>(
    initialUser ?? getPreviewUser(getCurrentSearch(), import.meta.env.DEV),
  );
  const [loginState, setLoginState] = useState<LoginState>("idle");
  const [mfaChallengeToken, setMfaChallengeToken] = useState<string | null>(null);
  const [activeView, setActiveView] = useState<WorkspaceView>(initialView);
  const [themePreference, setThemePreference] = useState<ThemePreference>("dark");
  const [toast, setToast] = useState<ToastMessage | null>(initialToast);
  const [preferences, setPreferences] = useState<UserPreferences>({
    theme_preference: "dark",
    timezone: "UTC",
    date_format: "YYYY-MM-DD",
    table_state: {},
  });

  const handlePreferencesChange = useMemo(
    () => (nextPreferences: UserPreferences) => {
      setPreferences(nextPreferences);
      setThemePreference(nextPreferences.theme_preference);
    },
    [],
  );

  useEffect(() => {
    if (typeof document !== "undefined") {
      document.documentElement.dataset.theme = themePreference;
    }
  }, [themePreference]);

  useEffect(() => {
    if (!toast || typeof window === "undefined") {
      return undefined;
    }
    const timeout = window.setTimeout(() => setToast(null), 2600);
    return () => window.clearTimeout(timeout);
  }, [toast]);

  const showToast = useCallback(({ message, tone = "success" }: NotifyPayload) => {
    setToast({ id: Date.now(), tone, message });
  }, []);

  const canManageUsers = user ? hasPermission(user, "users:manage") : false;
  const canManageRoles = user ? hasPermission(user, "roles:manage") : false;
  const canReadAudit = user ? hasPermission(user, "audit:read") : false;
  const effectiveActiveView = activeView;

  async function handleThemeToggle() {
    const nextTheme = themePreference === "dark" ? "light" : "dark";
    const previousTheme = themePreference;
    setThemePreference(nextTheme);

    try {
      const nextPreferences = await fetchJson<UserPreferences>("/settings/preferences", {
        method: "PUT",
        body: JSON.stringify({
          ...preferences,
          theme_preference: nextTheme,
          default_landing_page: "dashboard",
        }),
      });
      setPreferences(nextPreferences);
      setThemePreference(nextPreferences.theme_preference);
    } catch {
      setThemePreference(previousTheme);
    }
  }

  const initials = useMemo(() => {
    if (!user) {
      return "";
    }
    return user.display_name
      .split(" ")
      .map((part) => part[0])
      .join("")
      .slice(0, 2)
      .toUpperCase();
  }, [user]);

  async function handleLogin(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formData = new FormData(event.currentTarget);
    setLoginState("submitting");

    try {
      const response = await fetch(`${API_BASE_URL}/auth/login`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: formData.get("email"),
          password: formData.get("password"),
        }),
      });
      if (!response.ok) {
        const errorPayload = (await response.json().catch(() => null)) as { detail?: string } | null;
        if (response.status === statusCodeForbidden && errorPayload?.detail === "Account is disabled") {
          setLoginState("disabled");
          return;
        }
        throw new Error("Invalid credentials");
      }
      if (response.status === statusCodeAccepted) {
        const payload = (await response.json()) as { mfa_required: boolean; mfa_challenge_token: string };
        if (payload.mfa_required && payload.mfa_challenge_token) {
          setMfaChallengeToken(payload.mfa_challenge_token);
          setLoginState("mfa");
          return;
        }
        throw new Error("Missing MFA challenge");
      }
      const payload = (await response.json()) as { user: AuthenticatedUser };
      setUser(payload.user);
      setMfaChallengeToken(null);
      setLoginState("idle");
    } catch {
      setLoginState("failed");
    }
  }

  async function handleMfaLogin(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formData = new FormData(event.currentTarget);
    setLoginState("mfa-submitting");

    try {
      const response = await fetch(`${API_BASE_URL}/auth/mfa/verify`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          mfa_challenge_token: mfaChallengeToken,
          code: formData.get("code"),
        }),
      });
      if (!response.ok) {
        throw new Error("Invalid MFA code");
      }
      const payload = (await response.json()) as { user: AuthenticatedUser };
      setUser(payload.user);
      setMfaChallengeToken(null);
      setLoginState("idle");
    } catch {
      setLoginState("mfa");
    }
  }

  async function handleLogout() {
    await fetch(`${API_BASE_URL}/auth/logout`, {
      method: "POST",
      credentials: "include",
      headers: buildAuthHeaders(),
    }).catch(() => undefined);
    setUser(null);
  }

  if (!user) {
    return (
      <LoginScreen
        loginState={loginState}
        onSubmit={handleLogin}
        onMfaSubmit={handleMfaLogin}
        ssoLoginUrl={SSO_LOGIN_URL}
      />
    );
  }

  const title = effectiveActiveView === "settings" ? "Account Settings" : effectiveActiveView === "admin" ? "Administration" : "Findings Dashboard";
  const subtitle =
    effectiveActiveView === "settings"
      ? "Manage identity, password, preferences, and authentication controls."
      : effectiveActiveView === "admin"
        ? "Manage local users, role assignments, and custom RBAC roles."
        : "Scanner intake, scope status, and exploit metadata triage.";

  return (
    <main className={`app-shell theme-${themePreference}`}>
      <aside className="sidebar">
        <div className="brand">
          <img src={eveLogo} alt="EVE logo" className="brand-logo" />
          <div>
            <strong>EVE</strong>
            <span>Community Edition</span>
          </div>
        </div>
        <nav className="nav-list" aria-label="Primary navigation">
          {navItems.map((item) => {
            const Icon = item.icon;
            const itemView: WorkspaceView = item.view ?? "dashboard";
            return (
              <button
                className={item.view && effectiveActiveView === itemView ? "active" : undefined}
                type="button"
                onClick={() => setActiveView(itemView)}
                key={item.label}
              >
                <Icon size={17} aria-hidden="true" />
                {item.label}
              </button>
            );
          })}
        </nav>
        <section className="scope-panel" aria-label="Authorized scope">
          <div className="scope-icon">
            <ShieldCheck size={18} aria-hidden="true" />
          </div>
          <div>
            <strong>Authorized Scope</strong>
            <span>184 active targets</span>
          </div>
        </section>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div>
            <h1>{title}</h1>
            <p>{subtitle}</p>
          </div>
          <div className="topbar-actions">
            <label className="search-field">
              <Search size={17} aria-hidden="true" />
              <input type="search" placeholder="Search findings, CVEs, targets" />
            </label>
            <button className="icon-button" type="button" aria-label="Notifications">
              <Bell size={18} aria-hidden="true" />
            </button>
            <button
              className="theme-toggle"
              type="button"
              aria-label={themePreference === "dark" ? "Switch to light theme" : "Switch to dark theme"}
              aria-pressed={themePreference === "light"}
              onClick={handleThemeToggle}
            >
              <Moon size={16} aria-hidden="true" />
              <span />
              <Sun size={16} aria-hidden="true" />
            </button>
            <button
              className="user-chip"
              type="button"
              aria-label="Open account settings"
              onClick={() => setActiveView("settings")}
            >
              <span>{initials}</span>
              <div>
                <strong>{user.display_name}</strong>
                <small>{user.role}</small>
              </div>
            </button>
            <button className="icon-button" type="button" aria-label="Log out" onClick={handleLogout}>
              <LogOut size={18} aria-hidden="true" />
            </button>
          </div>
        </header>

        {effectiveActiveView === "settings" ? (
          <SettingsWorkspace
            user={user}
            onUserChange={setUser}
            preferences={preferences}
            onPreferencesChange={handlePreferencesChange}
            onNotify={showToast}
          />
        ) : effectiveActiveView === "admin" ? (
          <AdminWorkspace
            initialUsers={initialAdminUsers}
            initialRoles={initialAdminRoles}
            canManageUsers={canManageUsers}
            canManageRoles={canManageRoles}
            canReadAudit={canReadAudit}
            initialAuditLogEntries={initialAuditLogEntries}
            initialSsoSettings={initialSsoSettings}
            onNotify={showToast}
          />
        ) : (
          <DashboardWorkspace />
        )}
        {toast ? <ToastNotification toast={toast} /> : null}
      </section>
    </main>
  );
}

function DashboardWorkspace() {
  return (
    <>
        <section className="metrics-grid" aria-label="Environment summary">
          {metrics.map((item) => (
            <article className={`metric-card ${item.tone}`} key={item.label}>
              <span>{item.label}</span>
              <strong>{item.value}</strong>
              <small>{item.delta}</small>
            </article>
          ))}
        </section>

        <section className="dashboard-grid">
          <section className="panel severity-panel">
            <div className="panel-header">
              <div>
                <h2>Severity Distribution</h2>
                <p>Open findings from the latest scanner sync.</p>
              </div>
              <Activity size={18} aria-hidden="true" />
            </div>
            <div className="severity-bars" aria-label="Severity distribution">
              <SeverityBar label="Critical" value={12} max={50} tone="critical" />
              <SeverityBar label="High" value={38} max={50} tone="high" />
              <SeverityBar label="Medium" value={24} max={50} tone="medium" />
              <SeverityBar label="Low" value={9} max={50} tone="low" />
            </div>
          </section>

          <section className="panel scanner-panel">
            <div className="panel-header">
              <div>
                <h2>Nessus Connector</h2>
                <p>Initial scanner connector for Phase 1.</p>
              </div>
              <Radar size={18} aria-hidden="true" />
            </div>
            <ol className="connector-steps">
              <li className="complete">
                <CheckCircle2 size={16} aria-hidden="true" />
                API credentials stored
              </li>
              <li className="complete">
                <CheckCircle2 size={16} aria-hidden="true" />
                Authorized scope mapped
              </li>
              <li>
                <ShieldEllipsis size={16} aria-hidden="true" />
                Import schedule pending
              </li>
            </ol>
            <button className="secondary-action" type="button">
              Configure Scanner
            </button>
          </section>

          <section className="panel activity-panel">
            <div className="panel-header">
              <div>
                <h2>Intake Timeline</h2>
                <p>Recent normalization and enrichment events.</p>
              </div>
              <Database size={18} aria-hidden="true" />
            </div>
            <ul className="activity-list">
              {activityFeed.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          </section>
        </section>

        <section className="panel findings-panel">
          <div className="panel-header table-header">
            <div>
              <h2>Latest Findings</h2>
              <p>Normalized scanner findings with metadata-only exploit intelligence.</p>
            </div>
            <button className="secondary-action" type="button">
              Review Queue
            </button>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Finding</th>
                  <th>Target</th>
                  <th>CVE</th>
                  <th>Confidence</th>
                  <th>Status</th>
                  <th>Last Seen</th>
                </tr>
              </thead>
              <tbody>
                {findings.map((finding) => (
                  <tr key={`${finding.finding}-${finding.target}`}>
                    <td>
                      <span className={`severity-pill ${finding.severity.toLowerCase()}`}>
                        {finding.severity}
                      </span>
                    </td>
                    <td>{finding.finding}</td>
                    <td>{finding.target}</td>
                    <td>{finding.cve}</td>
                    <td>{finding.confidence}</td>
                    <td>{finding.status}</td>
                    <td>{finding.lastSeen}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
    </>
  );
}

function AdminWorkspace({
  initialUsers,
  initialRoles,
  initialAuditLogEntries,
  initialSsoSettings,
  canManageUsers,
  canManageRoles,
  canReadAudit,
  onNotify,
}: {
  initialUsers: AdminUser[];
  initialRoles: AdminRole[];
  initialAuditLogEntries: AuditLogEntry[];
  initialSsoSettings: SsoSettings;
  canManageUsers: boolean;
  canManageRoles: boolean;
  canReadAudit: boolean;
  onNotify: NotifyHandler;
}) {
  const [users, setUsers] = useState<AdminUser[]>(initialUsers);
  const [roles, setRoles] = useState<AdminRole[]>(initialRoles);
  const [auditLogEntries, setAuditLogEntries] = useState<AuditLogEntry[]>(initialAuditLogEntries);
  const [ssoSettings, setSsoSettings] = useState<SsoSettings>(initialSsoSettings);
  const [userState, setUserState] = useState<SaveState>("idle");
  const [roleState, setRoleState] = useState<SaveState>("idle");
  const [ssoState, setSsoState] = useState<SaveState>("idle");
  const [rowState, setRowState] = useState<Record<string, SaveState>>({});
  const hasAdministrationAccess = canManageUsers || canManageRoles || canReadAudit;

  useEffect(() => {
    let cancelled = false;

    async function loadAdminData() {
      try {
        const [usersResponse, rolesResponse] = await Promise.all([
          canManageUsers
            ? fetchJson<AdminListResponse<AdminUser>>("/admin/users")
            : Promise.resolve({ items: initialUsers, page: 1, page_size: initialUsers.length, total: initialUsers.length }),
          canManageRoles || canManageUsers
            ? fetchJson<AdminListResponse<AdminRole>>("/admin/roles").catch(() => ({
                items: initialRoles,
                page: 1,
                page_size: initialRoles.length,
                total: initialRoles.length,
              }))
            : Promise.resolve({ items: initialRoles, page: 1, page_size: initialRoles.length, total: initialRoles.length }),
        ]);
        if (!cancelled) {
          setUsers(usersResponse.items);
          setRoles(rolesResponse.items);
        }
      } catch {
        if (!cancelled) {
          onNotify({ message: "Unable to load administration data.", tone: "error" });
        }
      }
    }

    loadAdminData();
    return () => {
      cancelled = true;
    };
  }, [canManageRoles, canManageUsers, initialRoles, initialUsers, onNotify]);

  useEffect(() => {
    let cancelled = false;

    async function loadAuditLog() {
      if (!canReadAudit) {
        setAuditLogEntries(initialAuditLogEntries);
        return;
      }

      try {
        const response = await fetchJson<AdminListResponse<AuditLogEntry>>("/admin/audit-log");
        if (!cancelled) {
          setAuditLogEntries(response.items);
        }
      } catch {
        if (!cancelled) {
          onNotify({ message: "Unable to load audit log.", tone: "error" });
        }
      }
    }

    loadAuditLog();
    return () => {
      cancelled = true;
    };
  }, [canReadAudit, initialAuditLogEntries, onNotify]);

  useEffect(() => {
    let cancelled = false;

    async function loadSsoSettings() {
      if (!canManageRoles) {
        setSsoSettings(initialSsoSettings);
        return;
      }
      try {
        const response = await fetchJson<SsoSettings>("/admin/sso");
        if (!cancelled) {
          setSsoSettings(response);
        }
      } catch {
        if (!cancelled) {
          onNotify({ message: "Unable to load SSO settings.", tone: "error" });
        }
      }
    }

    loadSsoSettings();
    return () => {
      cancelled = true;
    };
  }, [canManageRoles, initialSsoSettings, onNotify]);

  async function handleCreateUser(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const formData = new FormData(form);
    setUserState("saving");
    try {
      const user = await fetchJson<AdminUser>("/admin/users", {
        method: "POST",
        body: JSON.stringify({
          email: formData.get("email"),
          display_name: formData.get("display_name"),
          password: formData.get("password"),
          role_id: formData.get("role_id"),
        }),
      });
      setUsers((current) => sortUsers([...current, user]));
      setUserState("idle");
      onNotify({ message: "User created." });
      form.reset();
    } catch {
      setUserState("idle");
      onNotify({ message: "Unable to create user.", tone: "error" });
    }
  }

  async function handleCreateRole(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const formData = new FormData(form);
    setRoleState("saving");
    try {
      const role = await fetchJson<AdminRole>("/admin/roles", {
        method: "POST",
        body: JSON.stringify({
          name: formData.get("name"),
          permissions: formData.getAll("permissions"),
        }),
      });
      setRoles((current) => sortRoles([...current, role]));
      setRoleState("idle");
      onNotify({ message: "Role created." });
      form.reset();
    } catch {
      setRoleState("idle");
      onNotify({ message: "Unable to create role.", tone: "error" });
    }
  }

  async function handleSsoSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const formData = new FormData(form);
    setSsoState("saving");
    try {
      const nextSettings = await fetchJson<SsoSettings>("/admin/sso", {
        method: "PUT",
        body: JSON.stringify({
          enabled: formData.get("enabled") === "on",
          provider: formData.get("provider"),
          display_name: formData.get("display_name"),
          issuer_url: formData.get("issuer_url"),
          client_id: formData.get("client_id"),
          metadata_url: formData.get("metadata_url"),
          client_secret: formData.get("client_secret") || undefined,
          auto_provision: formData.get("auto_provision") === "on",
          default_role: formData.get("default_role"),
        }),
      });
      setSsoSettings(nextSettings);
      setSsoState("idle");
      onNotify({ message: "SSO settings saved." });
      form.reset();
    } catch {
      setSsoState("idle");
      onNotify({ message: "Unable to save SSO settings.", tone: "error" });
    }
  }

  async function handleUserUpdate(user: AdminUser, form: HTMLFormElement) {
    const formData = new FormData(form);
    setRowState((current) => ({ ...current, [user.id]: "saving" }));
    try {
      const nextUser = await fetchJson<AdminUser>(`/admin/users/${user.id}`, {
        method: "PATCH",
        body: JSON.stringify({
          display_name: formData.get("display_name"),
          email: formData.get("email"),
          role_id: formData.get("role_id"),
        }),
      });
      setUsers((current) => sortUsers(current.map((item) => (item.id === user.id ? nextUser : item))));
      onNotify({ message: "User updated." });
    } catch {
      onNotify({ message: "Unable to update user.", tone: "error" });
    } finally {
      setRowState((current) => ({ ...current, [user.id]: "idle" }));
    }
  }

  async function handleUserDisabled(user: AdminUser) {
    setRowState((current) => ({ ...current, [user.id]: "saving" }));
    try {
      const nextUser = await fetchJson<AdminUser>(`/admin/users/${user.id}`, {
        method: "PATCH",
        body: JSON.stringify({ disabled: !user.disabled }),
      });
      setUsers((current) => sortUsers(current.map((item) => (item.id === user.id ? nextUser : item))));
      onNotify({ message: nextUser.disabled ? "User disabled." : "User enabled." });
    } catch {
      onNotify({ message: "Unable to update user status.", tone: "error" });
    } finally {
      setRowState((current) => ({ ...current, [user.id]: "idle" }));
    }
  }

  async function handleDeleteUser(user: AdminUser) {
    setRowState((current) => ({ ...current, [user.id]: "saving" }));
    try {
      await fetchJson<void>(`/admin/users/${user.id}`, { method: "DELETE" });
      setUsers((current) => current.filter((item) => item.id !== user.id));
      onNotify({ message: "User deleted." });
    } catch {
      onNotify({ message: "Unable to delete user.", tone: "error" });
    } finally {
      setRowState((current) => ({ ...current, [user.id]: "idle" }));
    }
  }

  async function handleClearUserMfa(user: AdminUser) {
    setRowState((current) => ({ ...current, [user.id]: "saving" }));
    try {
      const nextUser = await fetchJson<AdminUser>(`/admin/users/${user.id}/mfa`, { method: "DELETE" });
      setUsers((current) => sortUsers(current.map((item) => (item.id === user.id ? nextUser : item))));
      onNotify({ message: "MFA configuration cleared." });
    } catch {
      onNotify({ message: "Unable to clear MFA configuration.", tone: "error" });
    } finally {
      setRowState((current) => ({ ...current, [user.id]: "idle" }));
    }
  }

  async function handleDeleteRole(role: AdminRole) {
    setRowState((current) => ({ ...current, [role.id]: "saving" }));
    try {
      await fetchJson<void>(`/admin/roles/${role.id}`, { method: "DELETE" });
      setRoles((current) => current.filter((item) => item.id !== role.id));
      onNotify({ message: "Role deleted." });
    } catch {
      onNotify({ message: "Unable to delete role.", tone: "error" });
    } finally {
      setRowState((current) => ({ ...current, [role.id]: "idle" }));
    }
  }

  return (
    <section className="admin-grid" aria-label="Administration">
      {!hasAdministrationAccess ? (
        <section className="panel authorization-panel">
          <div className="panel-header">
            <div>
              <h2>Not Authorized</h2>
              <p>You are not authorized to view administration content.</p>
            </div>
            <ShieldCheck size={18} aria-hidden="true" />
          </div>
        </section>
      ) : null}

      {canManageUsers ? (
      <section className="panel admin-users-panel">
        <div className="panel-header">
          <div>
            <h2>Local Users</h2>
            <p>Create users, update profile details, assign roles, and disable accounts.</p>
          </div>
          <UserCog size={18} aria-hidden="true" />
        </div>
        <div className="table-wrap admin-table-wrap">
          <table>
            <thead>
              <tr>
                <th>User</th>
                <th>Email</th>
                <th>Role</th>
                <th>Status</th>
                <th>MFA</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map((user) => {
                const busy = rowState[user.id] === "saving";
                const builtInAdminUser = user.email === builtInAdminEmail;
                return (
                  <tr key={user.id}>
                    <td>
                      <form
                        id={`admin-user-${user.id}`}
                        className="table-edit-form"
                        onSubmit={(event) => {
                          event.preventDefault();
                          handleUserUpdate(user, event.currentTarget);
                        }}
                      >
                        <input name="display_name" defaultValue={user.display_name} required />
                      </form>
                    </td>
                    <td>
                      <input
                        form={`admin-user-${user.id}`}
                        name="email"
                        type="email"
                        defaultValue={user.email}
                        required
                      />
                    </td>
                    <td>
                      <select
                        form={`admin-user-${user.id}`}
                        name="role_id"
                        defaultValue={user.role.id}
                        disabled={builtInAdminUser}
                        aria-label={builtInAdminUser ? "Built-in Admin role cannot be changed" : undefined}
                      >
                        {roles.map((role) => (
                          <option value={role.id} key={role.id}>
                            {role.name}
                          </option>
                        ))}
                      </select>
                    </td>
                    <td>
                      <span className={`status-pill ${user.disabled ? "disabled" : "active"}`}>
                        {user.disabled ? "Disabled" : "Enabled"}
                      </span>
                    </td>
                    <td>
                      <span className={`status-pill ${user.mfa_enrolled ? "active" : "disabled"}`}>
                        {user.mfa_enrolled ? "Enabled" : "Disabled"}
                      </span>
                    </td>
                    <td>
                      <div className="table-actions">
                        <button
                          className="secondary-action"
                          type="submit"
                          form={`admin-user-${user.id}`}
                          disabled={busy}
                        >
                          <Save size={15} aria-hidden="true" />
                          Save
                        </button>
                        <button
                          className="secondary-action"
                          type="button"
                          onClick={() => handleUserDisabled(user)}
                          disabled={busy || builtInAdminUser}
                        >
                          <Eye size={15} aria-hidden="true" />
                          {user.disabled ? "Enable" : "Disable"}
                        </button>
                        <button
                          className="secondary-action"
                          type="button"
                          onClick={() => handleDeleteUser(user)}
                          disabled={busy || builtInAdminUser}
                        >
                          <Trash2 size={15} aria-hidden="true" />
                          Delete
                        </button>
                        <button
                          className="secondary-action"
                          type="button"
                          onClick={() => handleClearUserMfa(user)}
                          disabled={busy || !user.mfa_enrolled}
                        >
                          <KeyRound size={15} aria-hidden="true" />
                          Clear MFA
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>
      ) : null}

      {canManageUsers ? (
      <section className="panel settings-panel">
        <div className="panel-header">
          <div>
            <h2>Create User</h2>
            <p>Add a local account and assign an initial role.</p>
          </div>
          <UserPlus size={18} aria-hidden="true" />
        </div>
        <form className="settings-form" onSubmit={handleCreateUser}>
          <label>
            Name
            <input name="display_name" required />
          </label>
          <label>
            Email
            <input name="email" type="email" required />
          </label>
          <label>
            Password
            <input name="password" type="password" minLength={12} autoComplete="new-password" required />
          </label>
          <label>
            Role
            <select name="role_id" required defaultValue={roles[0]?.id ?? ""}>
              {roles.map((role) => (
                <option value={role.id} key={role.id}>
                  {role.name}
                </option>
              ))}
            </select>
          </label>
          <button className="primary-action" type="submit" disabled={userState === "saving" || roles.length === 0}>
            <Plus size={17} aria-hidden="true" />
            Create User
          </button>
        </form>
      </section>
      ) : null}

      {canManageRoles ? (
      <section className="panel admin-roles-panel">
        <div className="panel-header">
          <div>
            <h2>Roles</h2>
            <p>Review built-in roles and remove custom roles that are no longer assigned.</p>
          </div>
          <ShieldCheck size={18} aria-hidden="true" />
        </div>
        <div className="role-list">
          {roles.map((role) => (
            <article className="role-card" key={role.id}>
              <div>
                <strong>{role.name}</strong>
                <span>{role.is_system_role ? "System role" : "Custom role"}</span>
              </div>
              <div className="permission-list">
                {role.permissions.map((permission) => (
                  <span key={permission}>{permission}</span>
                ))}
              </div>
              <button
                className="secondary-action"
                type="button"
                disabled={role.is_system_role || rowState[role.id] === "saving"}
                onClick={() => handleDeleteRole(role)}
              >
                <Trash2 size={15} aria-hidden="true" />
                Delete
              </button>
            </article>
          ))}
        </div>
      </section>
      ) : null}

      {canManageRoles ? (
      <section className="panel settings-panel">
        <div className="panel-header">
          <div>
            <h2>Create Role</h2>
            <p>Define a custom role from the registered permission set.</p>
          </div>
          <ShieldCheck size={18} aria-hidden="true" />
        </div>
        <form className="settings-form" onSubmit={handleCreateRole}>
          <label>
            Role name
            <input name="name" required />
          </label>
          <fieldset className="permission-options">
            <legend>Permissions</legend>
            {permissionOptions.map((permission) => (
              <label key={permission}>
                <input name="permissions" type="checkbox" value={permission} />
                {permission}
              </label>
            ))}
          </fieldset>
          <button className="primary-action" type="submit" disabled={roleState === "saving"}>
            <Plus size={17} aria-hidden="true" />
            Create Role
          </button>
        </form>
      </section>
      ) : null}

      {canManageRoles ? (
      <section className="panel settings-panel sso-panel">
        <div className="panel-header">
          <div>
            <h2>SSO Configuration</h2>
            <p>Configure browser SSO through an external identity provider.</p>
          </div>
          <ShieldCheck size={18} aria-hidden="true" />
        </div>
        <form className="settings-form settings-form-inline" onSubmit={handleSsoSubmit}>
          <p className="form-note">Register this redirect URI with your OIDC provider: {OIDC_REDIRECT_URI}</p>
          <label>
            <span>Enabled</span>
            <input name="enabled" type="checkbox" defaultChecked={ssoSettings.enabled} />
          </label>
          <label>
            Provider
            <select name="provider" defaultValue={ssoSettings.provider}>
              <option value="oidc">OpenID Connect</option>
              <option value="saml">SAML 2.0</option>
            </select>
          </label>
          <label>
            Display name
            <input name="display_name" defaultValue={ssoSettings.display_name} />
          </label>
          <label>
            Default role
            <input name="default_role" defaultValue={ssoSettings.default_role} />
          </label>
          <label>
            Issuer URL
            <input name="issuer_url" type="url" defaultValue={ssoSettings.issuer_url} />
          </label>
          <label>
            Metadata URL
            <input name="metadata_url" type="url" defaultValue={ssoSettings.metadata_url} />
          </label>
          <label>
            Client ID
            <input name="client_id" defaultValue={ssoSettings.client_id} />
          </label>
          <label>
            Client secret
            <input
              name="client_secret"
              type="password"
              placeholder={ssoSettings.client_secret_configured ? "Configured" : "Not configured"}
              autoComplete="new-password"
            />
          </label>
          <label>
            <span>Auto provision users</span>
            <input name="auto_provision" type="checkbox" defaultChecked={ssoSettings.auto_provision} />
          </label>
          <button className="primary-action" type="submit" disabled={ssoState === "saving"}>
            <Save size={17} aria-hidden="true" />
            Save SSO Settings
          </button>
        </form>
      </section>
      ) : null}

      {canReadAudit ? (
      <section className="panel audit-log-panel">
        <div className="panel-header">
          <div>
            <h2>Audit Log</h2>
            <p>Tamper-evident administrative and authentication events.</p>
          </div>
          <Database size={18} aria-hidden="true" />
        </div>
        <div className="table-wrap audit-table-wrap">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Action</th>
                <th>Resource</th>
                <th>Outcome</th>
                <th>Source</th>
              </tr>
            </thead>
            <tbody>
              {auditLogEntries.map((entry) => (
                <tr key={entry.id}>
                  <td>{formatTimestamp(entry.occurred_at)}</td>
                  <td>{entry.action}</td>
                  <td>{formatAuditResource(entry)}</td>
                  <td>
                    <span className={`status-pill ${entry.outcome === "success" ? "active" : "disabled"}`}>
                      {entry.outcome}
                    </span>
                  </td>
                  <td>{entry.source_ip ?? "Unknown"}</td>
                </tr>
              ))}
              {auditLogEntries.length === 0 ? (
                <tr>
                  <td colSpan={5}>No audit events recorded.</td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </section>
      ) : null}
    </section>
  );
}

function SettingsWorkspace({
  user,
  onUserChange,
  preferences,
  onPreferencesChange,
  onNotify,
}: {
  user: AuthenticatedUser;
  onUserChange: Dispatch<SetStateAction<AuthenticatedUser | null>>;
  preferences: UserPreferences;
  onPreferencesChange: Dispatch<UserPreferences>;
  onNotify: NotifyHandler;
}) {
  const [profile, setProfile] = useState<UserProfile>({
    ...user,
    mfa_enrolled: false,
    created_at: "",
  });
  const [profileState, setProfileState] = useState<SaveState>("idle");
  const [passwordState, setPasswordState] = useState<SaveState>("idle");
  const [preferenceState, setPreferenceState] = useState<SaveState>("idle");
  const [mfaState, setMfaState] = useState<SaveState>("idle");
  const [mfaEnrollment, setMfaEnrollment] = useState<MfaEnrollment | null>(null);
  const [mfaQrCode, setMfaQrCode] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function loadSettings() {
      try {
        const [profileResponse, preferencesResponse] = await Promise.all([
          fetchJson<UserProfile>("/settings/profile"),
          fetchJson<UserPreferences>("/settings/preferences"),
        ]);
        if (!cancelled) {
          setProfile(profileResponse);
          onPreferencesChange(preferencesResponse);
          onUserChange((currentUser) => ({
            id: profileResponse.id,
            email: profileResponse.email,
            display_name: profileResponse.display_name,
            role: profileResponse.role,
            permissions: profileResponse.permissions ?? currentUser?.permissions,
          }));
        }
      } catch {
        if (!cancelled) {
          setProfileState("failed");
        }
      }
    }

    loadSettings();
    return () => {
      cancelled = true;
    };
  }, [onPreferencesChange, onUserChange]);

  async function handleProfileSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const formData = new FormData(form);
    setProfileState("saving");
    try {
      const nextProfile = await fetchJson<UserProfile>("/settings/profile", {
        method: "PATCH",
        body: JSON.stringify({
          display_name: formData.get("display_name"),
          email: formData.get("email"),
          current_password: formData.get("current_password") || undefined,
        }),
      });
      setProfile(nextProfile);
      onUserChange((currentUser) => ({
        id: nextProfile.id,
        email: nextProfile.email,
        display_name: nextProfile.display_name,
        role: nextProfile.role,
        permissions: nextProfile.permissions ?? currentUser?.permissions,
      }));
      setProfileState("idle");
      onNotify({ message: "Changes saved." });
      form.reset();
    } catch {
      setProfileState("failed");
      onNotify({ message: "Unable to save changes.", tone: "error" });
    }
  }

  async function handlePasswordSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const formData = new FormData(form);
    const newPassword = formData.get("new_password");
    if (newPassword !== formData.get("confirm_new_password")) {
      setPasswordState("idle");
      onNotify({ message: "New passwords do not match.", tone: "error" });
      return;
    }
    setPasswordState("saving");
    try {
      await fetchJson<void>("/settings/password", {
        method: "PUT",
        body: JSON.stringify({
          current_password: formData.get("current_password"),
          new_password: newPassword,
        }),
      });
      setPasswordState("idle");
      onNotify({ message: "Changes saved." });
      form.reset();
    } catch {
      setPasswordState("failed");
      onNotify({ message: "Unable to save changes.", tone: "error" });
    }
  }

  async function handlePreferencesSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formData = new FormData(event.currentTarget);
    setPreferenceState("saving");
    try {
      const nextPreferences = await fetchJson<UserPreferences>("/settings/preferences", {
        method: "PUT",
        body: JSON.stringify({
          theme_preference: preferences.theme_preference,
          timezone: formData.get("timezone"),
          date_format: formData.get("date_format"),
          default_landing_page: "dashboard",
          table_state: preferences.table_state,
        }),
      });
      onPreferencesChange(nextPreferences);
      setPreferenceState("idle");
      onNotify({ message: "Changes saved." });
    } catch {
      setPreferenceState("failed");
      onNotify({ message: "Unable to save changes.", tone: "error" });
    }
  }

  async function handleMfaEnrollmentStart() {
    setMfaState("saving");
    try {
      const enrollment = await fetchJson<MfaEnrollment>("/settings/mfa/enrollment", {
        method: "POST",
      });
      setMfaEnrollment(enrollment);
      setMfaQrCode(await QRCode.toDataURL(enrollment.otpauth_uri, { margin: 1, width: 180 }));
      setMfaState("idle");
      onNotify({ message: "MFA setup started." });
    } catch {
      setMfaState("failed");
      onNotify({ message: "Unable to start MFA setup.", tone: "error" });
    }
  }

  async function handleMfaVerifySubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const formData = new FormData(form);
    setMfaState("saving");
    try {
      const nextProfile = await fetchJson<UserProfile>("/settings/mfa/verify", {
        method: "POST",
        body: JSON.stringify({ code: formData.get("code") }),
      });
      setProfile(nextProfile);
      setMfaEnrollment(null);
      setMfaQrCode(null);
      setMfaState("idle");
      onNotify({ message: "MFA enabled." });
      form.reset();
    } catch {
      setMfaState("failed");
      onNotify({ message: "Invalid MFA code.", tone: "error" });
    }
  }

  async function handleMfaDisableSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const formData = new FormData(form);
    setMfaState("saving");
    try {
      const nextProfile = await fetchJson<UserProfile>("/settings/mfa/disable", {
        method: "POST",
        body: JSON.stringify({ current_password: formData.get("current_password") }),
      });
      setProfile(nextProfile);
      setMfaEnrollment(null);
      setMfaQrCode(null);
      setMfaState("idle");
      onNotify({ message: "MFA disabled." });
      form.reset();
    } catch {
      setMfaState("failed");
      onNotify({ message: "Unable to disable MFA.", tone: "error" });
    }
  }

  return (
    <section className="settings-grid" aria-label="Account settings">
      <section className="panel settings-panel">
        <div className="panel-header">
          <div>
            <h2>Profile</h2>
            <p>Update your name and account email.</p>
          </div>
          <UserCog size={18} aria-hidden="true" />
        </div>
        <form className="settings-form" onSubmit={handleProfileSubmit} key={`${profile.email}-${profile.display_name}`}>
          <label>
            Name
            <input name="display_name" defaultValue={profile.display_name} required />
          </label>
          <label>
            Email
            <input name="email" type="email" defaultValue={profile.email} required />
          </label>
          <label>
            Current password
            <input
              name="current_password"
              type="password"
              autoComplete="current-password"
              placeholder="Required for email changes"
            />
          </label>
          <button className="primary-action" type="submit" disabled={profileState === "saving"}>
            <Save size={17} aria-hidden="true" />
            Save Profile
          </button>
        </form>
      </section>

      <section className="panel settings-panel">
        <div className="panel-header">
          <div>
            <h2>Password</h2>
            <p>Change your password and revoke other active sessions.</p>
          </div>
          <KeyRound size={18} aria-hidden="true" />
        </div>
        <form className="settings-form" onSubmit={handlePasswordSubmit}>
          <label>
            Current password
            <input name="current_password" type="password" autoComplete="current-password" required />
          </label>
          <label>
            New password
            <input name="new_password" type="password" minLength={12} autoComplete="new-password" required />
          </label>
          <label>
            Confirm new password
            <input
              name="confirm_new_password"
              type="password"
              minLength={12}
              autoComplete="new-password"
              required
            />
          </label>
          <button className="primary-action" type="submit" disabled={passwordState === "saving"}>
            <KeyRound size={17} aria-hidden="true" />
            Update Password
          </button>
        </form>
      </section>

      <section className="panel settings-panel">
        <div className="panel-header">
          <div>
            <h2>Preferences</h2>
            <p>Set display defaults for this browser account.</p>
          </div>
          <SlidersHorizontal size={18} aria-hidden="true" />
        </div>
        <form
          className="settings-form settings-form-inline"
          onSubmit={handlePreferencesSubmit}
          key={`${preferences.timezone}-${preferences.date_format}`}
        >
          <label>
            Timezone
            <select name="timezone" defaultValue={preferences.timezone}>
              {timezoneOptions.map((option) => (
                <option value={option.value} key={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </label>
          <label>
            Date format
            <select name="date_format" defaultValue={preferences.date_format}>
              {dateFormatOptions.map((option) => (
                <option value={option.value} key={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </label>
          <button className="primary-action" type="submit" disabled={preferenceState === "saving"}>
            <Save size={17} aria-hidden="true" />
            Save Preferences
          </button>
        </form>
      </section>

      <section className="panel settings-panel security-summary">
        <div className="panel-header">
          <div>
            <h2>MFA</h2>
            <p>TOTP enrollment will use this account settings area.</p>
          </div>
          <ShieldCheck size={18} aria-hidden="true" />
        </div>
        <dl className="settings-facts">
          <div>
            <dt>Status</dt>
            <dd>{profile.mfa_enrolled ? "Enabled" : "Not enrolled"}</dd>
          </div>
          <div>
            <dt>Role</dt>
            <dd>{profile.role}</dd>
          </div>
          <div>
            <dt>Account</dt>
            <dd>{profile.email}</dd>
          </div>
        </dl>
        {!profile.mfa_enrolled ? (
          <>
            <button
              className="secondary-action"
              type="button"
              onClick={handleMfaEnrollmentStart}
              disabled={mfaState === "saving"}
            >
              Enable MFA
            </button>
            <p className="form-note">Scan QR code with an authenticator app, then enter the verification code.</p>
            {mfaEnrollment ? (
              <div className="mfa-setup">
                <strong>Scan QR code</strong>
                {mfaQrCode ? <img className="mfa-qr-code" src={mfaQrCode} alt="MFA QR code" /> : null}
                <dl className="settings-facts">
                  <div>
                    <dt>Setup key</dt>
                    <dd>{mfaEnrollment.secret}</dd>
                  </div>
                </dl>
              </div>
            ) : null}
            <form className="settings-form" onSubmit={handleMfaVerifySubmit}>
              <label>
                Verification code
                <input
                  name="code"
                  inputMode="numeric"
                  pattern="[0-9]{6}"
                  maxLength={6}
                  disabled={!mfaEnrollment || mfaState === "saving"}
                  required
                />
              </label>
              <button className="primary-action" type="submit" disabled={!mfaEnrollment || mfaState === "saving"}>
                Verify And Enable
              </button>
            </form>
          </>
        ) : (
          <form className="settings-form" onSubmit={handleMfaDisableSubmit}>
            <label>
              Current password
              <input name="current_password" type="password" autoComplete="current-password" required />
            </label>
            <button className="secondary-action" type="submit" disabled={mfaState === "saving"}>
              Disable MFA
            </button>
          </form>
        )}
      </section>
    </section>
  );
}

function ToastNotification({ toast }: { toast: ToastMessage }) {
  return (
    <div className={`toast ${toast.tone}`} role={toast.tone === "success" ? "status" : "alert"}>
      {toast.message}
    </div>
  );
}

function sortUsers(users: AdminUser[]) {
  return users.sort((left, right) => left.email.localeCompare(right.email));
}

function sortRoles(roles: AdminRole[]) {
  return roles.sort((left, right) => left.name.localeCompare(right.name));
}

function formatTimestamp(value: string) {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return value;
  }
  return parsed.toLocaleString(undefined, {
    dateStyle: "short",
    timeStyle: "medium",
  });
}

function formatAuditResource(entry: AuditLogEntry) {
  return entry.resource_id ? `${entry.resource_type}:${entry.resource_id}` : entry.resource_type;
}

function hasPermission(user: AuthenticatedUser, permission: string) {
  if (user.role === "Admin") {
    return true;
  }
  return user.permissions?.includes("*") || user.permissions?.includes(permission) || false;
}

async function fetchJson<T>(
  path: string,
  init: { method?: string; body?: string; headers?: Record<string, string> } = {},
) {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      ...buildAuthHeaders(),
      ...init.headers,
    },
  });
  if (!response.ok) {
    throw new Error(`Request failed: ${response.status}`);
  }
  if (response.status === 204) {
    return undefined as T;
  }
  return (await response.json()) as T;
}

function getCurrentSearch() {
  return typeof window === "undefined" ? "" : window.location.search;
}

function LoginScreen({
  loginState,
  onSubmit,
  onMfaSubmit,
  ssoLoginUrl,
}: {
  loginState: LoginState;
  onSubmit: FormEventHandler<HTMLFormElement>;
  onMfaSubmit: FormEventHandler<HTMLFormElement>;
  ssoLoginUrl: string;
}) {
  const isSubmitting = loginState === "submitting" || loginState === "mfa-submitting";
  const needsMfa = loginState === "mfa" || loginState === "mfa-submitting";

  return (
    <main className="login-shell">
      <section className="login-panel">
        <div className="login-brand">
          <img src={eveLogo} alt="EVE logo" />
          <div>
            <strong>EVE</strong>
            <span>Exploit Validation Engine</span>
          </div>
        </div>
        <div className="login-copy">
          <h1>Sign in to EVE</h1>
          <p>Use your local account to review authorized scanner findings.</p>
        </div>
        {!needsMfa ? (
        <form className="login-form" onSubmit={onSubmit}>
          <label>
            Email address
            <input name="email" type="email" defaultValue="admin@example.test" required />
          </label>
          <label>
            Password
            <input name="password" type="password" autoComplete="current-password" required />
          </label>
          {loginState === "failed" ? (
            <p className="form-error">
              <AlertTriangle size={16} aria-hidden="true" />
              Invalid email or password.
            </p>
          ) : null}
          {loginState === "disabled" ? (
            <p className="form-error">
              <AlertTriangle size={16} aria-hidden="true" />
              This account is disabled.
            </p>
          ) : null}
          <button className="primary-action" type="submit" disabled={isSubmitting}>
            <UserRound size={18} aria-hidden="true" />
            {isSubmitting ? "Signing in" : "Sign In"}
          </button>
          <div className="login-divider" aria-hidden="true">
            <span />
          </div>
          <a className="secondary-action sso-login-action" href={ssoLoginUrl}>
            <KeyRound size={18} aria-hidden="true" />
            Continue with SSO
          </a>
        </form>
        ) : (
        <form className="login-form" onSubmit={onMfaSubmit}>
          <label>
            Verification code
            <input name="code" inputMode="numeric" pattern="[0-9]{6}" maxLength={6} required autoFocus />
          </label>
          <button className="primary-action" type="submit" disabled={isSubmitting}>
            <ShieldCheck size={18} aria-hidden="true" />
            {isSubmitting ? "Verifying" : "Verify MFA"}
          </button>
        </form>
        )}
      </section>
      <section className="login-preview" aria-label="EVE platform preview">
        <div className="preview-window">
          <div className="preview-toolbar">
            <span />
            <span />
            <span />
          </div>
          <div className="preview-content">
            <strong>Authorized Assessment Workspace</strong>
            <span>12 critical findings</span>
            <span>184 assets in scope</span>
            <span>Nessus sync active</span>
          </div>
        </div>
      </section>
    </main>
  );
}

function SeverityBar({
  label,
  value,
  max,
  tone,
}: {
  label: string;
  value: number;
  max: number;
  tone: string;
}) {
  return (
    <div className="severity-row">
      <span>{label}</span>
      <div className="bar-track">
        <div className={`bar-fill ${tone}`} style={{ width: `${(value / max) * 100}%` }} />
      </div>
      <strong>{value}</strong>
    </div>
  );
}
