import {
  Activity,
  AlertTriangle,
  Bell,
  CheckCircle2,
  Database,
  Gauge,
  KeyRound,
  LogOut,
  Radar,
  Save,
  Search,
  Settings,
  ShieldCheck,
  ShieldEllipsis,
  SlidersHorizontal,
  Siren,
  Target,
  UserCog,
  UserRound,
} from "lucide-react";
import {
  FormEvent,
  FormEventHandler,
  type Dispatch,
  type SetStateAction,
  useEffect,
  useMemo,
  useState,
} from "react";

import eveLogo from "../assets/eve-logo.png";
import { getPreviewUser } from "../auth/preview";
import { buildAuthHeaders } from "../auth/session";

const API_BASE_URL = import.meta.env.VITE_EVE_API_BASE_URL ?? "http://localhost:8001";

export type AuthenticatedUser = {
  id: string;
  email: string;
  display_name: string;
  role: string;
};

type AppProps = {
  initialUser?: AuthenticatedUser | null;
  initialView?: WorkspaceView;
};

type LoginState = "idle" | "submitting" | "failed";
type WorkspaceView = "dashboard" | "settings";
type SaveState = "idle" | "saving" | "saved" | "failed";

type UserProfile = AuthenticatedUser & {
  mfa_enrolled: boolean;
  created_at: string;
};

type UserPreferences = {
  theme_preference: "dark" | "light";
  timezone: string;
  date_format: string;
  default_landing_page: string;
  table_state: Record<string, unknown>;
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

export function App({ initialUser = null, initialView = "dashboard" }: AppProps) {
  const [user, setUser] = useState<AuthenticatedUser | null>(
    initialUser ?? getPreviewUser(getCurrentSearch(), import.meta.env.DEV),
  );
  const [loginState, setLoginState] = useState<LoginState>("idle");
  const [activeView, setActiveView] = useState<WorkspaceView>(initialView);

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
        throw new Error("Invalid credentials");
      }
      const payload = (await response.json()) as { user: AuthenticatedUser };
      setUser(payload.user);
      setLoginState("idle");
    } catch {
      setLoginState("failed");
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
    return <LoginScreen loginState={loginState} onSubmit={handleLogin} />;
  }

  return (
    <main className="app-shell">
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
                className={item.view && activeView === itemView ? "active" : undefined}
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
            <h1>{activeView === "settings" ? "Account Settings" : "Findings Dashboard"}</h1>
            <p>
              {activeView === "settings"
                ? "Manage identity, password, preferences, and authentication controls."
                : "Scanner intake, scope status, and exploit metadata triage."}
            </p>
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

        {activeView === "settings" ? (
          <SettingsWorkspace user={user} onUserChange={setUser} />
        ) : (
          <DashboardWorkspace />
        )}
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

function SettingsWorkspace({
  user,
  onUserChange,
}: {
  user: AuthenticatedUser;
  onUserChange: Dispatch<SetStateAction<AuthenticatedUser | null>>;
}) {
  const [profile, setProfile] = useState<UserProfile>({
    ...user,
    mfa_enrolled: false,
    created_at: "",
  });
  const [preferences, setPreferences] = useState<UserPreferences>({
    theme_preference: "dark",
    timezone: "UTC",
    date_format: "YYYY-MM-DD",
    default_landing_page: "dashboard",
    table_state: {},
  });
  const [profileState, setProfileState] = useState<SaveState>("idle");
  const [passwordState, setPasswordState] = useState<SaveState>("idle");
  const [preferenceState, setPreferenceState] = useState<SaveState>("idle");

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
          setPreferences(preferencesResponse);
          onUserChange({
            id: profileResponse.id,
            email: profileResponse.email,
            display_name: profileResponse.display_name,
            role: profileResponse.role,
          });
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
  }, [onUserChange]);

  async function handleProfileSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formData = new FormData(event.currentTarget);
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
      onUserChange({
        id: nextProfile.id,
        email: nextProfile.email,
        display_name: nextProfile.display_name,
        role: nextProfile.role,
      });
      setProfileState("saved");
      event.currentTarget.reset();
    } catch {
      setProfileState("failed");
    }
  }

  async function handlePasswordSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formData = new FormData(event.currentTarget);
    setPasswordState("saving");
    try {
      await fetchJson<void>("/settings/password", {
        method: "PUT",
        body: JSON.stringify({
          current_password: formData.get("current_password"),
          new_password: formData.get("new_password"),
        }),
      });
      setPasswordState("saved");
      event.currentTarget.reset();
    } catch {
      setPasswordState("failed");
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
          theme_preference: formData.get("theme_preference"),
          timezone: formData.get("timezone"),
          date_format: formData.get("date_format"),
          default_landing_page: formData.get("default_landing_page"),
          table_state: preferences.table_state,
        }),
      });
      setPreferences(nextPreferences);
      setPreferenceState("saved");
    } catch {
      setPreferenceState("failed");
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
          <FormStatus state={profileState} />
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
          <FormStatus state={passwordState} />
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
          key={`${preferences.theme_preference}-${preferences.timezone}-${preferences.default_landing_page}`}
        >
          <label>
            Theme
            <select name="theme_preference" defaultValue={preferences.theme_preference}>
              <option value="dark">Dark</option>
              <option value="light">Light</option>
            </select>
          </label>
          <label>
            Timezone
            <input name="timezone" defaultValue={preferences.timezone} required />
          </label>
          <label>
            Date format
            <input name="date_format" defaultValue={preferences.date_format} required />
          </label>
          <label>
            Landing page
            <select name="default_landing_page" defaultValue={preferences.default_landing_page}>
              <option value="dashboard">Dashboard</option>
              <option value="findings">Findings</option>
              <option value="settings">Settings</option>
            </select>
          </label>
          <FormStatus state={preferenceState} />
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
        <button className="secondary-action" type="button" disabled>
          MFA Enrollment Pending
        </button>
      </section>
    </section>
  );
}

function FormStatus({ state }: { state: SaveState }) {
  if (state === "idle") {
    return null;
  }
  if (state === "saving") {
    return <p className="form-note">Saving changes</p>;
  }
  if (state === "saved") {
    return <p className="form-success">Changes saved.</p>;
  }
  return <p className="form-error">Unable to save changes.</p>;
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
}: {
  loginState: LoginState;
  onSubmit: FormEventHandler<HTMLFormElement>;
}) {
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
          <button className="primary-action" type="submit" disabled={loginState === "submitting"}>
            <UserRound size={18} aria-hidden="true" />
            {loginState === "submitting" ? "Signing in" : "Sign In"}
          </button>
        </form>
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
