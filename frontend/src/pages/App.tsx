import {
  Activity,
  AlertTriangle,
  Bell,
  CheckCircle2,
  Database,
  Gauge,
  LogOut,
  Radar,
  Search,
  Settings,
  ShieldCheck,
  ShieldEllipsis,
  Siren,
  Target,
  UserRound,
} from "lucide-react";
import { FormEvent, FormEventHandler, useMemo, useState } from "react";

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
};

type LoginState = "idle" | "submitting" | "failed";

const navItems = [
  { label: "Dashboard", icon: Gauge, active: true },
  { label: "Targets", icon: Target },
  { label: "Findings", icon: Siren },
  { label: "Intelligence", icon: Database },
  { label: "Scanners", icon: Radar },
  { label: "Settings", icon: Settings },
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

export function App({ initialUser = null }: AppProps) {
  const [user, setUser] = useState<AuthenticatedUser | null>(
    initialUser ?? getPreviewUser(getCurrentSearch(), import.meta.env.DEV),
  );
  const [loginState, setLoginState] = useState<LoginState>("idle");

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
            return (
              <a className={item.active ? "active" : undefined} href={`#${item.label}`} key={item.label}>
                <Icon size={17} aria-hidden="true" />
                {item.label}
              </a>
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
            <h1>Findings Dashboard</h1>
            <p>Scanner intake, scope status, and exploit metadata triage.</p>
          </div>
          <div className="topbar-actions">
            <label className="search-field">
              <Search size={17} aria-hidden="true" />
              <input type="search" placeholder="Search findings, CVEs, targets" />
            </label>
            <button className="icon-button" type="button" aria-label="Notifications">
              <Bell size={18} aria-hidden="true" />
            </button>
            <div className="user-chip">
              <span>{initials}</span>
              <div>
                <strong>{user.display_name}</strong>
                <small>{user.role}</small>
              </div>
            </div>
            <button className="icon-button" type="button" aria-label="Log out" onClick={handleLogout}>
              <LogOut size={18} aria-hidden="true" />
            </button>
          </div>
        </header>

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
      </section>
    </main>
  );
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
