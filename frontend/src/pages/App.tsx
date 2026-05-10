import { Activity, Database, Radar, ShieldCheck } from "lucide-react";

import eveLogo from "../assets/eve-logo.png";

const stats = [
  { label: "Findings", value: "0", icon: Activity },
  { label: "Targets", value: "0", icon: Radar },
  { label: "Intel Hits", value: "0", icon: Database },
];

export function App() {
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
          <a className="active" href="#dashboard">Dashboard</a>
          <a href="#targets">Targets</a>
          <a href="#findings">Findings</a>
          <a href="#intelligence">Exploit Intelligence</a>
          <a href="#settings">Settings</a>
        </nav>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div>
            <p className="eyebrow">Exploit Validation Engine</p>
            <h1>Security findings triage starts here.</h1>
          </div>
          <button type="button" className="primary-action">
            <ShieldCheck size={18} aria-hidden="true" />
            Connect Nessus
          </button>
        </header>

        <section className="stats-grid" aria-label="Environment summary">
          {stats.map((item) => {
            const Icon = item.icon;
            return (
              <article className="stat-card" key={item.label}>
                <Icon size={20} aria-hidden="true" />
                <span>{item.label}</span>
                <strong>{item.value}</strong>
              </article>
            );
          })}
        </section>

        <section className="empty-state">
          <h2>No scanner connected yet</h2>
          <p>
            The Phase 1 MVP begins with the Nessus / Tenable.sc connector, then normalizes
            findings and enriches CVEs with metadata-only exploit intelligence.
          </p>
        </section>
      </section>
    </main>
  );
}

