import { renderToString } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { buildAuthHeaders, getCookieValue } from "../auth/session";
import { getPreviewUser } from "../auth/preview";
import { App } from "./App";

describe("App", () => {
  it("renders the login workflow before a user session exists", () => {
    const markup = renderToString(<App />);

    expect(markup).toContain("Sign in to EVE");
    expect(markup).toContain("Email address");
    expect(markup).toContain("Password");
  });

  it("renders an inaccessible SSO action before SSO is configured", () => {
    const markup = renderToString(<App />);

    expect(markup).toContain("Continue with SSO");
    expect(markup).toContain("SSO has not been configured by an administrator.");
    expect(markup).toContain("disabled=\"\"");
    expect(markup).not.toContain('href="http://localhost:8001/auth/sso/login"');
  });

  it("renders an SSO login link when SSO is configured", () => {
    const markup = renderToString(
      <App
        initialSsoStatus={{
          enabled: true,
          provider: "oidc",
          display_name: "Corporate IdP",
          login_url: "http://localhost:8001/auth/sso/login",
        }}
      />,
    );

    expect(markup).toContain("Continue with Corporate IdP");
    expect(markup).toContain('href="http://localhost:8001/auth/sso/login"');
  });

  it("renders the authenticated dashboard when an initial user is provided", () => {
    const markup = renderToString(
      <App
        initialUser={{
          id: "user-1",
          email: "admin@example.test",
          display_name: "Admin User",
          role: "Admin",
          permissions: ["*"],
        }}
      />,
    );

    expect(markup).toContain("Findings Dashboard");
    expect(markup).toContain("Nessus Connector");
    expect(markup).toContain("Latest Findings");
    expect(markup).toContain("Admin User");
  });

  it("renders the authenticated account settings surface", () => {
    const markup = renderToString(
      <App
        initialView="settings"
        initialUser={{
          id: "user-1",
          email: "admin@example.test",
          display_name: "Admin User",
          role: "Admin",
          permissions: ["*"],
        }}
      />,
    );

    expect(markup).toContain("Account Settings");
    expect(markup).toContain("Profile");
    expect(markup).toContain("Password");
    expect(markup).toContain("Preferences");
    expect(markup).toContain("MFA");
    expect(markup).toContain("Enable MFA");
    expect(markup).toContain("Verification code");
    expect(markup).toContain("Scan QR code");
  });

  it("requires password confirmation when changing password", () => {
    const markup = renderToString(
      <App
        initialView="settings"
        initialUser={{
          id: "user-1",
          email: "admin@example.test",
          display_name: "Admin User",
          role: "Admin",
          permissions: ["users:manage", "roles:manage"],
        }}
      />,
    );

    expect(markup).toContain('name="new_password"');
    expect(markup).toContain('name="confirm_new_password"');
    expect(markup).toContain("Confirm new password");
  });

  it("renders administrative user and role management", () => {
    const markup = renderToString(
      <App
        initialView="admin"
        initialAdminUsers={[
          {
            id: "user-1",
            email: "admin@example.test",
            display_name: "Admin User",
            role: { id: "role-1", name: "Admin" },
            disabled: false,
            mfa_enrolled: false,
            created_at: "2026-01-01T00:00:00Z",
          },
        ]}
        initialAdminRoles={[
          {
            id: "role-1",
            name: "Admin",
            is_system_role: true,
            permissions: ["users:manage", "roles:manage"],
          },
          {
            id: "role-2",
            name: "Triage",
            is_system_role: false,
            permissions: ["findings:read"],
          },
        ]}
        initialUser={{
          id: "user-1",
          email: "admin@example.test",
          display_name: "Admin User",
          role: "Admin",
          permissions: ["*"],
        }}
      />,
    );

    expect(markup).toContain("Administration");
    expect(markup).toContain("Local Users");
    expect(markup).toContain("Create User");
    expect(markup).toContain("Create Role");
    expect(markup).toContain("admin@example.test");
    expect(markup).toContain("Triage");
  });

  it("treats the built-in Admin role as authorized even without a populated permission array", () => {
    const markup = renderToString(
      <App
        initialView="admin"
        initialUser={{
          id: "user-1",
          email: "admin@example.test",
          display_name: "Admin User",
          role: "Admin",
        }}
      />,
    );

    expect(markup).toContain("Local Users");
    expect(markup).toContain("Create Role");
    expect(markup).toContain("Audit Log");
    expect(markup).not.toContain("You are not authorized to view administration content.");
  });

  it("shows administration navigation with an authorization message for users without administrative permissions", () => {
    const markup = renderToString(
      <App
        initialView="admin"
        initialUser={{
          id: "user-2",
          email: "analyst@example.test",
          display_name: "Analyst User",
          role: "Analyst",
          permissions: ["findings:read"],
        }}
      />,
    );

    expect(markup).toContain("Administration");
    expect(markup).toContain("You are not authorized to view administration content.");
    expect(markup).not.toContain("Local Users");
    expect(markup).not.toContain("Audit Log");
  });

  it("shows only user administration for users with users:manage", () => {
    const markup = renderToString(
      <App
        initialView="admin"
        initialUser={{
          id: "user-2",
          email: "user-admin@example.test",
          display_name: "User Admin",
          role: "User Manager",
          permissions: ["users:manage"],
        }}
        initialAdminRoles={[
          {
            id: "role-1",
            name: "Analyst",
            is_system_role: true,
            permissions: ["findings:read"],
          },
        ]}
      />,
    );

    expect(markup).toContain("Administration");
    expect(markup).toContain("Local Users");
    expect(markup).toContain("Create User");
    expect(markup).not.toContain("Create Role");
  });

  it("shows only role administration for users with roles:manage", () => {
    const markup = renderToString(
      <App
        initialView="admin"
        initialUser={{
          id: "user-3",
          email: "role-admin@example.test",
          display_name: "Role Admin",
          role: "Role Manager",
          permissions: ["roles:manage"],
        }}
        initialAdminRoles={[
          {
            id: "role-2",
            name: "Triage",
            is_system_role: false,
            permissions: ["findings:read"],
          },
        ]}
      />,
    );

    expect(markup).toContain("Administration");
    expect(markup).toContain("Roles");
    expect(markup).toContain("Create Role");
    expect(markup).not.toContain("Local Users");
    expect(markup).not.toContain("Create User");
  });

  it("renders SSO configuration for role administrators", () => {
    const markup = renderToString(
      <App
        initialView="admin"
        initialUser={{
          id: "user-3",
          email: "role-admin@example.test",
          display_name: "Role Admin",
          role: "Role Manager",
          permissions: ["roles:manage"],
        }}
        initialSsoSettings={{
          enabled: true,
          provider: "oidc",
          display_name: "Corporate IdP",
          issuer_url: "https://idp.example.test",
          client_id: "eve-client",
          metadata_url: "https://idp.example.test/.well-known/openid-configuration",
          auto_provision: true,
          default_role: "Analyst",
          client_secret_configured: false,
        }}
      />,
    );

    expect(markup).toContain("SSO Configuration");
    expect(markup).toContain("Corporate IdP");
    expect(markup).toContain("OpenID Connect");
    expect(markup).toContain("http://localhost:8001/auth/sso/oidc/callback");
    expect(markup).toContain("Save SSO Settings");
    expect(markup).toContain("Validate SSO Configuration");
  });

  it("renders scanner integration management on the scanners page", () => {
    const markup = renderToString(
      <App
        initialView="scanners"
        initialUser={{
          id: "user-4",
          email: "scanner-admin@example.test",
          display_name: "Scanner Admin",
          role: "Scanner Manager",
          permissions: ["scanners:manage"],
        }}
        initialScannerIntegrations={[
          {
            id: "scanner-1",
            name: "Production Nessus",
            scanner_type: "nessus",
            enabled: true,
            last_sync_status: "succeeded",
            last_sync_at: "2026-05-10T08:30:00Z",
            last_error: null,
            created_at: "2026-05-10T08:00:00Z",
            updated_at: "2026-05-10T08:30:00Z",
          },
          {
            id: "scanner-2",
            name: "Lab OpenVAS",
            scanner_type: "greenbone",
            enabled: true,
            last_sync_status: "never_run",
            last_sync_at: null,
            last_error: null,
            created_at: "2026-05-10T08:00:00Z",
            updated_at: "2026-05-10T08:30:00Z",
          },
        ]}
      />,
    );

    expect(markup).toContain("Scanner Integrations");
    expect(markup).toContain("Production Nessus");
    expect(markup).toContain("Lab OpenVAS");
    expect(markup).toContain("OpenVAS / Greenbone");
    expect(markup).toContain("Test Connection");
    expect(markup).toContain("Sync Now");
    expect(markup).toContain("Add Scanner Integration");
    expect(markup).toContain('name="scanner_type"');
    expect(markup).toContain('name="base_url"');
    expect(markup).toContain('name="access_key"');
    expect(markup).toContain('name="secret_key"');
    expect(markup).not.toContain("You are not authorized to view administration content.");
    expect(markup).not.toContain("SSO Configuration");
  });

  it("renders the audit log beneath administration controls for audit readers", () => {
    const markup = renderToString(
      <App
        initialView="admin"
        initialUser={{
          id: "user-1",
          email: "admin@example.test",
          display_name: "Admin User",
          role: "Admin",
          permissions: ["users:manage", "roles:manage", "audit:read"],
        }}
        initialAdminUsers={[
          {
            id: "user-1",
            email: "admin@example.test",
            display_name: "Admin User",
            role: { id: "role-1", name: "Admin" },
            disabled: false,
            mfa_enrolled: false,
            created_at: "2026-01-01T00:00:00Z",
          },
        ]}
        initialAdminRoles={[
          {
            id: "role-1",
            name: "Admin",
            is_system_role: true,
            permissions: ["*"],
          },
        ]}
        initialAuditLogEntries={[
          {
            id: "audit-1",
            occurred_at: "2026-05-10T08:30:00Z",
            user_id: "user-1",
            action: "admin.user_update",
            resource_type: "user",
            resource_id: "user-2",
            outcome: "success",
            source_ip: "127.0.0.1",
            metadata: { email: "analyst@example.test" },
            previous_hash: "abc",
            entry_hash: "def",
          },
        ]}
      />,
    );

    expect(markup).toContain("Local Users");
    expect(markup).toContain("Create Role");
    expect(markup).toContain("Audit Log");
    expect(markup).toContain("admin.user_update");
    expect(markup.indexOf("Audit Log")).toBeGreaterThan(markup.indexOf("Create Role"));
  });

  it("does not allow disabling the built-in Admin user from the UI", () => {
    const markup = renderToString(
      <App
        initialView="admin"
        initialAdminUsers={[
          {
            id: "user-1",
            email: "admin@example.test",
            display_name: "Admin User",
            role: { id: "role-1", name: "Admin" },
            disabled: false,
            mfa_enrolled: false,
            created_at: "2026-01-01T00:00:00Z",
          },
        ]}
        initialAdminRoles={[
          {
            id: "role-1",
            name: "Admin",
            is_system_role: true,
            permissions: ["users:manage", "roles:manage"],
          },
        ]}
        initialUser={{
          id: "user-1",
          email: "admin@example.test",
          display_name: "Admin User",
          role: "Admin",
          permissions: ["*"],
        }}
      />,
    );

    expect(markup).toContain("Enabled");
    expect(markup).toContain("disabled=\"\"");
  });

  it("locks the built-in Admin role and renders standard user status labels", () => {
    const markup = renderToString(
      <App
        initialView="admin"
        initialAdminUsers={[
          {
            id: "user-1",
            email: "admin@example.test",
            display_name: "Admin User",
            role: { id: "role-1", name: "Admin" },
            disabled: false,
            mfa_enrolled: false,
            created_at: "2026-01-01T00:00:00Z",
          },
          {
            id: "user-2",
            email: "analyst@example.test",
            display_name: "Analyst User",
            role: { id: "role-2", name: "Analyst" },
            disabled: true,
            mfa_enrolled: false,
            created_at: "2026-01-01T00:00:00Z",
          },
        ]}
        initialAdminRoles={[
          {
            id: "role-1",
            name: "Admin",
            is_system_role: true,
            permissions: ["users:manage", "roles:manage"],
          },
          {
            id: "role-2",
            name: "Analyst",
            is_system_role: true,
            permissions: ["findings:read"],
          },
        ]}
        initialUser={{
          id: "user-1",
          email: "admin@example.test",
          display_name: "Admin User",
          role: "Admin",
          permissions: ["*"],
        }}
      />,
    );

    expect(markup).not.toContain(">Built-in Admin<");
    expect(markup).toContain("Enabled");
    expect(markup).toContain("Disabled");
    expect(markup).toContain('aria-label="Built-in Admin role cannot be changed"');
  });

  it("renders theme switching in the topbar instead of preferences", () => {
    const markup = renderToString(
      <App
        initialView="settings"
        initialUser={{
          id: "user-1",
          email: "admin@example.test",
          display_name: "Admin User",
          role: "Admin",
        }}
      />,
    );

    expect(markup).toContain("Switch to light theme");
    expect(markup.indexOf("lucide-moon")).toBeLessThan(markup.indexOf("lucide-sun"));
    expect(markup).not.toContain(">Theme</label>");
  });

  it("renders saved changes in a toast notification", () => {
    const markup = renderToString(
      <App
        initialToast={{ id: 1, tone: "success", message: "Changes saved." }}
        initialUser={{
          id: "user-1",
          email: "admin@example.test",
          display_name: "Admin User",
          role: "Admin",
        }}
      />,
    );

    expect(markup).toContain('class="toast success"');
    expect(markup).toContain('role="status"');
    expect(markup).toContain("Changes saved.");
  });

  it("renders timezone and date format dropdowns without landing page settings", () => {
    const markup = renderToString(
      <App
        initialView="settings"
        initialUser={{
          id: "user-1",
          email: "admin@example.test",
          display_name: "Admin User",
          role: "Admin",
        }}
      />,
    );

    expect(markup).toContain('<select name="timezone"');
    expect(markup).toContain("America/Denver");
    expect(markup).toContain('<select name="date_format"');
    expect(markup).toContain("MM/DD/YYYY");
    expect(markup).not.toContain("Landing page");
    expect(markup).not.toContain("default_landing_page");
  });

  it("labels the create user password field as Password", () => {
    const markup = renderToString(
      <App
        initialView="admin"
        initialUser={{
          id: "user-1",
          email: "admin@example.test",
          display_name: "Admin User",
          role: "Admin",
          permissions: ["users:manage"],
        }}
        initialAdminRoles={[
          {
            id: "role-1",
            name: "Admin",
            is_system_role: true,
            permissions: ["users:manage"],
          },
        ]}
      />,
    );

    expect(markup).toContain("Password");
    expect(markup).not.toContain("Temporary password");
  });

  it("builds CSRF headers from the readable CSRF cookie", () => {
    const headers = buildAuthHeaders("eve_access_token=opaque; eve_csrf_token=csrf-123");

    expect(headers).toEqual({ "x-csrf-token": "csrf-123" });
  });

  it("returns null for missing cookies", () => {
    expect(getCookieValue("eve_csrf_token", "eve_access_token=opaque")).toBeNull();
  });

  it("provides a dev-only dashboard preview user from the preview query", () => {
    const previewUser = getPreviewUser("?preview=dashboard", true);

    expect(previewUser?.email).toBe("admin@example.test");
    expect(getPreviewUser("?preview=dashboard", false)).toBeNull();
  });
});
