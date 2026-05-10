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

  it("renders the authenticated dashboard when an initial user is provided", () => {
    const markup = renderToString(
      <App
        initialUser={{
          id: "user-1",
          email: "admin@example.test",
          display_name: "Admin User",
          role: "Admin",
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
        }}
      />,
    );

    expect(markup).toContain("Account Settings");
    expect(markup).toContain("Profile");
    expect(markup).toContain("Password");
    expect(markup).toContain("Preferences");
    expect(markup).toContain("MFA");
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
    expect(markup).not.toContain(">Theme</label>");
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
