import type { AuthenticatedUser } from "../pages/App";

const previewDashboardUser: AuthenticatedUser = {
  id: "preview-admin",
  email: "admin@example.test",
  display_name: "Admin User",
  role: "Admin",
};

export function getPreviewUser(search: string, isDevelopment: boolean) {
  if (!isDevelopment) {
    return null;
  }

  return new URLSearchParams(search).get("preview") === "dashboard" ? previewDashboardUser : null;
}
