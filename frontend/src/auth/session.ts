const CSRF_COOKIE_NAME = "eve_csrf_token";

export function getCookieValue(name: string, cookieSource = document.cookie) {
  const cookie = cookieSource
    .split(";")
    .map((item) => item.trim())
    .find((item) => item.startsWith(`${name}=`));

  if (!cookie) {
    return null;
  }

  return decodeURIComponent(cookie.slice(name.length + 1));
}

export function buildAuthHeaders(cookieSource?: string): Record<string, string> {
  const csrfToken = getCookieValue(CSRF_COOKIE_NAME, cookieSource);
  return csrfToken ? { "x-csrf-token": csrfToken } : {};
}
