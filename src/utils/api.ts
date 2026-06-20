/**
 * Custom Fetch utility to handle authentication securely and robustly
 * bypassing read-only window.fetch limitations in secure sandboxed environments.
 */

export async function secureFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
  const customizedInit: RequestInit = init ? { ...init } : {};

  // SEC cookie-auth: auth credential is the HttpOnly nfm_session cookie (set by the server on
  // login). Send it on same-origin requests; JS never reads or stores the token. The
  // X-NFM-CSRF header is required by the server for non-GET requests and — combined with
  // SameSite=Strict — is the CSRF defense (cross-site forms cannot set this custom header).
  customizedInit.credentials = "same-origin";
  const headers = new Headers(customizedInit.headers || {});
  headers.set("X-NFM-CSRF", "1");
  customizedInit.headers = headers;

  const res = await window.fetch(input, customizedInit);

  if (res.status === 401 &&
      !url.endsWith("/api/login") &&
      !url.endsWith("/api/setup-status") &&
      !url.endsWith("/api/setup-install") &&
      !url.endsWith("/api/reinstall")
  ) {
    // SEC cookie-auth: server session is gone/expired — drop device-local admin hint and
    // signal the app to fall back to the login screen. No token is stored client-side.
    localStorage.removeItem("nginx_flow_admin_user");
    window.dispatchEvent(new Event("nginx-flow-unauthorized"));
  }

  // RBAC: a 403 means the session is valid but the user's role isn't allowed this action. Surface
  // the server's reason so the UI can show a friendly toast instead of a silent failure.
  if (res.status === 403) {
    try {
      const data = await res.clone().json().catch(() => null);
      const msg = (data && (data as { error?: string }).error) || "Permiso insuficiente para esta acción.";
      window.dispatchEvent(new CustomEvent("nginx-flow-forbidden", { detail: msg }));
    } catch { /* non-JSON 403 — ignore */ }
  }

  return res;
}
