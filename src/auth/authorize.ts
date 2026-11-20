import { AuthorizationError, authorizationErrorRedirect, CimdFetchError, type ConsentDescription } from "@cloudflare/workers-oauth-provider";
import { type App, isKnownUser } from "../app";
import { timingSafeEqualString } from "../util/constant-time";
import { escapeHtml, htmlPage, messagePage, notAuthorizedPage } from "../util/html";
import { errorInfo, log } from "../util/log";
import { githubAuthorizeUrl, githubVerifiedEmail } from "./github";
import { pkceChallenge, pkceVerifier, randomState } from "./pkce";
import { clearCookie, LOGIN_COOKIE, loginCookie, readLoginState, sessionCookie } from "./session";

/**
 * Routes:
 *   GET/POST /authorize            MCP client authorization (consent, then GitHub)
 *   GET  /auth/github/callback     GitHub callback for the MCP flow
 *   GET  /login?next=/connect/...  Browser login for the /connect pages
 *   GET  /auth/github/callback/session  GitHub callback for browser login
 * Register `${PUBLIC_URL}/auth/github/callback` as the GitHub OAuth app callback URL; the
 * /session sub-path is allowed by GitHub because it sits under it.
 */

const mcpCallback = (app: App) => `${app.publicUrl}/auth/github/callback`;
const sessionCallback = (app: App) => `${app.publicUrl}/auth/github/callback/session`;

function consentPage(d: ConsentDescription, handle: string, gateway: string): string {
  const name = escapeHtml(d.clientName);
  const origin = d.clientDomain
    ? `Published by <strong>${escapeHtml(d.clientDomain)}</strong>.`
    : "This app registered itself; its name is not verified.";
  return `<h1>Allow ${name} to use ${escapeHtml(gateway)}?</h1>
<p>${origin} Access will be sent to <strong>${escapeHtml(d.redirectHost)}</strong>.</p>
${d.redirectIsLoopback ? '<p class="warn"><strong>This sends access to an app on your computer.</strong> Continue only if you just started connecting from it.</p>' : ""}
<p class="muted">You will sign in with GitHub next. Only accounts listed in a vault policy can finish.</p>
<form method="post">
<input type="hidden" name="handle" value="${escapeHtml(handle)}">
<button name="decision" value="approve">Allow</button><button name="decision" value="deny">Deny</button>
</form>`;
}

async function authorize(req: Request, app: App): Promise<Response> {
  const oauth = app.env.OAUTH_PROVIDER;
  if (req.method === "GET") {
    const request = await oauth.parseAuthRequest(req);
    const details = await oauth.describeConsent(request);
    const consent = await oauth.beginConsent(request);
    return htmlPage("Authorize", consentPage(details, consent.handle, new URL(app.publicUrl).host), 200, consent.headers);
  }
  if (req.method !== "POST") return new Response("Method not allowed", { status: 405 });

  const form = await req.formData();
  const handle = String(form.get("handle") ?? "");
  if (form.get("decision") !== "approve") {
    const denied = await oauth.denyConsent(req, handle);
    denied.headers.set("Location", denied.redirectTo);
    return new Response(null, { status: 302, headers: denied.headers });
  }
  const approved = await oauth.approveConsent(req, handle);
  const verifier = pkceVerifier();
  const { state, headers } = await oauth.beginUpstream(approved.request, { data: { verifier }, headers: approved.headers });
  headers.set(
    "Location",
    githubAuthorizeUrl({ clientId: app.env.GITHUB_CLIENT_ID, redirectUri: mcpCallback(app), state, codeChallenge: await pkceChallenge(verifier) }),
  );
  return new Response(null, { status: 302, headers });
}

async function mcpGithubCallback(req: Request, app: App): Promise<Response> {
  const oauth = app.env.OAUTH_PROVIDER;
  const url = new URL(req.url);
  const { request, data, headers } = await oauth.finishUpstream<{ verifier: string }>(req);
  if (url.searchParams.get("error") || !url.searchParams.get("code")) {
    headers.set("Location", authorizationErrorRedirect(request, "access_denied"));
    return new Response(null, { status: 302, headers });
  }
  const email = await githubVerifiedEmail({
    clientId: app.env.GITHUB_CLIENT_ID,
    clientSecret: app.env.GITHUB_CLIENT_SECRET,
    code: url.searchParams.get("code")!,
    redirectUri: mcpCallback(app),
    codeVerifier: data.verifier,
  });
  if (!isKnownUser(email, await app.registry.getAll())) {
    log("warn", "auth.denied", { reason: "email not in any policy" });
    return notAuthorizedPage();
  }
  const { redirectTo } = await oauth.completeAuthorization({
    request,
    userId: email,
    metadata: { label: email },
    scope: request.scope,
    props: { email },
    revokeExistingGrants: false,
  });
  log("info", "auth.authorized", { caller: email, client: request.clientId });
  headers.set("Location", redirectTo);
  return new Response(null, { status: 302, headers });
}

/** Only same-site paths under /connect/ are valid post-login destinations. */
function safeNext(next: string | null): string {
  return next && /^\/connect\/[a-z0-9_]+\/[a-z0-9_]+$/.test(next) ? next : "/";
}

async function login(req: Request, app: App): Promise<Response> {
  const next = safeNext(new URL(req.url).searchParams.get("next"));
  const state = randomState();
  const verifier = pkceVerifier();
  const headers = new Headers({ "Set-Cookie": await loginCookie(app.ring, { state, verifier, next }), "Cache-Control": "no-store" });
  headers.set(
    "Location",
    githubAuthorizeUrl({ clientId: app.env.GITHUB_CLIENT_ID, redirectUri: sessionCallback(app), state, codeChallenge: await pkceChallenge(verifier) }),
  );
  return new Response(null, { status: 302, headers });
}

async function sessionGithubCallback(req: Request, app: App): Promise<Response> {
  const url = new URL(req.url);
  const pending = await readLoginState(req, app.ring);
  const state = url.searchParams.get("state") ?? "";
  if (!pending || !(await timingSafeEqualString(state, pending.state))) {
    return messagePage("Sign-in expired", "This sign-in link expired or was opened in another browser. Please start again.", 400);
  }
  const code = url.searchParams.get("code");
  if (!code) return messagePage("Sign-in cancelled", "GitHub sign-in was cancelled.", 400);
  const email = await githubVerifiedEmail({
    clientId: app.env.GITHUB_CLIENT_ID,
    clientSecret: app.env.GITHUB_CLIENT_SECRET,
    code,
    redirectUri: sessionCallback(app),
    codeVerifier: pending.verifier,
  });
  if (!isKnownUser(email, await app.registry.getAll())) return notAuthorizedPage();
  const headers = new Headers({ Location: pending.next, "Cache-Control": "no-store" });
  headers.append("Set-Cookie", await sessionCookie(app.ring, email));
  headers.append("Set-Cookie", clearCookie(LOGIN_COOKIE));
  return new Response(null, { status: 302, headers });
}

/** Returns a response for auth routes, or undefined when the path is not an auth route. */
export async function handleAuthRoute(req: Request, app: App, path: string): Promise<Response | undefined> {
  try {
    if (path === "/authorize") return await authorize(req, app);
    if (req.method !== "GET") return undefined;
    if (path === "/auth/github/callback") return await mcpGithubCallback(req, app);
    if (path === "/login") return await login(req, app);
    if (path === "/auth/github/callback/session") return await sessionGithubCallback(req, app);
    return undefined;
  } catch (e) {
    if (e instanceof AuthorizationError && e.redirectTo) return Response.redirect(e.redirectTo, 302);
    if (e instanceof AuthorizationError) return messagePage("Authorization failed", e.description ?? "This request is no longer valid. Please start again.", 400);
    if (e instanceof CimdFetchError) return messagePage("Authorization failed", "This app could not be verified.", 400);
    log("error", "auth.error", { path, error: errorInfo(e) });
    return messagePage("Sign-in failed", "Something went wrong while signing in. Please try again.", 500);
  }
}
