/**
 * GitHub OAuth, used only to learn who the user is: their verified primary email.
 * The GitHub token is used for one API call and then discarded.
 */

const USER_AGENT = "mcp-vault-gateway";

export function githubAuthorizeUrl(p: { clientId: string; redirectUri: string; state: string; codeChallenge: string }): string {
  const u = new URL("https://github.com/login/oauth/authorize");
  u.searchParams.set("client_id", p.clientId);
  u.searchParams.set("redirect_uri", p.redirectUri);
  u.searchParams.set("scope", "user:email");
  u.searchParams.set("state", p.state);
  u.searchParams.set("code_challenge", p.codeChallenge);
  u.searchParams.set("code_challenge_method", "S256");
  u.searchParams.set("allow_signup", "false");
  return u.toString();
}

export class GithubLoginError extends Error {
  override name = "GithubLoginError";
}

/** Exchange the code and return the user's verified primary email, lowercased. */
export async function githubVerifiedEmail(p: {
  clientId: string;
  clientSecret: string;
  code: string;
  redirectUri: string;
  codeVerifier: string;
}): Promise<string> {
  const tokenRes = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: { Accept: "application/json", "Content-Type": "application/json", "User-Agent": USER_AGENT },
    body: JSON.stringify({
      client_id: p.clientId,
      client_secret: p.clientSecret,
      code: p.code,
      redirect_uri: p.redirectUri,
      code_verifier: p.codeVerifier,
    }),
    signal: AbortSignal.timeout(10_000),
  });
  const token = (await tokenRes.json().catch(() => ({}))) as { access_token?: string; error?: string };
  if (!tokenRes.ok || !token.access_token) throw new GithubLoginError(`GitHub token exchange failed (${token.error ?? tokenRes.status})`);

  const emailsRes = await fetch("https://api.github.com/user/emails", {
    headers: { Authorization: `Bearer ${token.access_token}`, Accept: "application/vnd.github+json", "User-Agent": USER_AGENT },
    signal: AbortSignal.timeout(10_000),
  });
  if (!emailsRes.ok) throw new GithubLoginError(`GitHub emails request failed (${emailsRes.status})`);
  const emails = (await emailsRes.json()) as { email: string; primary: boolean; verified: boolean }[];
  const primary = emails.find((e) => e.primary && e.verified);
  if (!primary) throw new GithubLoginError("GitHub account has no verified primary email");
  return primary.email.toLowerCase();
}
