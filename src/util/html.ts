/** Headers for every HTML page the gateway renders. */
export const HTML_SECURITY_HEADERS: Record<string, string> = {
  "Content-Type": "text/html; charset=utf-8",
  "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
  "Cache-Control": "no-store",
};

export const escapeHtml = (value: string): string => value.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

const STYLE = `body{font:16px/1.5 system-ui,sans-serif;max-width:36rem;margin:4rem auto;padding:0 1rem;color:#1b1b1b;background:#fafafa}
h1{font-size:1.4rem}code{background:#eee;padding:0 .25rem;border-radius:3px}button{font:inherit;padding:.5rem 1rem;margin-right:.5rem;cursor:pointer}
.muted{color:#666;font-size:.9rem}.warn{background:#fff4e5;padding:.5rem .75rem;border-radius:4px}
@media (prefers-color-scheme:dark){body{background:#151515;color:#e8e8e8}code{background:#2a2a2a}.muted{color:#999}.warn{background:#3a2a10}}`;

/** Minimal page. `bodyHtml` must already be escaped by the caller. */
export function htmlPage(title: string, bodyHtml: string, status = 200, extra?: Headers): Response {
  const headers = new Headers(extra);
  for (const [k, v] of Object.entries(HTML_SECURITY_HEADERS)) headers.set(k, v);
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(title)}</title><style>${STYLE}</style></head><body>${bodyHtml}</body></html>`;
  return new Response(html, { status, headers });
}

export const messagePage = (title: string, message: string, status = 200, extra?: Headers): Response =>
  htmlPage(title, `<h1>${escapeHtml(title)}</h1><p>${escapeHtml(message)}</p>`, status, extra);

export const notAuthorizedPage = (): Response =>
  messagePage("Not authorized", "This account is not allowed to use this gateway.", 403);
