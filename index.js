/**
 * dsh-cookie-janitor — Host half.
 *
 * DSH mints one browser cookie per request authority (`dsh-auth-<sha256(host:port)>`),
 * stamps it with a 30-day Max-Age, and never sends a deletion. A browser jar keeps every
 * authority it has talked to, and because a cookie is host-scoped (not port-scoped) one
 * `127.0.0.1` jar accumulates one `dsh-auth-*` entry per port ever used inside that
 * window. At roughly 226 bytes per entry, ~69 such cookies push the `Cookie` request
 * header past Node's 16 KiB header limit, where the HTTP parser answers 431 before any
 * route, handler, or plugin can run.
 *
 * This plugin watches the `Cookie` header of every request the Web server receives and,
 * once the header crosses a configurable budget, expires every `dsh-auth-*` cookie that
 * does not belong to the request's own authority — keeping the newest `retain` of them —
 * so the browser jar drains on the next response instead of starving the next launch.
 *
 * The hook is a `prependListener('request')` on the listening server: it only adds
 * `Set-Cookie` headers and never writes a response, so routing, auth, and the fallback
 * pipeline are untouched. `GET /__dsh-cookie-janitor` expires every cookie in the jar and
 * is the manual rescue for a jar that is already unusable.
 */

import { createHash } from 'node:crypto';

const COOKIE_PREFIX = 'dsh-auth-';
const CLEAR_PATH = '/__dsh-cookie-janitor';
const HOOK_MARK = '__dshCookieJanitor';

const DEFAULTS = {
  /** Prune once the browser sends more than this many `dsh-auth-*` cookies. */
  maxCookies: 8,
  /** Prune once the whole `Cookie` header exceeds this many bytes. */
  maxHeaderBytes: 4096,
  /** Cookies kept after a prune, including the current request's own. */
  retain: 2,
  /** Report what would be pruned without sending deletions. */
  dryRun: false
};

/** Clamp user config to usable values; `retain` may never exceed `maxCookies`. */
function normalizeConfig(config) {
  const raw = config !== null && typeof config === 'object' ? config : {};
  const count = (value, fallback, min) =>
    typeof value === 'number' && Number.isFinite(value) && value >= min ? Math.floor(value) : fallback;
  const maxCookies = count(raw.maxCookies, DEFAULTS.maxCookies, 1);
  return {
    maxCookies,
    maxHeaderBytes: count(raw.maxHeaderBytes, DEFAULTS.maxHeaderBytes, 256),
    retain: Math.min(count(raw.retain, DEFAULTS.retain, 1), maxCookies),
    dryRun: raw.dryRun === true
  };
}

/** Split a `Cookie` header into name/value pairs without general cookie decoding. */
function parseCookieHeader(raw) {
  const entries = [];
  for (const segment of raw.split(';')) {
    const at = segment.indexOf('=');
    if (at <= 0) continue;
    const name = segment.slice(0, at).trim();
    if (name.length === 0) continue;
    entries.push({ name, value: segment.slice(at + 1).trim() });
  }
  return entries;
}

/**
 * Read the signed payload of a `dsh-auth-*` value (`v<version>.<base64url json>.<sig>`).
 * The signature is not verified: this only orders and labels cookies the browser already
 * holds, and a value that does not decode is simply the oldest candidate.
 */
function decodePayload(value) {
  const parts = typeof value === 'string' ? value.split('.') : [];
  if (parts.length !== 3) return undefined;
  try {
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    if (payload === null || typeof payload !== 'object') return undefined;
    return {
      authority: typeof payload.authority === 'string' ? payload.authority : undefined,
      issuedAt: Number.isSafeInteger(payload.issuedAt) ? payload.issuedAt : undefined,
      expiresAt: Number.isSafeInteger(payload.expiresAt) ? payload.expiresAt : undefined
    };
  } catch {
    return undefined;
  }
}

/** The authority a request is addressed to, spelled exactly as the Host spells it. */
function requestAuthority(headers, secure) {
  const host = headers.host;
  if (typeof host !== 'string' || host.length === 0) return undefined;
  try {
    const url = new URL(`${secure ? 'https:' : 'http:'}//${host}`);
    return secure ? url.origin : url.host;
  } catch {
    return undefined;
  }
}

/** The cookie name the Host would mint for one authority. */
function cookieNameOf(authority) {
  const digest = createHash('sha256').update(authority).digest('base64url');
  return COOKIE_PREFIX + digest;
}

/** A `Set-Cookie` value that removes one cookie from the browser jar. */
function expiredCookie(name, secure) {
  const attributes = `${name}=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Strict`;
  return secure ? `${attributes}; Secure` : attributes;
}

/**
 * Choose the cookies to expire: never the request's own authority, then the oldest of the
 * rest, keeping `options.retain` cookies in total.
 * @param entries - `dsh-auth-*` pairs carrying a decoded `issuedAt`.
 * @param authority - the request's own authority, when the Host header was usable.
 * @param options - normalized config.
 * @returns the entries whose names should be expired, oldest first.
 */
function planExpired(entries, authority, options) {
  const own = authority === undefined ? undefined : cookieNameOf(authority);
  const protectedNames = new Set();
  if (own !== undefined && entries.some((entry) => entry.name === own)) protectedNames.add(own);
  const others = entries
    .filter((entry) => !protectedNames.has(entry.name))
    .map((entry) => ({ entry, issuedAt: typeof entry.issuedAt === 'number' ? entry.issuedAt : 0 }))
    .sort((left, right) => right.issuedAt - left.issuedAt);
  return others.slice(Math.max(0, options.retain - protectedNames.size)).map((candidate) => candidate.entry);
}

/** The browser-facing rescue page, also the plugin's only status surface. */
function rescuePage(state, entries) {
  const rows = entries
    .map((entry) => {
      const issued = typeof entry.issuedAt === 'number' ? new Date(entry.issuedAt).toISOString() : 'unknown';
      return `<li><code>${entry.name.slice(0, 20)}…</code> — issued ${issued}</li>`;
    })
    .join('');
  const observed =
    entries.length === 0
      ? '<p>This request carried no <code>dsh-auth-*</code> cookie, so there was nothing to clear.</p>'
      : `<p>Expired ${entries.length} <code>dsh-auth-*</code> cookie(s):</p><ul>${rows}</ul>`;
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Cookie Janitor</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body{font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif;margin:0;padding:48px 24px;background:#0f1115;color:#e6e8ee}
main{max-width:640px;margin:0 auto}h1{font-size:22px;margin:0 0 16px}p{margin:0 0 12px;color:#b6bccb}
ul{padding-left:20px;color:#b6bccb}code{font-family:ui-monospace,Consolas,monospace;color:#8ec5ff}
strong{color:#e6e8ee}
</style></head>
<body><main>
<h1>Cookie Janitor</h1>
${observed}
<p>Largest <code>Cookie</code> header seen: <strong>${state.maxBytes}</strong> B,
most <code>dsh-auth-*</code> cookies seen: <strong>${state.maxCount}</strong>,
pruned so far: <strong>${state.pruned}</strong>.</p>
<p>Reopen the URL printed by DSH (or restart the app) to sign in again.</p>
</main></body></html>`;
}

/**
 * Host activation: watch every request the Web server receives and register the rescue route.
 * @param ctx - Host plugin context with `webServer`.
 * @param config - row config; see {@link DEFAULTS}.
 */
export function apply(ctx, config) {
  const options = normalizeConfig(config);
  const logger = ctx.logger('cookie-janitor');
  const secure = () => ctx.webServer?.protocol === 'https:';
  const state = { maxBytes: 0, maxCount: 0, pruned: 0 };

  const hook = (req, res) => {
    try {
      if (res.headersSent || res[HOOK_MARK] === true) return;
      const raw = req.headers.cookie;
      if (typeof raw !== 'string' || raw.length === 0) return;
      const entries = parseCookieHeader(raw).filter((entry) => entry.name.startsWith(COOKIE_PREFIX));
      if (entries.length === 0) return;
      const bytes = Buffer.byteLength(raw);
      if (bytes > state.maxBytes) state.maxBytes = bytes;
      if (entries.length > state.maxCount) state.maxCount = entries.length;
      if (entries.length <= options.maxCookies && bytes <= options.maxHeaderBytes) return;
      for (const entry of entries) entry.issuedAt = decodePayload(entry.value)?.issuedAt;
      const doomed = planExpired(entries, requestAuthority(req.headers, secure()), options);
      if (doomed.length === 0) return;
      res[HOOK_MARK] = true;
      if (!options.dryRun) {
        const alreadySet = res.getHeader('set-cookie');
        const headers = Array.isArray(alreadySet) ? [...alreadySet] : alreadySet === undefined ? [] : [String(alreadySet)];
        for (const entry of doomed) headers.push(expiredCookie(entry.name, secure()));
        res.setHeader('set-cookie', headers);
      }
      state.pruned += doomed.length;
      const verb = options.dryRun ? 'would prune' : 'pruned';
      logger.warn(
        `${verb} ${doomed.length} stale dsh-auth cookie(s): ${entries.length} -> ${entries.length - doomed.length}, Cookie header ${bytes} B`
      );
    } catch (error) {
      try {
        logger.warn(`cookie-janitor skipped one request: ${error instanceof Error ? error.message : String(error)}`);
      } catch {
        /* logging must never fail a request */
      }
    }
  };

  ctx.effect(() => {
    let timer;
    let attached;
    const attach = () => {
      const server = ctx.webServer?.server;
      if (server === undefined || server === null || typeof server.prependListener !== 'function') {
        timer = setTimeout(attach, 50);
        if (typeof timer.unref === 'function') timer.unref();
        return;
      }
      attached = server;
      server.prependListener('request', hook);
      logger.info(
        `watching Web requests; prune past ${options.maxCookies} cookies or ${options.maxHeaderBytes} B, keep ${options.retain}`
      );
    };
    attach();
    return () => {
      if (timer !== undefined) clearTimeout(timer);
      if (attached !== undefined) attached.off('request', hook);
    };
  }, 'cookie-janitor: request hook');

  ctx.effect(
    () =>
      ctx.webServer.register({
        kind: 'exact',
        path: CLEAR_PATH,
        handler: (req, res) => {
          if (req.method !== 'GET' && req.method !== 'HEAD') {
            res.writeHead(405, { allow: 'GET, HEAD', 'cache-control': 'no-store' });
            res.end();
            return;
          }
          const raw = typeof req.headers.cookie === 'string' ? req.headers.cookie : '';
          const entries = parseCookieHeader(raw)
            .filter((entry) => entry.name.startsWith(COOKIE_PREFIX))
            .map((entry) => ({ ...entry, issuedAt: decodePayload(entry.value)?.issuedAt }));
          const headers = {
            'cache-control': 'no-store',
            'content-type': 'text/html; charset=utf-8',
            'referrer-policy': 'no-referrer'
          };
          if (entries.length > 0) headers['set-cookie'] = entries.map((entry) => expiredCookie(entry.name, secure()));
          res.writeHead(200, headers);
          res.end(req.method === 'HEAD' ? undefined : rescuePage(state, entries));
        }
      }),
    'cookie-janitor: clear route'
  );

  logger.info(`active; manual rescue at ${CLEAR_PATH}`);
}

export const inject = ['webServer'];

/** Exposed for the workspace test harness; the loader only reads `apply`/`inject`. */
export const internals = {
  CLEAR_PATH,
  DEFAULTS,
  normalizeConfig,
  parseCookieHeader,
  decodePayload,
  requestAuthority,
  cookieNameOf,
  expiredCookie,
  planExpired
};
