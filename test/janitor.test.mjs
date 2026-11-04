import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { apply, internals } from '../index.js';

const b64 = (value) => Buffer.from(value).toString('base64url');

/** Build the cookie pair the Host mints for one authority. */
function mint(authority, issuedAt) {
  const name = 'dsh-auth-' + createHash('sha256').update(authority).digest('base64url');
  const payload = { version: 1, authority, issuedAt, expiresAt: issuedAt + 30 * 864e5 };
  const value = `v1.${b64(JSON.stringify(payload))}.${b64(Buffer.alloc(32, 7))}`;
  return { name, value, pair: `${name}=${value}` };
}

function makeRes() {
  const headers = new Map();
  return {
    headersSent: false,
    setHeader(name, value) {
      headers.set(name.toLowerCase(), value);
    },
    getHeader(name) {
      return headers.get(name.toLowerCase());
    },
    writeHead(status, extra) {
      this.headersSent = true;
      this.status = status;
      this.out = { ...(extra ?? {}) };
    },
    end(body) {
      this.body = body;
    },
    headers
  };
}

function boot(config) {
  const listeners = [];
  const routes = [];
  const logs = [];
  const server = {
    prependListener(event, fn) {
      if (event === 'request') listeners.unshift(fn);
    },
    off() {}
  };
  const ctx = {
    logger: () => ({
      info: (message) => logs.push(['info', message]),
      warn: (message) => logs.push(['warn', message]),
      error: (message) => logs.push(['error', message])
    }),
    effect: (fn) => {
      fn();
    },
    webServer: {
      protocol: 'http:',
      server,
      register(route) {
        routes.push(route);
        return () => {};
      }
    }
  };
  apply(ctx, config);
  assert.equal(listeners.length, 1, 'one request hook installed');
  return { hook: listeners[0], routes, logs };
}

const HOUR = 3600e3;
const base = Date.UTC(2026, 10, 4, 12, 0, 0);

// 1) Below budget: a single own cookie must never be touched.
{
  const { hook, logs } = boot({});
  const own = mint('127.0.0.1:53904', base);
  const res = makeRes();
  hook({ headers: { host: '127.0.0.1:53904', cookie: own.pair } }, res);
  assert.equal(res.getHeader('set-cookie'), undefined, 'healthy jar untouched');
  assert.equal(logs.filter(([kind]) => kind === 'warn').length, 0);
}

// 2) Nine cookies: prune down to `retain`, always keeping the request's own.
{
  const { hook, logs } = boot({});
  const own = mint('127.0.0.1:53904', base);
  const stale = Array.from({ length: 8 }, (_, index) => mint(`127.0.0.1:${40000 + index}`, base - (index + 1) * HOUR));
  const cookie = [own.pair, ...stale.map((entry) => entry.pair)].join('; ');
  const res = makeRes();
  hook({ headers: { host: '127.0.0.1:53904', cookie } }, res);
  const deletions = res.getHeader('set-cookie');
  assert.ok(Array.isArray(deletions), 'deletions emitted');
  assert.equal(deletions.length, 7, 'keeps own + one newest stale');
  const deletedNames = deletions.map((value) => value.slice(0, value.indexOf('=')));
  assert.ok(!deletedNames.includes(own.name), 'own cookie survives');
  assert.ok(!deletedNames.includes(stale[0].name), 'newest stale cookie retained');
  for (const value of deletions) {
    assert.match(value, /Max-Age=0/, 'deletion expires the cookie');
    assert.match(value, /Path=\//, 'deletion covers the path the Host used');
  }
  assert.equal(logs.filter(([kind]) => kind === 'warn').length, 1, 'one warning per pruned request');
}

// 3) Byte budget alone triggers a prune even with few cookies.
{
  const { hook } = boot({ maxCookies: 64, maxHeaderBytes: 2048, retain: 1 });
  const own = mint('127.0.0.1:53904', base);
  const fat = mint('127.0.0.1:9999', base - HOUR);
  const fatPair = `${fat.name}=${fat.value}${'A'.repeat(3000)}`;
  const res = makeRes();
  hook({ headers: { host: '127.0.0.1:53904', cookie: `${own.pair}; ${fatPair}` } }, res);
  const deletions = res.getHeader('set-cookie');
  assert.ok(Array.isArray(deletions) && deletions.length === 1, 'byte budget prunes');
  assert.ok(deletions[0].startsWith(fat.name), 'the oversized foreign cookie is the one dropped');
}

// 4) dryRun reports without touching the response.
{
  const { hook, logs } = boot({ dryRun: true });
  const pairs = Array.from({ length: 12 }, (_, index) => mint(`127.0.0.1:${50000 + index}`, base - index * HOUR).pair);
  const res = makeRes();
  hook({ headers: { host: '127.0.0.1:53904', cookie: pairs.join('; ') } }, res);
  assert.equal(res.getHeader('set-cookie'), undefined, 'dry run writes nothing');
  assert.ok(logs.some(([kind, message]) => kind === 'warn' && message.startsWith('would prune')));
}

// 5) Non-dsh cookies and duplicate hook passes are ignored.
{
  const { hook } = boot({});
  const res = makeRes();
  hook({ headers: { host: '127.0.0.1:53904', cookie: 'theme=dark; lang=zh' } }, res);
  assert.equal(res.getHeader('set-cookie'), undefined);

  const pairs = Array.from({ length: 10 }, (_, index) => mint(`127.0.0.1:${60000 + index}`, base).pair).join('; ');
  const first = makeRes();
  hook({ headers: { host: '127.0.0.1:53904', cookie: pairs } }, first);
  const snapshot = first.getHeader('set-cookie').length;
  hook({ headers: { host: '127.0.0.1:53904', cookie: pairs } }, first);
  assert.equal(first.getHeader('set-cookie').length, snapshot, 'second pass in the same response is a no-op');
}

// 6) The rescue route expires every dsh-auth cookie the request carries.
{
  const { routes } = boot({});
  const route = routes.find((candidate) => candidate.path === internals.CLEAR_PATH);
  assert.ok(route, 'rescue route registered');
  const pairs = Array.from({ length: 3 }, (_, index) => mint(`127.0.0.1:${70000 + index}`, base).pair).join('; ');
  const res = makeRes();
  route.handler({ method: 'GET', headers: { host: '127.0.0.1:53904', cookie: pairs } }, res);
  assert.equal(res.status, 200);
  assert.equal(res.out['set-cookie'].length, 3, 'every cookie expired');
  assert.match(res.body, /Cookie Janitor/);

  const head = makeRes();
  route.handler({ method: 'HEAD', headers: { host: '127.0.0.1:53904', cookie: pairs } }, head);
  assert.equal(head.body, undefined, 'HEAD sends no body');

  const post = makeRes();
  route.handler({ method: 'POST', headers: { host: '127.0.0.1:53904' } }, post);
  assert.equal(post.status, 405);
}

// 7) The Host's own authority spelling decides which cookie is protected.
{
  const { hook } = boot({ retain: 1, maxCookies: 1 });
  const own = mint('localhost:3080', base);
  const other = mint('127.0.0.1:3080', base);
  const res = makeRes();
  hook(
    { headers: { host: 'localhost:3080', cookie: [own.pair, `dsh-auth-${'b'.repeat(43)}=v1.${b64('{}')}.x`].join('; ') } },
    res
  );
  assert.equal(res.getHeader('set-cookie').length, 1, 'only the foreign entry is dropped');
  assert.ok(res.getHeader('set-cookie')[0].startsWith(`dsh-auth-${'b'.repeat(43)}`));
  assert.ok(own.name.length === 52);
  assert.ok(other.name.length === 52);
}

// 8) Config normalization is defensive.
{
  assert.deepEqual(internals.normalizeConfig(undefined), { maxCookies: 8, maxHeaderBytes: 4096, retain: 2, dryRun: false });
  assert.deepEqual(internals.normalizeConfig({ maxCookies: 4, retain: 9 }), {
    maxCookies: 4,
    maxHeaderBytes: 4096,
    retain: 4,
    dryRun: false
  });
  assert.equal(internals.normalizeConfig({ maxHeaderBytes: -5 }).maxHeaderBytes, 4096);
}

console.log('dsh-cookie-janitor: all checks passed');
