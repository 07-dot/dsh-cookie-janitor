# dsh-cookie-janitor

English | [中文](README.zh.md)

A [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) plugin that expires stale
`dsh-auth-*` sign-in cookies before the `Cookie` request header can reach Node's 16 KiB header
limit — the point where the HTTP parser answers `431 Request Header Fields Too Large` before any
route, handler, or plugin runs.

## The problem it fixes

`@deepseek-ai/dsh-client-connection` mints one browser cookie per request **authority**:

```
dsh-auth-<base64url(sha256("host:port"))> = v1.<payload>.<hmac>
  ; Max-Age=2592000; Path=/; HttpOnly; SameSite=Strict
```

The name embeds the authority, the lifetime is 30 days (`cookieMaxAgeDays`, default 30), and the
package never sends a deletion — there is no cleanup path at all. Cookies are **host-scoped, not
port-scoped**, so every port a browser has used for `dsh web` within those 30 days leaves one more
`dsh-auth-*` entry in the same jar for `127.0.0.1`.

One pair is about 226 bytes. The parser's limit is 16 KiB of request headers: in testing, a request
whose `Cookie` header was 16,400 bytes returned 431 while 16,200 bytes still reached the
application. Roughly 69 accumulated cookies are therefore enough to lock the GUI out, and once it
happens nothing in the GUI can recover the page — every request dies before routing.

## Install

```sh
dsh plugin add dsh-cookie-janitor
```

Directly from this repository:

```sh
dsh plugin add github:07-dot/dsh-cookie-janitor
```

Then restart `dsh web` (or the Desktop app) if your host does not hot-apply plugins.

## What it does

On activation the plugin prepends one `request` listener to the listening `http.Server`. For each
request carrying `dsh-auth-*` cookies it measures the `Cookie` header; once the jar crosses the
budget it adds

```
Set-Cookie: <name>=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Strict
```

for every cookie that is **not** the current request's own authority, oldest first, keeping
`retain` of them. The browser drains the jar on that response. The request itself is answered by
the normal pipeline: the hook only sets headers and never writes one, so routing, authentication,
and the SPA fallback are untouched.

## Configuration

```yaml
- id: cookie-janitor
  name: dsh-cookie-janitor
  config:
    maxCookies: 8        # prune past this many dsh-auth cookies
    maxHeaderBytes: 4096 # prune past this Cookie-header size
    retain: 2            # cookies kept after a prune, including the current authority's
    dryRun: false        # log intended prunes without sending deletions
```

Pruning only starts above the budget, so a jar holding one cookie per live instance is never
touched. Several live authorities on one host (Desktop plus `dsh web` on port 3080, say) keep
working until the jar crosses the budget; after that the oldest entries are the ones expired, and a
reaped instance signs in again from its printed URL.

## Manual rescue

`GET /__dsh-cookie-janitor` expires every `dsh-auth-*` cookie the request carries and prints the
observed statistics — largest `Cookie` header, most cookies seen, total pruned. Use it when a jar is
already unusable: open it in the same browser that holds the cookies, then reopen the DSH URL.

## When you do not need it

The Desktop app does not accumulate these cookies: its main window talks to the Host through the
`dsh-app://app/` protocol handler, which forwards exactly one cookie held in the shell's memory and
withholds `set-cookie` from the page jar (checked against DSH 0.2.1-rc.5). The exposure is the
`web` profile in a real browser, where the jar is shared across every port used within the cookie
lifetime. The plugin is harmless where it has nothing to prune — it emits no headers below the
budget.

It also cannot help with a `Cookie` header that is large for reasons other than `dsh-auth-*`
cookies; those are left alone deliberately.

## Requirements

- DSH `0.2.1-rc.1` or newer on the same 0.2.x line (`engines.dsh`).
- No runtime dependencies, no build step, no install scripts.

## Development

```sh
npm test
```

The suite drives the real `apply()` against a fake context and a fake response: budget gating,
`retain`, byte-only pruning, `dryRun`, duplicate-pass protection, the rescue route, authority
matching, and config normalization.

## License

MIT
