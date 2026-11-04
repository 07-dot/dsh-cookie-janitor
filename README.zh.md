# dsh-cookie-janitor

[English](README.md) | 中文

一个 [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) 插件：在 `Cookie` 请求头
触到 Node 的 16 KiB 上限之前，把失效的 `dsh-auth-*` 登录 Cookie 过期掉——一旦越过那条线，HTTP
解析器会在任何路由、handler 或插件跑起来之前直接返回 `431 Request Header Fields Too Large`。

## 它解决的问题

`@deepseek-ai/dsh-client-connection` 按**请求 authority** 铸造浏览器 Cookie：

```
dsh-auth-<base64url(sha256("host:port"))> = v1.<payload>.<hmac>
  ; Max-Age=2592000; Path=/; HttpOnly; SameSite=Strict
```

名字里嵌着 authority，寿命 30 天（`cookieMaxAgeDays`，默认 30），而这个包**从不发送删除**——根本
没有清理路径。Cookie 又是**按 host 存、不按端口隔离**的，所以浏览器在 30 天内用过的每一个
`dsh web` 端口，都会在 `127.0.0.1` 的同一个 jar 里多留一条 `dsh-auth-*`。

单条约 226 字节。解析器的上限是 16 KiB 请求头：实测 `Cookie` 头 16 400 字节返回 431，16 200 字节
仍能到达应用。也就是说大约 69 条累积的 Cookie 就足以把界面锁死，而一旦发生，界面里的任何操作都
救不回来——每个请求都在路由之前就死了。

## 安装

```sh
dsh plugin add dsh-cookie-janitor
```

直接从本仓库安装：

```sh
dsh plugin add github:07-dot/dsh-cookie-janitor
```

如果你的宿主不会热加载插件，装完重启 `dsh web`（或桌面端）。

## 它做什么

激活时，插件在监听中的 `http.Server` 上 `prependListener('request')` 挂一个监听器。对每个带着
`dsh-auth-*` 的请求，它量一下 `Cookie` 头；一旦 jar 越过预算，就对**不属于本次请求 authority**
的每一条追加

```
Set-Cookie: <name>=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Strict
```

从最旧的开始，保留 `retain` 条。浏览器在收到该响应时把这些条目清出 jar。请求本身仍由原流程应答：
这个钩子只设置响应头，从不写响应，所以路由、鉴权、SPA fallback 都不受影响。

## 配置

```yaml
- id: cookie-janitor
  name: dsh-cookie-janitor
  config:
    maxCookies: 8        # 超过这么多条 dsh-auth Cookie 就清理
    maxHeaderBytes: 4096 # Cookie 头超过这么多字节就清理
    retain: 2            # 清理后保留的条数，含本次请求 authority 自己的那条
    dryRun: false        # 只记录将要清理什么，不发删除头
```

只有超过预算才动手，所以「每个活着的实例一条 Cookie」的 jar 永远不会被动。同一 host 上多个
authority 同时活着（比如桌面端加上 3080 端口的 `dsh web`）也能正常用到预算为止；之后再清理的是
最旧的条目，被清掉的实例重新打开它打印的地址即可重新登录。

## 手动抢救

`GET /__dsh-cookie-janitor` 会把本次请求携带的每一条 `dsh-auth-*` 都过期掉，并打印观测统计（最大
`Cookie` 头、最多条数、累计清理数）。jar 已经用不了的时候，用持有这些 Cookie 的同一个浏览器打开
它，然后重新打开 DSH 地址。

## 什么时候不需要它

桌面端不会累积这些 Cookie：主窗口通过 `dsh-app://app/` 协议处理器和 Host 通信，只转发 shell
内存里的那一条 Cookie，并且把 `set-cookie` 拦在页面 jar 之外（按 DSH 0.2.1-rc.5 的代码核对过）。
真正会踩到的是在真实浏览器里跑的 `web` profile——jar 跨它在 Cookie 生命周期内用过的所有端口共享。
没有可清理的东西时这个插件是空转的：不越预算就不发任何头。

如果 `Cookie` 头大在别的地方（不是 `dsh-auth-*`），它也帮不上忙；那些条目是刻意不碰的。

## 环境要求

- DSH `0.2.1-rc.1` 或更新的同一 0.2.x 版本线（`engines.dsh`）。
- 无运行时依赖、无构建步骤、无安装脚本。

## 开发

```sh
npm test
```

用例直接驱动真实的 `apply()`，用假的 context 和假的响应验证：预算门控、`retain`、仅字节超限时
清理、`dryRun`、同一响应重复挂载、抢救路由、authority 匹配、配置归一化。

## 许可证

MIT
