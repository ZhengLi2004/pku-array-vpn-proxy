# 接口与认证协议

## SOCKS5 用户接口

| 项目 | 值 |
|---|---|
| 传输 | TCP |
| 地址 | `127.0.0.1:11080` |
| DNS | 客户端必须使用 SOCKS5 hostname/远端解析 |
| 鉴权 | 无 |
| UDP/IPv6 | 不支持 |

## Secret 文件接口

`array-auth` 启动时读取四个 UTF-8 单行文件：

| 文件 | 约束 |
|---|---|
| `vpn_username` | 非空，不能包含换行或 NUL |
| `vpn_password` | 非空，不能包含换行或 NUL |
| `id_card_last6` | `[0-9]{5}[0-9Xx]` |
| `phone_missing4` | `[0-9]{4}` |

目录权限为 `0700`，文件权限为 `0600`。

## iSecSP 认证组件适配接口

固定参数：

| 项目 | 值 |
|---|---|
| Host/SNI | `arrayvpn.pku.edu.cn:443` |
| 认证方法 | `北京大学VPN` |
| 方法类型 | RADIUS（值 `2`） |
| 候选地址 | supervisor 本轮传入的公开 IPv4 |
| 证书 | 发送凭据前验证同一 TLS 连接的 SPKI pin |
| 主认证 | 每个 worker 最多一次 |
| 补充挑战 | 最多两次，只允许身份证后 6 位和缺位电话 4 位 |
| 总超时 | 120 秒 |

成功结果由组件 Cookie API 返回唯一、非占位且语法有效的：

```text
ANsession<suffix>=<opaque-value>
```

## Loopback IPC

传输为共享网络命名空间内的 TCP `127.0.0.1:10981`。多字节整数使用网络字节序。

请求固定为 16 字节：

| 偏移 | 长度 | 字段 |
|---:|---:|---|
| 0 | 8 | magic：`PKUAUTH1` |
| 8 | 1 | version：`1` |
| 9 | 1 | operation |
| 10 | 2 | reserved：`0` |
| 12 | 4 | candidate IPv4 |

operation：

| 值 | 含义 |
|---:|---|
| 1 | authenticate |
| 2 | health |
| 3 | invalidate cached Cookie |

响应头固定为 16 字节：

| 偏移 | 长度 | 字段 |
|---:|---:|---|
| 0 | 8 | magic：`PKUAUTH1` |
| 8 | 1 | version：`1` |
| 9 | 1 | status |
| 10 | 2 | reason |
| 12 | 4 | payload length |

status：`0` 成功、`64` 永久失败、`75` 瞬时失败。
只有成功的 authenticate 响应可以携带非空 payload。

reason 类型：

| 值 | 名称 |
|---:|---|
| 0 | `NONE` |
| 1 | `BAD_REQUEST` |
| 2 | `UNAVAILABLE` |
| 3 | `CONFIG` |
| 4 | `SECRET` |
| 5 | `SDK_INCOMPATIBLE` |
| 6 | `CERTIFICATE` |
| 7 | `METHOD` |
| 8 | `UNKNOWN_CHALLENGE` |
| 9 | `REPEATED_CHALLENGE` |
| 10 | `AUTH_REJECTED` |
| 11 | `AUTH_TIMEOUT` |
| 12 | `COOKIE` |
| 13 | `NETWORK` |
| 14 | `INTERNAL` |
| 15 | `RATE_LIMIT` |
| 16 | `MAUTH` |
| 17 | `METHOD_INPUT` |
| 18 | `METHOD_SELECTION` |
| 19 | `METHOD_STEPS` |
| 20 | `METHOD_SEQUENCE` |
| 21 | `METHOD_CALLBACK_ERROR` |
| 22 | `METHOD_BUFFER` |
| 23 | `METHOD_COUNT` |
| 24 | `METHOD_NAME` |
| 25 | `METHOD_INPUT_NULL` |
| 26 | `METHOD_INPUT_LENGTH` |
| 27 | `METHOD_OUTPUT_NULL` |
| 28 | `METHOD_OUTPUT_LENGTH_NULL` |
| 29 | `METHOD_OUTPUT_CAPACITY` |
