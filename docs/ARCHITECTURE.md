# 系统架构

本系统将 PKU Array VPN 转换为在宿主机 IPv4 回环发布的 TCP SOCKS5：

```text
Windows / WSL 应用
        │  SOCKS5 TCP，远端 DNS
        ▼
127.0.0.1:11080
        │  Docker 端口发布
        ▼
pku-array-vpn
  ocproxy ← OpenConnect 9.21 Array
        │            ▲
        │            │ ANsession（stdin）
        │      loopback IPC :10981
        │            ▲
        │            │
        └── 共享网络命名空间 ──── array-auth
                                    │
                                    └─ iSecSP 认证组件与隔离适配器
                                               │
                                               └─ SPKI-pinned HTTPS → PKU
```

| 组件 | 职责 |
|---|---|
| `pku-array-vpn` | 解析公开入口 IP、预检 SPKI、监督隧道、运行 OpenConnect 与 ocproxy |
| `array-auth` | 读取 secrets、调用本地 iSecSP 认证组件、缓存 `ANsession`、提供回环 IPC |
| authentication adapter | 限制组件的目标地址、证书、认证轮次、挑战类型、Cookie 与日志输出 |
| OpenConnect | 使用 Array 数据协议建立 TLS 隧道，并把网络参数传给 ocproxy |
| ocproxy | 把 OpenConnect 的 script-tun 接口转换为 TCP SOCKS5 |
| supervisor | 管理候选 IP、退避、健康状态与会话失效 |

## 容器与网络

`array-auth` 使用 `network_mode: service:pku-array-vpn`。两个服务共享容器网络命名空间，认证 IPC 监听其中的 `127.0.0.1:10981`。网络命名空间由
`pku-array-vpn` 持有；更新或重启时必须同步重启 `array-auth`。

Compose 发布项固定为：

```text
127.0.0.1:11080/tcp → pku-array-vpn:1080/tcp
```

## 凭据

四项 Docker secrets 只挂载到 `array-auth`：

```text
/run/secrets/vpn_username
/run/secrets/vpn_password
/run/secrets/id_card_last6
/run/secrets/phone_missing4
```

隧道容器不可见这些文件。
网关 Host 与 SNI 固定为 `arrayvpn.pku.edu.cn`。解析器通过 DoH 获取公开 IPv4，过滤
私有、保留和 Clash fake-IP 地址。认证适配器将组件连接绑定到 supervisor 选择的候选
IPv4，并在发送凭据前验证该连接的 SPKI pin。

## 生命周期

```text
starting → resolving → connecting → healthy
                 │          │          │
                 └─ transient ─→ backoff ─┘
                            │
                            └─ permanent → 等待人工修正并重启
```

sidecar 在内存中缓存成功 Cookie，使隧道启动阶段的瞬时错误不会再次认证；
曾健康的隧道结束后 supervisor 使缓存失效。新认证受最短间隔限制，永久错误锁存到容器重启。
隧道健康检查定期经 SOCKS5 使用远端 DNS 请求目标，连续达到失败阈值后才重连。

## 构建与发布结构

`Dockerfile` 构建 OpenConnect、哈希锁定的 ocproxy 与认证 IPC client，生成可以公开发布的隧道镜像。

`Dockerfile.isecsp-auth` 从用户提供、Git 忽略且哈希锁定的官方包中静态提取
`libvl3vpn.so` 与 `libisec.so`，并编译项目自带隔离适配器。

`scripts/build.sh` 默认构建两个服务，`--auth-only` 只构建本地认证镜像，`--check`
只执行版本、官方包哈希、镜像源和 Compose 预检。带 `vX.Y.Z` 的 Git 标签发布
`linux/amd64` 隧道镜像，并附带 SBOM、provenance 与 artifact attestation。

组件间的数据格式、状态码和认证事务见 [`AUTH_PROTOCOL.md`](AUTH_PROTOCOL.md)。
