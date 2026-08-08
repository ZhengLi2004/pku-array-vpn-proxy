# PKU Array VPN

该项目为北京大学 Array VPN 的本地代理实现，意在解决官方 VPN 客户端对网络环境的侵入修改问题，该项目于 Docker 中完成门户认证和
VPN 数据隧道，并向宿主机 IPv4 回环地址发布一个 TCP SOCKS5 端口：

```text
Windows / WSL 应用
        │  SOCKS5 TCP（远端 DNS）
        ▼
127.0.0.1:11080
        │  Docker 回环端口映射
        ▼
ocproxy ← OpenConnect 9.21 Array ← arrayvpn.pku.edu.cn
                    ▲
                    └─ 认证 sidecar 提供 ANsession
                       └─ 本地 iSecSP 认证组件
```

> [!IMPORTANT]
> 请遵守学校的信息系统使用规则，不要反复提交错误凭据到真实网关。

## 功能

支持 PKU 的 Array VPN 入口 `arrayvpn.pku.edu.cn`，用户接口固定为无鉴权 TCP SOCKS5 `127.0.0.1:11080`，SOCKS 侧只支持 IPv4 TCP。

认证 sidecar 复用用户自行取得、哈希锁定的官方 iSecSP 认证组件，构建过程静态提取 `libvl3vpn.so` 和 `libisec.so`。

需要可运行 Linux 容器的 Docker Engine 兼容 daemon，以及 Docker Compose v2.17.0 或更高版本。

## 快速开始

### 1. 检查 Docker Engine 与 Compose

在 WSL 中，仓库必须位于 Linux 文件系统，例如 `/usr/src/pku-array-vpn-proxy`。
初始化和运行命令应由同一个非 root 用户执行：

```bash
id -u
id -g
```

确认当前终端能够访问 Docker daemon：

```bash
docker version
docker compose version
```

### 2. 可选的构建镜像源

不配置镜像源时，构建使用上游 Alpine 仓库和当前 Docker daemon 的默认拉取策略。
网络受限时可从模板创建本机配置：

```bash
cp proxy.env.example proxy.env
```

`proxy.env` 被 Git 忽略，支持以下可选项：

- `ALPINE_MIRROR`：由项目传给 Docker 构建，用来替换 Alpine 包仓库；
- `UBUNTU_APT_MIRROR`：只供本地 iSecSP 兼容镜像替换 Ubuntu 包仓库；
- `UBUNTU_IMAGE`：兼容镜像的可选 digest-pinned Ubuntu 基础镜像引用，留空时使用
  `versions.env` 的上游锁定值；
- `DOCKERHUB_MIRROR`：仅记录由操作者在 daemon 侧配置的 Docker Hub mirror。

镜像地址必须是无凭据的 HTTPS URL。

### 3. 写入凭据

进入仓库后运行：

```bash
./scripts/init-secrets.sh
```

脚本会隐藏输入并创建四个 Git 忽略文件：

```text
secrets/vpn_username
secrets/vpn_password
secrets/id_card_last6
secrets/phone_missing4
```

目录权限为 `0700`，文件权限为 `0600`。`id_card_last6` 必须匹配
`[0-9]{5}[0-9Xx]`，`phone_missing4` 必须是四位数字。
脚本还会在 `.env` 中原子更新 `ARRAYVPN_UID` 和 `ARRAYVPN_GID`，并保留其中已有的健康检查等本机设置。

需要覆盖现有值时运行：

```bash
./scripts/init-secrets.sh --replace
```

已有 secrets、只需迁移或刷新运行身份时，不必重新输入凭据：

```bash
./scripts/init-secrets.sh --sync-runtime-id
```

### 4. 准备认证组件

从[北京大学官方 VPN 页面](https://its.pku.edu.cn/service_1_vpn2.jsp)下载
`iSecSP_ubuntu_2.4.0.deb`，然后导入：

```bash
./scripts/prepare-isecsp.sh /path/to/iSecSP_ubuntu_2.4.0.deb
```

脚本执行解包与 SHA-256 校验，。验证后的文件位于 Git 忽略且权限为 `0600` 的
`local/iSecSP_ubuntu_2.4.0.deb`。

该镜像包含专有库，只能按适用于你的授权在本机使用。

### 5. 构建或拉取隧道镜像

#### 全部从源码构建

执行：

```bash
make check-static
make compose-check
make build-check
make build
make post-build-check
```

`make build` 生成：

- `pku-array-vpn-proxy:local`：OpenConnect、ocproxy 与隧道监督器；
- `pku-array-vpn-auth:isecsp-local`：本机专有认证组件与开源隔离适配器。

只修改认证适配器时可以执行：

```bash
make auth-build
```

#### 使用预构建隧道镜像

预构建发布只包含可再分发的隧道镜像，认证镜像仍必须在本机生成。先执行：

```bash
make auth-build
```

然后在 `.env` 中添加明确版本号：

```dotenv
PKU_ARRAY_VPN_IMAGE=ghcr.io/zhengli2004/pku-array-vpn-proxy:v0.1.0
```

拉取隧道镜像并检查两个运行镜像：

```bash
docker compose pull pku-array-vpn
make post-build-check
```

预构建版本目前只提供 `linux/amd64`。

### 6. 启动

先记录宿主网络基线，再启动已经拉取或构建的镜像：

```bash
./scripts/network-snapshot.sh before
docker compose up -d --no-build --force-recreate
docker compose ps
docker compose logs --no-color --tail=200
```

等待两个服务都变为 `healthy`。正常隧道日志包含：

```text
state=healthy
```

此时唯一用户接口是：

```text
SOCKS5 127.0.0.1:11080
```

### 7. 验收

先确认 SOCKS 可建立 HTTPS 连接。必须使用 `--socks5-hostname`，让代理端解析域名：

```bash
curl --fail --show-error \
  --socks5-hostname 127.0.0.1:11080 \
  --head https://its.pku.edu.cn/service_1_vpn2.jsp
```

完整验收还需要一个你有权访问的真实校园目标。在 Git 忽略的
`local-acceptance.env` 中写入：

```bash
TEST_TARGET_HOST='your-campus-host.pku.edu.cn'
TEST_TARGET_PORT='22'
```

显式导入后运行：

```bash
set -a
source ./local-acceptance.env
set +a
make acceptance
./scripts/network-snapshot.sh after
./scripts/network-snapshot.sh compare
```

预期输出包含 `acceptance=ok` 和网络快照 `unchanged`。

## 使用 SOCKS5

支持 SOCKS5 hostname/远端 DNS 的程序可直接配置：

| 项目 | 值 |
|---|---|
| 类型 | SOCKS5 |
| 地址 | `127.0.0.1` |
| 端口 | `11080` |
| 用户名/密码 | 留空 |
| UDP | 关闭 |
| DNS | 远端解析 |

命令行示例：

```bash
curl --socks5-hostname 127.0.0.1:11080 https://your-campus-host/
```

## 接入 Clash / Mihomo

下面是最小示例：

```yaml
proxies:
  - name: PKU-Array
    type: socks5
    server: 127.0.0.1
    port: 11080
    udp: false

rules:
  - DOMAIN,arrayvpn.pku.edu.cn,DIRECT
  - DOMAIN,dns.alidns.com,DIRECT
  - DOMAIN,cloudflare-dns.com,DIRECT
  - DOMAIN-SUFFIX,pku.edu.cn,PKU-Array
  - MATCH,DIRECT
```

## 日常运维

查看状态和日志：

```bash
docker compose ps
docker compose logs -f --no-color
```

重新创建容器：

```bash
docker compose up -d --no-build --force-recreate
```

停止并删除运行容器：

```bash
make clean-runtime
```

证书 pin 变化时只查看候选证书：

```bash
docker compose exec pku-array-vpn \
  /usr/local/bin/inspect-certificates.sh
```

通过可信渠道人工核对新 SPKI，随后更新 `config/servercert-pins.txt` 并重新执行构建后检查和真实验收。

## DNS、TUN 与常见问题

- Windows TUN 可能影响 Docker 下载或容器到 PKU 的路由。出现 EOF、超时或自环时，
  关闭 TUN 后使用同一镜像复测；
- `Failed to open /dev/vhost-net` 是 ocproxy 的可选加速设备缺失，不影响当前用户态
  SOCKS5 路径；
- `docker` 不可用时，确认 daemon 已启动，并检查当前 Docker context、套接字权限或
  远程连接配置；

## 开发与测试

本地检查：

```bash
make check-static
make compose-check
make build-check
```

构建完成后：

```bash
make post-build-check
```

真实登录和校园目标连通性应由有权限的操作者在本机测试。

## 许可证与第三方组件

当前版本的项目自有代码采用 [Apache License 2.0](LICENSE)，版权声明见 [NOTICE](NOTICE)。OpenConnect、ocproxy、lwIP、iSecSP 组件和镜像内软件包仍受各自许可证约束；Apache-2.0
不覆盖用户提供的 iSecSP 包或从中提取的库，详见
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
