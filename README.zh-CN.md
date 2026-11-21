# OpenWeir for OpenWrt

[English](README.md)

在 LuCI 的「服务 → OpenWeir」中，可以登录服务商账户、添加外部订阅或导入本地文件。插件使用 OpenWeir 版 mihomo 处理流量。账户使用 `OpenWeir/<版本> (OpenWrt)` 请求 Clash YAML，保留节点、策略组、规则提供方和规则顺序。外部链接默认使用 `clash`，也可选 `sing-box` 或 `OpenWeir`。名称可留空，自动使用订阅自带的名称，没有时用域名。sing-box JSON 和分享链接在导入时由共享的 [subconv](https://github.com/openweir/subconv) 转换（与桌面端相同），转不了的内容在导入详情中列出。

路由器管理控制端口、DNS、透明代理和监听权限。原生规则提供方支持 YAML、text 和 MRS，安装包内含已校验的中国大陆域名及 IP 规则。使用 GEOIP 或 GEOSITE 的配置按需准备指定版本的地理数据库，校验通过后可复用。

从旧版升级后会保留账户、订阅地址和界面设置。远程来源重新拉取订阅，本地文件需在「订阅」中重新导入。请在启动前检查设备和自定义规则仍指向可用的出口。

首次打开「服务 → OpenWeir」时会弹出初始化引导。每次刷新账户订阅时，路由器都会读取本人套餐详情。服务商启用 `app` 或 `both` 时，使用登录 API 获取配置。启用 `link` 时，使用本次签发的链接下载，下载请求不携带账户凭据。旧版服务商省略入口模式时，有链接就使用链接，链接为空则使用登录 API。

按包管理器选择一个离线包即可。OpenWrt 23.05.6 和 24.10.8 使用通用 IPK，25.12.6 使用通用 APK。每个包都包含所有支持架构的管理程序。安装时会复用固件已有的 LuCI、procd 和系统命令，离线安装前可用发布页的 SHA-256 核对文件。IPK 使用 `opkg install ./文件名.ipk`，APK 使用 `apk add --no-network --allow-untrusted ./文件名.apk`。[下载与校验值](https://github.com/openweir/openwrt/releases/latest)

### 从旧版 Cortex-A53 APK 手动升级

已安装过旧 A53 包的路由器可用下面的命令离线升级。它先模拟这次升级，把 APK 原本会移除的旧版直接依赖一并保留，包括已安装的 `ip-full` 和 `kmod-tun`。这些组件之后可由管理员独立管理。将第一行改为已校验的新包路径。

```sh
file='./luci-app-openweir-<version>-r<revision>.apk'
local_apk() { LC_ALL=C apk --no-network --no-cache --repositories-file /dev/null add --allow-untrusted "$@"; }
plan=$(local_apk --simulate "$file") && (
  set -- "$file"
  for p in $(apk query --installed --fields depends --format json luci-app-openweir | jsonfilter -e '@[0].depends[*]') dnsmasq-full; do
    if printf '%s\n' "$plan" | grep -Fq " Purging $p ("; then set -- "$@" "$p"; fi
  done
  local_apk "$@"
)
```

### 卸载与重装

卸载插件（包括 `opkg install --force-reinstall`）会恢复直连并停止服务，但保留已下载的内核、订阅、服务商账户和规则集，重新安装后可直接使用。如需一并删除，请在卸载前运行 `openweird purge`。

## 构建与回归

在仓库根目录使用 Go 和 Docker 执行以下命令。

```sh
go test -race ./...
go vet ./...
OPENWEIR_FEED_MODE=test OPENWEIR_PACKAGE_ARCH=aarch64_generic packaging/openwrt/build.sh 24.10.8 aarch64_generic "$(cat VERSION)" dist/feed/aarch64_generic
packaging/openwrt/install-test.sh 24.10.8 aarch64_generic dist/feed/aarch64_generic
```

安装时会在临时目录展开架构载荷，再将匹配本机 CPU 的管理程序写入持久存储。每个正式版安装包对应一个 OpenWrt 架构（`DISTRIB_ARCH`），请按路由器架构下载（发布说明里列出了每个 OpenWrt 架构对应的包）。临时目录需预留约“安装包大小 + 1 MiB”；若安装包也在 `/tmp`，还需计入安装包本身。管理程序按架构约占 8–10 MiB。LuCI 的「检查更新」从官方 GitHub Release 读取对应文件的 SHA-256，核对下载内容后即可一键安装。[打包细节](packaging/openwrt/README.md)

运行模式自动选择：防火墙支持透明代理时用 TProxy，否则用 TUN。在概览的「检查运行环境」中可查看当前防火墙缺少的能力。TProxy 需要 fw4 的 nftables 或 fw3 的 iptables-legacy 支持透明代理，路由器有 IPv6 出口时也检查 IPv6 规则。TUN 模式需要可用的 TUN 设备。固件自带的驱动、兼容的 ip 命令、BusyBox 锁工具和 dnsmasq-full 均可直接使用。

开启「DNS 保护」后，dnsmasq 继续解析本地域名，并将上游查询交给 mihomo。和 OpenClash 一样，所选局域网设备发往其他 DNS 服务器的 TCP 和 UDP 53 查询也会统一交给网关解析。fw3 接管 IPv6 DNS 还需 `ip6tables-mod-nat`。停止服务后，路由器恢复原上游并移除重定向。

内核用国内 DoH 解析中国大陆域名，其余域名经代理走加密 DNS，被污染的结果不会影响分流。两组服务器可在概览的「DNS」卡片中管理。开启 DNS 保护时使用 Fake-IP，内核不返回 AAAA 记录，设备访问代理域名时使用 IPv4。内核始终按嗅探到的真实域名连接、屏蔽可能走代理的 QUIC 让浏览器改用 TCP（直连设备和大陆域名不受影响），并开启并发连接和统一延迟。在 fw4 上，路由器自身的流量也按规则分流。时间同步（NTP）始终直连。这些都是固定的推荐设置，无需配置。

路由器直连的网段（LAN、WAN 子网和下发的 IPv6 前缀）始终直连，接口变化时自动更新。在 fw4 上，「大陆 IP 直连」还可以让大陆 IP 在防火墙直接直连、不经内核；默认关闭，Fake-IP 模式下只对直接用 IP 发起的连接生效。

局域网的 DNS 请求经 dnsmasq 转发给内核，`.lan` 等本地域名仍由 dnsmasq 回答。和 OpenClash 一样，接管期间 dnsmasq 不缓存结果，停止后恢复原缓存设置。崩溃或升级中断留下的 dnsmasq 配置和缓存设置，会在下次启动或停止时自动清理。

切换代理模式、订阅、规则、分组或故障切换时，内核原地重载配置，不会断开。更改 DNS、局域网或内核，或 IPv6 出口出现或消失时会重新接管。

按域名指定的上游 DNS 可以继续使用，例如仅将公司域名交给内网 DNS 解析。受管的 dnsmasq 实例若有显式默认上游、动态上游列表，或与未接管实例共用配置目录，「检查运行环境」会指出冲突。启用「失败时回退直连」后，若连续探测到 mihomo 的本地 DNS 无法应答，守护进程会恢复直连 DNS。

路由器交给 OpenWrt 校时。若路由器时间超出证书有效期，LuCI 会显示核验时的路由器时间和证书起止日期。时间校正到有效期内后，OpenWeir 会重试受影响的订阅刷新或首次内核下载。手动选择的内核版本优先。

## 查看路由器状态

procd 分别监管管理进程与网络恢复进程。路由器管理员可以通过受 ACL 保护的 ubus 接口查看状态和可用操作。

```sh
ubus call openweir status
ubus call openweir kernel_read '{"action":"status"}'
ubus -v list openweir
```

## 安装与切换 mihomo

内核由 [openweir/mihomo](https://github.com/openweir/mihomo/releases) 独立发布。插件根据架构和 ABI 选择文件，用上游 SHA-256 核对来自 GitHub、HTTPS 镜像或手动上传的发行包。首次自动准备只选择兼容的稳定版。上游仅有测试版时，可在内核管理中查看测试版和匹配的架构。Naive 可用性取决于所选二进制的编译能力。

有订阅时，候选内核会先检查路由器实际生成的配置。停机选版后服务继续停机。运行中换版需要本机控制接口、代理监听和已启用的 DNS 检查连续通过 3 秒。双版本存储保留上一份已确认的内核用于回退。

在 ARM64 上实测，已发布的 `Prerelease-Alpha`（`2ca4a53`）能加载 Snell v6 和 AnyTLS + REALITY 配置，无法加载 Naive 或 Nowhere。固定提交 `15fb245e` 的本地静态版还能加载 Nowhere。这些结果来自配置校验；节点选择页会根据本机实际选用的内核标注可用性。
