# OpenWeir for OpenWrt

[English](README.md) · [下载](https://github.com/openweir/openwrt/releases/latest)

把 OpenWrt 路由器变成全屋透明代理的 LuCI 插件，内核是 OpenWeir 版 [mihomo](https://github.com/openweir/mihomo)。订阅、内核、DNS 和防火墙都由插件管理，常用设置自动选好，不用一个个开关去调。

## 功能

- 支持服务商账户、订阅链接和本地文件，常见格式（Clash、sing-box、Surge、Quantumult X、分享链接等）都由 [subconv](https://github.com/openweir/subconv) 统一转换
- 订阅没有规则或规则转换不全时，自动使用内置分流规则（来自 dler-io/Rules，每日更新）
- 智能分流或全局代理，可按设备分流、自定义规则，节点失联自动切换
- 自动选择 TProxy 或 TUN，支持 fw4、fw3 和 IPv6
- DNS 保护（Fake-IP），可选大陆 IP 直连，国内列表每周自动更新
- 自动适应网络变化，支持旁路由，防火墙规则被清掉后自动恢复
- 代理异常时回退直连；停止或卸载后总能恢复原网络
- 内核下载经过校验，可回滚

## 要求

- OpenWrt 23.05 / 24.10（`.ipk`）或 25.12（`.apk`）
- x86、ARM、MIPS、RISC-V 64 或 LoongArch64
- 256 MiB 内存 + 128 MiB 闪存，或 512 MiB 内存 + 64 MiB 闪存
- 推荐 fw4；fw3 上不代理路由器自身流量，也没有 Fake-IP 和大陆 IP 直连

## 安装

先查架构（`grep DISTRIB_ARCH /etc/openwrt_release`），从[最新版本](https://github.com/openweir/openwrt/releases/latest)下载对应的包并核对 SHA-256，然后：

```sh
opkg install ./luci-app-openweir_*.ipk                          # 23.05 / 24.10
apk add --no-network --allow-untrusted ./luci-app-openweir-*.apk  # 25.12
```

之后在 LuCI 里点「检查更新」即可升级。卸载会自动恢复直连；如需同时删除已下载的内核和订阅，先运行 `openweird purge`。

## 快速上手

1. 打开「服务 → OpenWeir」，首次使用会自动准备内核。
2. 在「订阅」中添加订阅。
3. 回到「概览」启动代理。

启动被拒绝时，点「检查运行环境」查看原因。

## 常见问题

**能和 OpenClash、PassWall、HomeProxy 一起用吗？** 不能。检测到它们在运行时不会启动，请先停用。

**AdGuard Home、SmartDNS 怎么办？** 开启 DNS 保护期间，它们作为 dnsmasq 上游会被暂时摘下，停止后自动恢复。想继续用它们，关闭 DNS 保护即可。

**旁路由能用吗？** 能，会自动识别。设备的网关和 DNS 都要指向旁路由。

**订阅没有规则，或者部分规则用不了？** 每个订阅都有「分流规则」设置，默认用订阅自带的规则；订阅没有规则、缺少最后的 MATCH，或超过一成规则无法使用时，会自动改用内置规则。也可以设为始终使用内置规则。

**出问题了怎么办？** 「记录」页面有连接和日志，「导出诊断」可以生成去除隐私信息的报告，附在 issue 里。

## 构建

```sh
go test ./...
OPENWEIR_FEED_MODE=test OPENWEIR_PACKAGE_ARCH=aarch64_generic packaging/openwrt/build.sh 24.10.8 aarch64_generic "$(cat VERSION)" dist/feed/aarch64_generic
```

日常开发在 `develop`（发布预览版），`main` 用于正式发布。打包细节见 [packaging/openwrt/README.md](packaging/openwrt/README.md)。

## 许可证

[GPL-3.0](LICENSE)。内置的国内规则集来自 MetaCubeX 的 [meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat)。
