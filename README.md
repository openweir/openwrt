# OpenWeir for OpenWrt

[中文说明](README.zh-CN.md) · [Releases](https://github.com/openweir/openwrt/releases/latest)

A LuCI app that turns an OpenWrt router into a transparent proxy for the whole network, powered by the OpenWeir fork of [mihomo](https://github.com/openweir/mihomo). It manages subscriptions, the core, DNS and the firewall, and picks sensible defaults automatically instead of exposing dozens of switches.

## Features

- Provider accounts, subscription URLs and local files in any common format (Clash, sing-box, Surge, Quantumult X, share links and more), converted by [subconv](https://github.com/openweir/subconv)
- Built-in routing rules (from dler-io/Rules, updated daily) for subscriptions without rules or whose rules don't convert well
- Smart (rule-based) or global mode, per-device routes, custom rules, automatic node failover
- TProxy or TUN, chosen automatically, on fw4 or fw3, with IPv6
- DNS protection with Fake-IP, plus optional mainland China direct (lists updated weekly)
- Follows network changes, works as a side router, and restores its firewall rules if they are wiped
- Falls back to direct when the proxy fails; stopping or uninstalling always restores the network
- Verified mihomo core downloads with rollback

## Requirements

- OpenWrt 23.05 / 24.10 (`.ipk`) or 25.12 (`.apk`)
- x86, ARM, MIPS, RISC-V 64 or LoongArch64
- 256 MiB RAM with 128 MiB flash, or 512 MiB RAM with 64 MiB flash
- fw4 recommended; on fw3 the router's own traffic, Fake-IP and the China IP shortcut are unavailable

## Installation

Download the package for your architecture (`grep DISTRIB_ARCH /etc/openwrt_release`) from the [latest release](https://github.com/openweir/openwrt/releases/latest), check its SHA-256, then:

```sh
opkg install ./luci-app-openweir_*.ipk                          # 23.05 / 24.10
apk add --no-network --allow-untrusted ./luci-app-openweir-*.apk  # 25.12
```

Later updates install from LuCI with **检查更新** (Check for updates). Removing the package restores the direct network; run `openweird purge` first to also delete the downloaded core, subscriptions, rule sets and geodata, and the rule files you imported.

## Getting started

1. Open **Services → OpenWeir**; the first-use dialog prepares the core.
2. Add a subscription under **订阅** (Subscriptions).
3. Start the proxy on **概览** (Overview).

If the start is refused, **检查运行环境** (Check environment) tells you why.

## FAQ

**Can it run with OpenClash, PassWall or HomeProxy?** No. OpenWeir stops them and disables their autostart when it starts. Anything they leave behind that it cannot remove is listed in the start error.

**AdGuard Home or SmartDNS?** While DNS protection is on, they are set aside as dnsmasq's upstream and restored afterwards. Turn DNS protection off to keep them in charge.

**Side router (旁路由)?** Detected automatically. Point devices' gateway and DNS at it.

**My subscription has no rules, or some don't work.** Each subscription's **分流规则** (Routing rules) setting defaults to the subscription's own rules and switches to the built-in rules when it has none, has no final MATCH, or more than 10% can't be used. You can also always use the built-in rules.

**Something is wrong.** Check the **日志** (Logs) and **连接记录** (Connections) pages; **导出诊断** (Export diagnostics) saves a redacted report for an issue.

## Building

```sh
go test ./...
OPENWEIR_FEED_MODE=test OPENWEIR_PACKAGE_ARCH=aarch64_generic packaging/openwrt/build.sh 24.10.8 aarch64_generic "$(cat VERSION)" dist/feed/aarch64_generic
```

Development happens on `develop` (preview builds); `main` is released. See [packaging/openwrt/README.md](packaging/openwrt/README.md).

## License

[GPL-3.0](LICENSE). Bundled China rule sets © MetaCubeX ([meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat)).
