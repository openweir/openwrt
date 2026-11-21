# OpenWeir for OpenWrt

[中文说明](README.zh-CN.md)

Open **Services → OpenWeir** in LuCI to connect a provider account, add a subscription URL or import a local file. The OpenWeir fork of mihomo handles traffic. Account requests use `OpenWeir/<version> (OpenWrt)` to fetch Clash YAML with its nodes, policy groups, providers and ordered rules. External links default to `clash`; you can switch to `sing-box` or `OpenWeir`. Leave the name empty to use the subscription's own title, or its domain. The importer converts sing-box JSON and share links with the shared [subconv](https://github.com/openweir/subconv) converter, the same one the desktop app uses, and reports what it leaves out.

The router controls listeners, transparent proxying, the controller secret and DNS. Native rule providers support YAML, text and MRS. The installer includes verified mainland China IP and domain rules. Profiles using GEOIP or GEOSITE can reuse the pinned geographic databases after their first verified download.

Upgrades preserve accounts, subscription URLs and LuCI preferences. Remote sources refresh to create new snapshots. Reimport local files in **Subscriptions**. Check device and custom rule references to missing nodes before starting.

Open **Services → OpenWeir** for the first-use setup dialog. Each account refresh reads the signed-in user’s plan details. In `app` or `both` mode the router uses the authenticated configuration API. In `link` mode it downloads the freshly issued URL without forwarding account credentials. For older providers that omit the mode, the router uses the issued URL when present and the authenticated API otherwise.

Download one installer for your package manager. OpenWrt 23.05.6 and 24.10.8 use the universal IPK. OpenWrt 25.12.6 uses the universal APK. Each file contains the management programs for all supported CPU architectures. The installer reuses the firmware’s existing LuCI, procd and system commands. Verify the file’s SHA-256 against the official release before installing offline. Install the IPK with `opkg install ./<filename>.ipk` or the APK with `apk add --no-network --allow-untrusted ./<filename>.apk`. [Latest release and checksums](https://github.com/openweir/openwrt/releases/latest)

### Manual upgrade from an older Cortex-A53 APK

On a router with an earlier A53 package, use the offline upgrade below. It simulates the transaction and keeps any installed direct dependencies that APK would otherwise remove, including `ip-full` and `kmod-tun`. You can manage those packages independently after the upgrade. Set the first line to the new file you have verified.

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

### Removing and reinstalling

Removing the package (including `opkg install --force-reinstall`) restores direct networking and stops the service, but keeps downloaded kernels, subscriptions, provider accounts and rule sets for the next installation. To delete them as well, run `openweird purge` before removing the package.

## Build and test

From the repository root, run the following commands with Go and Docker installed.

```sh
go test -race ./...
go vet ./...
OPENWEIR_FEED_MODE=test OPENWEIR_PACKAGE_ARCH=aarch64_generic packaging/openwrt/build.sh 24.10.8 aarch64_generic "$(cat VERSION)" dist/feed/aarch64_generic
packaging/openwrt/install-test.sh 24.10.8 aarch64_generic dist/feed/aarch64_generic
```

The installer unpacks the management program for the local CPU. Each Release package is built for one OpenWrt architecture (`DISTRIB_ARCH`), so pick the one for the router (the release notes list every OpenWrt architecture). Allow free temporary space of about the package size plus 1 MiB, in addition to the installer if it is stored in `/tmp`. The installed program takes approximately 8–10 MiB, depending on the architecture. In LuCI, **Check for updates** uses the asset digest from the official GitHub Release to verify the versioned download before installation. [Packaging details](packaging/openwrt/README.md)

The capture method is chosen automatically: TProxy where the firewall supports it, TUN otherwise. The environment check in LuCI identifies the active firewall and any missing capabilities. TProxy uses transparent proxy support in nftables on fw4 or iptables-legacy on fw3, including IPv6 when the router has an IPv6 uplink. TUN requires a working TUN device. Firmware-provided drivers, compatible iproute2 commands, BusyBox file locks and dnsmasq-full are supported.

DNS protection keeps dnsmasq in charge of local names and forwards upstream queries to mihomo. Like OpenClash, it also redirects TCP and UDP port 53 queries that devices on the selected LANs send to other resolvers. On fw3, IPv6 interception also needs `ip6tables-mod-nat`. Stopping the service restores the original upstream and removes the redirection.

The core resolves mainland China names through domestic DoH and every other name through encrypted DNS sent over the proxy, so poisoned answers never reach the routing decision. Edit both lists under **DNS** on the overview. On fw4, DNS protection uses Fake-IP (on fw3, where the router's own traffic is not captured, the core answers real addresses), and the core answers no AAAA records, so devices reach proxied names over IPv4. The core always dials the sniffed domain, blocks QUIC that may be proxied so browsers use TCP (direct devices and mainland names keep QUIC), and uses concurrent dialing and unified delay. On fw4 the router's own traffic follows the same rules. Time sync (NTP) always stays direct. These are fixed recommended settings with no switches.

Networks the router is attached to, including LAN and WAN subnets and delegated IPv6 prefixes, always stay direct and are refreshed when an interface changes. On fw4, **Mainland China IPs direct** can also send mainland China IPs straight past the core; it is off by default, and with Fake-IP it only covers connections made to an IP address.

LAN lookups reach the core through dnsmasq, which still answers local names such as `.lan`. As in OpenClash, dnsmasq caches nothing during the takeover and its cache size is restored afterwards. An include or cache setting left behind by a crash or an interrupted upgrade is cleaned up automatically the next time the service starts or stops.

Changing the routing mode, subscription, rules, groups or failover reloads the running core in place. Changes to DNS, LAN networks or the kernel, or an IPv6 uplink appearing or going away, restart the takeover.

Domain-specific dnsmasq upstreams, such as an internal resolver for a company domain, can coexist with DNS protection. If a managed instance has an explicit default upstream, a dynamic server list or a configuration directory shared with an unmanaged instance, the environment check identifies the conflict. With fail-open enabled, the watchdog restores direct DNS when repeated checks of the local mihomo DNS listener fail.

OpenWrt manages the system clock. If the clock falls outside a certificate's validity period, LuCI shows the router's verification time and the certificate dates. After the clock returns within that period, OpenWeir retries the affected subscription refresh or initial core download. Manual core selection takes precedence.

## Managing the router

The procd service starts the manager and a separate network recovery process. The administrative interface is available through the ACL-protected `openweir` ubus object. To check the service and the installed core on a test router, run the following commands.

```sh
ubus call openweir status
ubus call openweir kernel_read '{"action":"status"}'
ubus -v list openweir
```

## Installing and switching mihomo

Core releases come from [openweir/mihomo](https://github.com/openweir/mihomo/releases). The installer matches the router CPU and ABI and verifies the upstream SHA-256 for files from GitHub, HTTPS mirrors and manual uploads. Automatic preparation checks for a compatible stable release. If upstream only offers a prerelease, open kernel management to check the available builds. Naive availability depends on the selected binary.

When a subscription is configured, the candidate executable checks the generated router configuration before it can be selected. A stopped service stays stopped. A running switch requires 3 seconds of healthy local control, proxy and enabled DNS checks. Double-slot storage retains the last confirmed version for rollback.

On ARM64, the published `Prerelease-Alpha` build at `2ca4a53` accepted Snell v6 and AnyTLS with REALITY in its configuration check and rejected Naive and Nowhere. The locally built static core at `15fb245e` also accepted Nowhere. The router checks the selected artifact’s capabilities when displaying nodes. These results cover configuration parsing on that architecture.
