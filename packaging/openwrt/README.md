# SDK builds and feed tests

Build the universal opkg or apk installer with Go and the official OpenWrt SDK with Docker Buildx. Each installer embeds the management runtime for ten Linux CPU and ABI profiles. The installation script selects the runtime using the router's OpenWrt architecture, checks available space and installs the selected executable on the writable filesystem. The mihomo core has a separate lifecycle.

```sh
OPENWEIR_FEED_MODE=test packaging/openwrt/build.sh 24.10.8 x86_64 "$(cat VERSION)" dist/ipk
packaging/openwrt/install-test.sh 24.10.8 aarch64_generic dist/ipk
```

Test mode additionally prepares a baseline version to exercise the upgrade path. The main installer is the same artifact used for release. For a local build of the installer alone, use the default production mode. `DOCKER_CONTEXT` selects the Docker host and `OPENWEIR_TEST_ROOTFS` can select a matching prepared userland. Targets without a rootfs container use the official ImageBuilder. Set `OPENWEIR_RUNTIME_DIR` to reuse the ten outputs from `build-runtime.sh`.

Set `OPENWEIR_PACKAGE_ARCH=aarch64_cortex-a53` on the build and install test commands for a smaller local installer. This sets the package architecture and includes only its management executable. Pass the target architecture to the install test. Set OPENWEIR_PACKAGE_REVISION to increment the package-manager revision for another local build at the same plugin version. Public Release builds use the universal format.

The installation fixture first probes the target's own nft executable. When QEMU user-mode emulation rejects the netfilter socket, the fixture uses a native nft executable in the same disposable network namespace. The package manager, LuCI RPC, management service and removal hooks still run for the target architecture. Full-system firmware tests exercise the target's nft executable and kernel together.

The in-router updater reads the latest stable release from the official GitHub repository, matches the exact package name and tag, then verifies its size and SHA-256 before invoking the local package manager. APK uses `--allow-untrusted` for that local file. Run `/usr/libexec/openweir/package-update check` to inspect the installed and available versions. The `apply` command installs a newer verified package.

Before removing the package, run `/usr/sbin/openweird uninstall`. Proceed with the native package manager after the direct-network check succeeds. opkg aborts removal on a failed pre-uninstall hook. apk can still delete the installed files. In that case the hook starts a private retry process at `/tmp/openweir-recovery/retry`, with the network helper and its required binary dependencies. The worker restores owned routes, firewall rules and DNS, stops the service and discards expired state. The presence of `/tmp/openweir-recovery/pending` identifies recovery in progress. The APK regression holds the network lock until the manager is uninstalled, then verifies restoration with actual nftables and an owned dnsmasq include.

## Publish a version

The package includes two pinned MetaCubeX MRS rule providers. Update their digest, length and immutable source in `files/usr/share/openweir/rules/CATALOG`, `SOURCES` and `SHA256SUMS` together. Run `go run ./cmd/openweir-release rules` from the repository root to download and verify the files. The three on-demand geodata pins are in `GEODATA`. Package builds check both bundled files offline.

CI computes the next three-part version from the newest release tag and the conventional commits since it. A release takes the package revision after its last preview, so CI builds one package per OpenWrt architecture and format, named `luci-app-openweir_<version>-<revision>_<arch>.ipk` and `luci-app-openweir-<version>-r<revision>_<arch>.apk` and declaring that architecture, and passes those same files to every installation job for the matching architecture. CI also retains the candidates and their SHA-256 manifests. After **Router service CI** passes on the current commit, **Publish OpenWrt release** downloads the candidates from that exact run, checks the manifests, and uploads the 14 IPKs and 14 APKs to a GitHub draft. The publisher compares the remote asset digests before publishing. The release notes map every OpenWrt architecture to its package and list installation commands in English and Chinese with the hashes of all installers. The in-router updater picks the package for its own `DISTRIB_ARCH`. GitHub's release metadata is the trust source for in-router plugin updates.

Day-to-day work goes to `develop`; `main` holds what is to be released. After **Router service CI** passes on the newest `develop` commit, **Publish OpenWrt preview** uploads that run's tested installers as the pre-release `v<VERSION>-preview.<N>` (N counts from 1 for each version) with their SHA-256 manifest, and deletes the older preview with its tag, so exactly one preview exists. When `develop` and `main` point at the same commit, the develop CI run skips its checks and no preview is published. Previews keep `VERSION` inside the packages and the in-router updater never offers them.

A maintainer can rerun **Publish OpenWrt release** with the successful CI run ID while its artifacts are available. An interrupted draft resumes with the same files. First releases and version bumps use the same process.

The core is distributed separately by [openweir/mihomo](https://github.com/openweir/mihomo/releases). Plugin CI tests a fixed source revision. Published core assets have independent versions and per-architecture capabilities.
