#!/bin/sh
# Build a native OpenWrt package in a disposable, version-matched official SDK.
set -eu
release=${1:?OpenWrt version}; arch=${2:?OpenWrt package arch}; version=${3:?plugin version}; output=${4:?output directory}
case "$release" in 23.05.6|24.10.8|25.12.6) ;; *) echo "unsupported OpenWrt: $release" >&2; exit 1;; esac
base=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
# The selected SDK supplies the native packaging tools.
# OPENWEIR_PACKAGE_ARCH builds the package for one OpenWrt architecture, as released;
# without it the output is a universal test package with every supported CPU.
"$base/runtime-abi" "$arch" >/dev/null
root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
(cd "$root" && go run ./cmd/openweir-release version "$version")
mode=${OPENWEIR_FEED_MODE:-production}
case "$mode" in test|production) ;; *) exit 1;; esac
tmp=$(mktemp -d)
clean() { rm -rf "$tmp"; }
trap clean EXIT
trap 'exit 1' INT TERM
mkdir -p "$tmp/pkg/usr/sbin" "$output"
[ -z "$(ls -A "$output")" ] || { echo 'Package output directory must be empty' >&2; exit 1; }
cp -R "$root/files/." "$tmp/pkg"
# Browsers cache LuCI's ES modules by URL, so each build versions them to load the new interface.
stamp="$version-${OPENWEIR_PACKAGE_REVISION:-1}${OPENWEIR_PACKAGE_PRERELEASE:+-p$OPENWEIR_PACKAGE_PRERELEASE}"
luci="$tmp/pkg/www/luci-static/resources"
find "$luci/openweir" -name '*.js' -exec sed -i -E "s#((from|import\\() *')(\\.\\.?/[^'?]+\\.js)'#\\1\\3?v=$stamp'#g" {} +
find "$luci/openweir" -name '*.css' -exec sed -i -E "s#url\\('(\\.\\.?/[^'?]+\\.css)'\\)#url('\\1?v=$stamp')#g" {} +
# L.resource() drops any path part with characters outside its whitelist, such as ? and =,
# so the version goes after the resolved URL.
sed -i -E "s#L\\.resource\\('openweir/(app\\.js|style\\.css)'\\)#L.resource('openweir/\\1') + '?v=$stamp'#g" "$luci/view/openweir/router.js"
grep -q "app.js') + '?v=" "$luci/view/openweir/router.js" && grep -q "style.css') + '?v=" "$luci/view/openweir/router.js"
(cd "$tmp/pkg/usr/share/openweir/rules" && sha256sum -c SHA256SUMS)
(cd "$root" && go run ./cmd/openweir-release rules --check-package "$tmp/pkg/usr/share/openweir/rules")
mkdir -p "$tmp/pkg/usr/share/licenses/luci-app-openweir"
install -m 644 "$root/LICENSE" "$tmp/pkg/usr/share/licenses/luci-app-openweir/LICENSE"
mkdir -p "$tmp/pkg/usr/libexec/openweir"
install -m 755 "$root/packaging/openwrt/package-update" "$tmp/pkg/usr/libexec/openweir/package-update"
install -m 755 "$root/packaging/openwrt/package-recovery" "$tmp/pkg/usr/libexec/openweir/package-recovery"
install -m 755 "$base/runtime-abi" "$tmp/pkg/usr/libexec/openweir/runtime-abi"
install -m 755 "$base/activate-runtime" "$tmp/pkg/usr/libexec/openweir/activate-runtime"
for cli in openweird openweir-kernel openweir-net openweir-subscription; do
 ln -s ../libexec/openweir/manager "$tmp/pkg/usr/sbin/$cli"
done
mkdir -m 1777 "$tmp/pkg/tmp"
payload="$tmp/pkg/tmp/openweir-package-payload"
mkdir -m 700 "$payload"
package_arch=${OPENWEIR_PACKAGE_ARCH:-}
revision=${OPENWEIR_PACKAGE_REVISION:-1}
# A develop build also emits preview/ with package revision <N> (version-rN) for the pre-release.
prerelease=${OPENWEIR_PACKAGE_PRERELEASE:-}
case "$prerelease" in ''|[1-9]|[1-9][0-9]|[1-9][0-9][0-9]|[1-9][0-9][0-9][0-9]) ;; *) echo 'Expected a preview number' >&2; exit 1;; esac
case "$revision" in 0*|*[!0-9]*|'') echo 'Expected a positive package revision' >&2; exit 1;; esac
[ -n "$package_arch" ] || [ "$revision" = 1 ] || { echo 'Release assets use revision 1' >&2; exit 1; }
if [ -n "$package_arch" ]; then
 abis=$("$base/runtime-abi" "$package_arch")
else
 abis=$("$base/runtime-abi" --list)
fi
for abi in $abis; do
 if [ -n "${OPENWEIR_RUNTIME_DIR:-}" ]; then
  metadata="$OPENWEIR_RUNTIME_DIR/$abi.build"
  test "$(sed -n '2p' "$metadata")" = "$version"
  test "$(sed -n '3p' "$metadata")" = "${OPENWEIR_MIHOMO_PUBLIC_KEY:-}"
  (cd "$OPENWEIR_RUNTIME_DIR" && head -1 "$abi.build" | sha256sum -c -)
  cp "$OPENWEIR_RUNTIME_DIR/$abi.gz" "$payload/$abi.gz"
 else
  "$base/build-runtime.sh" "$abi" "$version" "$payload"
  rm "$payload/$abi.build"
 fi
done
(cd "$payload" && sha256sum *.gz > SHA256SUMS)
(cd "$root" && go run ./cmd/openweir-release licenses "$tmp/pkg/usr/share/licenses/luci-app-openweir")
cp "$root/packaging/openwrt/sdk-package.sh" "$tmp/package.sh"
image="ghcr.io/openwrt/sdk:$arch-$release"
# A container would copy the entire SDK into an anonymous /builder volume.
# BuildKit reads the SDK layers in place and exports only the package feed.
docker buildx build --platform linux/amd64 --file "$base/package.Dockerfile" \
 --build-arg "SDK=$image" --build-arg "RELEASE=$release" --build-arg "ARCH=$arch" \
 --build-arg "VERSION=$version" --build-arg "REVISION=$revision" \
 --build-arg "PACKAGE_ARCH=$package_arch" --build-arg "FEED_MODE=$mode" --build-arg "PRERELEASE=$prerelease" \
 --output "type=local,dest=$output" "$tmp"
