#!/bin/sh
# Download the latest stable release's installer for one package format and OpenWrt
# architecture into an empty directory, beside its line of the release's SHA256SUMS. A
# release without that installer (an architecture or format added since) leaves the
# directory empty, and the install test skips the upgrade from it.
set -eu
format=${1:?ipk or apk}; arch=${2:?OpenWrt package architecture}; output=${3:?empty directory}
base=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
. "$base/retry.sh"
case "$format" in ipk|apk) ;; *) echo "Unknown package format: $format" >&2; exit 2;; esac
case "$arch" in ''|*[!a-z0-9_-]*) echo "Invalid package architecture: $arch" >&2; exit 2;; esac
[ -d "$output" ] && [ -z "$(ls -A "$output")" ] || { echo "Expected an empty directory: $output" >&2; exit 2; }
releases=https://github.com/openweir/openwrt/releases
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
trap 'exit 1' INT TERM
fetch() { curl -fsSL --proto '=https' --proto-redir '=https' --connect-timeout 20 --max-time "$1" --max-filesize "$2" -o "$3" "$4"; }
# GitHub redirects /releases/latest to the newest release that is neither a draft nor a
# pre-release. The page needs no token, and has no API rate limit to share with other jobs.
latest() {
 _latest=$(curl -fsSIL --proto '=https' --proto-redir '=https' --connect-timeout 20 --max-time 60 \
  -o /dev/null -w '%{url_effective}' "$releases/latest") || return 1
 printf '%s\n' "$_latest"
}
url=$(retry latest)
tag=${url##*/}
if [ "$url" != "$releases/tag/$tag" ] || ! printf '%s\n' "$tag" | grep -Eqx 'v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)'; then
 echo "Unexpected latest release page: $url" >&2; exit 1
fi
retry fetch 60 65536 "$work/SHA256SUMS" "$releases/download/$tag/SHA256SUMS"
# The release names follow internal/release PackageName: the revision follows the last preview.
version=$(printf '%s' "${tag#v}" | sed 's/\./\\./g')
case "$format" in
 ipk) pattern="luci-app-openweir_$version-[1-9][0-9]*_$arch\\.ipk" ;;
 apk) pattern="luci-app-openweir-$version-r[1-9][0-9]*_$arch\\.apk" ;;
esac
count=$(grep -Ec "^[0-9a-f]{64}  $pattern\$" "$work/SHA256SUMS" || true)
case "$count" in
 0) echo "Release $tag has no $format package for $arch: skipping the upgrade from the latest release" >&2; exit 0 ;;
 1) ;;
 *) echo "Release $tag lists $count $format packages for $arch" >&2; exit 1 ;;
esac
line=$(grep -E "^[0-9a-f]{64}  $pattern\$" "$work/SHA256SUMS")
name=${line#*  }
# A truncated or corrupted copy is downloaded again.
download() {
 fetch 300 268435456 "$work/$name" "$releases/download/$tag/$name" &&
  (cd "$work" && printf '%s\n' "$line" | sha256sum -c -)
}
retry download
mv "$work/$name" "$output/$name"
printf '%s\n' "$line" > "$output/SHA256SUMS"
echo "Downloaded $name from $tag, matching the release's SHA256SUMS" >&2
