#!/bin/sh
# Package-manager and uninstall checks inside fresh, disposable containers.
set -eu
release=${1:?firmware}; arch=${2:?package arch}; feed=${3:?directory with the package for this architecture}
rootfs=${OPENWEIR_TEST_ROOTFS:-openwrt/rootfs:$arch-$release}
base=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
response=$(mktemp)
release_tool=$(mktemp)
network= server= target= generated=
# Release packages declare their OpenWrt architecture (build.sh with OPENWEIR_PACKAGE_ARCH).
package_arch=$arch
cleanup() {
 rm -f "$response" "$release_tool"
 [ -z "$target" ] || docker rm -f "$target" >/dev/null
 [ -z "$server" ] || docker rm -f "$server" >/dev/null
 [ -z "$network" ] || docker network rm "$network" >/dev/null
 [ -z "$generated" ] || docker image rm "$generated" >/dev/null
}
trap cleanup EXIT
trap 'exit 1' TERM INT
(cd "$base/../.." && go build -o "$release_tool" ./cmd/openweir-release)
# Official rootfs manifests use the OpenWrt package architecture as the OCI platform.
target_platform=${DOCKER_DEFAULT_PLATFORM:-}
if [ -z "${OPENWEIR_TEST_ROOTFS:-}" ]; then target_platform=linux/$arch; fi
if ! docker image inspect "$rootfs" >/dev/null 2>&1 && ! DOCKER_DEFAULT_PLATFORM="$target_platform" docker pull "$rootfs"; then
 [ -z "${OPENWEIR_TEST_ROOTFS:-}" ] || exit 1
 generated=$(sh "$base/test-rootfs.sh" "$release" "$arch")
 rootfs=$generated
fi
network=$(docker network create openweir-pkg-test-$$)
server=$(docker create --network "$network" --network-alias feed busybox:1.37 httpd -f -p 8080 -h /srv)
docker cp "$feed/." "$server:/srv"
docker start "$server" >/dev/null
# The candidate package embeds the official URLs. Only the isolated router's
# test transport maps those exact URLs to the local server.
serve_release() {
 subtree=$1; shift
 asset=$("$release_tool" fake-latest "$feed$subtree" "$response" "$@")
 docker exec "$server" sh -ec '
  directory=/srv/releases/download/${1%/*}
  mkdir -p "$directory"
  ln -sf "/srv$2/${1##*/}" "$directory/${1##*/}"
 ' sh "$asset" "$subtree"
 chmod 644 "$response"
 docker cp "$response" "$server:/srv/releases/latest"
}
serve_release ""
target=$(DOCKER_DEFAULT_PLATFORM="$target_platform" docker create --network "$network" --cap-add NET_ADMIN -e "OPENWEIR_PACKAGE_ARCH=$package_arch" --entrypoint sh "$rootfs" -c 'while :; do sleep 600; done')
docker start "$target" >/dev/null
docker cp "$base/check-web.sh" "$target:/tmp/check-web"
docker cp "$base/check-installed.sh" "$target:/tmp/check-installed"
docker exec "$target" mkdir /tmp/verified-feed
case "$release" in
 25.*) set -- "$feed"/SHA256SUMS "$feed"/*.apk ;;
 *) set -- "$feed"/SHA256SUMS "$feed"/*.ipk ;;
esac
for item do docker cp "$item" "$target:/tmp/verified-feed/"; done
docker cp "$feed/baseline" "$target:/tmp/openweir-baseline"
docker exec "$target" sh /tmp/check-installed prepare "$release" "$arch"
sh "$base/test-nft.sh" "$target" "$release" "$arch"
docker network disconnect "$network" "$target"
test "$(docker inspect -f '{{len .NetworkSettings.Networks}}' "$target")" = 0
docker exec "$target" sh /tmp/check-installed offline-install
docker exec "$target" sh /tmp/check-web
docker exec "$target" sh /tmp/check-installed uninstall
docker network connect "$network" "$target"
echo "Verified offline single-package installation, all four commands and LuCI RPC on $release ($arch)"
# Keep the original release digest while changing the served download.
docker exec "$server" sh -c 'set -e; for f in /srv/*.ipk /srv/*.apk; do [ -f "$f" ] || continue; cp "$f" "$f.clean"; dd if=/dev/zero of="$f" bs=1 count=16 conv=notrunc 2>/dev/null; done'
docker exec "$target" sh /tmp/check-installed install-baseline
docker exec "$target" sh /tmp/check-installed reject-tampered-upgrade
docker exec "$server" sh -c 'set -e; for f in /srv/*.clean; do mv "$f" "${f%.clean}"; done'
for invalid in digest tag origin url duplicate draft prerelease missing; do
 serve_release "" --invalid "$invalid"
 docker exec "$target" sh /tmp/check-installed reject-invalid-release
done
case "$release" in 25.*) ext=apk;; *) ext=ipk;; esac
set -- "$feed/baseline/"*."$ext"
serve_release "" --contents "$1"
docker exec "$server" sh -ec 'for f in /srv/releases/download/v*/*; do ln -sf "/srv/baseline/$1" "$f"; done' sh "${1##*/}"
docker exec "$target" sh /tmp/check-installed reject-wrong-version
serve_release ""
docker exec "$target" sh /tmp/check-installed upgrade
docker exec "$target" sh /tmp/check-web
serve_release /baseline
docker exec "$target" sh /tmp/check-installed reject-downgrade
if [ "$release" = 25.12.6 ]; then
 docker exec "$target" sh /tmp/check-installed prepare-recovery
 docker exec -d "$target" sh -ec 'exec 8>/var/run/openweir/network/lock; flock -x 8; touch /tmp/block-release; while [ -f /tmp/block-release ]; do sleep 1; done'
 docker exec "$target" sh /tmp/check-installed uninstall-with-recovery
else
 docker exec "$target" sh /tmp/check-installed uninstall
fi
echo "Verified native package installation, GitHub digest/identity checks, upgrade and removal on OpenWrt $release ($arch)"
