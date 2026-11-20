#!/bin/sh
# Some package architectures have an SDK and firmware but no prebuilt rootfs container.
# Build the matching userland with the official ImageBuilder and its signed repositories.
set -eu
release=${1:?OpenWrt release}; arch=${2:?package architecture}
sdk="ghcr.io/openwrt/sdk:$arch-$release"
if ! docker image inspect "$sdk" >/dev/null 2>&1; then
 docker pull --platform linux/amd64 "$sdk" >&2
fi
target=$(docker image inspect "$sdk" --format '{{range .Config.Env}}{{println .}}{{end}}' | sed -n 's,^TARGET=,,p')
board=${target%/*}; subtarget=${target#*/}
case "$board:$subtarget" in :*|*:|*[!a-zA-Z0-9_:-]*) echo "Invalid SDK target $target" >&2; exit 1;; esac
tmp=$(mktemp -d); cid=
cleanup() { [ -z "$cid" ] || docker rm -fv "$cid" >/dev/null; rm -rf "$tmp"; }
trap cleanup EXIT
trap 'exit 1' INT TERM
image="ghcr.io/openwrt/imagebuilder:$board-$subtarget-$release"
cid=$(docker create --platform linux/amd64 "$image" sh -ec '
 cd /builder
 [ -f Makefile ] || ./setup.sh
 make manifest >/dev/null
 make prepare_rootfs
 for root in build_dir/target-*/root-*; do
  case "$root" in *.orig) continue;; esac
  if [ -f "$root/etc/openwrt_release" ]; then
   tar -C "$root" --owner=0 --group=0 --exclude=./etc/resolv.conf -czf /tmp/router.tar.gz .
   exit 0
  fi
 done
 exit 1
')
docker start -a "$cid" >&2
test "$(docker inspect -f '{{.State.ExitCode}}' "$cid")" = 0
docker cp "$cid:/tmp/router.tar.gz" "$tmp/router.tar.gz"
# Like the official OpenWrt images, record the exact package architecture in the image.
docker import --platform "linux/$arch" "$tmp/router.tar.gz"
