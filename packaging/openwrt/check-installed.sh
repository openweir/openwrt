#!/bin/sh
set -eu
name=luci-app-openweir
case "$1" in reject-*|upgrade) PATH=/tmp/openweir-test-bin:$PATH; export PATH;; esac
case "$1" in
 prepare)
  . /etc/openwrt_release
  test "$DISTRIB_RELEASE" = "$2"
  test "$DISTRIB_ARCH" = "$3"
  mkdir -p /var/lock /var/run
  # Test doubles are outside the package and used only by the updater cases.
  mkdir -p /tmp/openweir-test-bin
  real_fetch=$(command -v uclient-fetch)
  cat > /tmp/openweir-test-bin/uclient-fetch <<'FETCH'
#!/bin/sh
set -eu
[ "$#" = 8 ] && [ "$1" = -T ] && [ "$3" = -U ] && [ "$4" = OpenWeir-OpenWrt ] && [ "$6" = -O ] || exit 1
case "$8" in
 https://api.github.com/repos/openweir/openwrt/releases/latest) path=releases/latest ;;
 https://github.com/openweir/openwrt/releases/download/v*/*) path=${8#https://github.com/openweir/openwrt/} ;;
 *) echo 'Unexpected release request' >&2; exit 1 ;;
esac
FETCH
  printf 'exec "%s" "$1" "$2" "$3" "$4" "$5" "$6" "$7" "http://feed:8080/$path"\n' "$real_fetch" >> /tmp/openweir-test-bin/uclient-fetch
  chmod 755 /tmp/openweir-test-bin/uclient-fetch
  (cd /tmp/verified-feed && sha256sum -c SHA256SUMS)
  rm /tmp/verified-feed/SHA256SUMS
  if command -v apk >/dev/null; then
   apk --allow-untrusted adbdump --format json /tmp/verified-feed/*.apk > /tmp/package-info.json
   test "$(jsonfilter -i /tmp/package-info.json -e '@.info.arch')" = "${OPENWEIR_PACKAGE_ARCH:-noarch}"
   jsonfilter -i /tmp/package-info.json -e '@.info.version' > /tmp/test-candidate-version
   depends=$(jsonfilter -i /tmp/package-info.json -e '@.info.depends[*]')
   if apk verify /tmp/verified-feed/*.apk >/dev/null 2>&1; then echo 'Expected an unsigned release APK' >&2; exit 1; fi
   test -n "$depends"
   # Stage dependencies declared by the old offline-upgrade fixture as well.
   baseline_deps=$(apk --allow-untrusted adbdump --format json /tmp/openweir-baseline/*.apk | jsonfilter -e '@.info.depends[*]')
   apk update
   apk add $depends $baseline_deps firewall4 nftables-json kmod-nft-tproxy uhttpd uhttpd-mod-ubus curl
  else
   tar -xzOf /tmp/verified-feed/*.ipk ./control.tar.gz | tar -xzO ./control > /tmp/package-control
   test "$(sed -n 's/^Architecture: //p' /tmp/package-control)" = "${OPENWEIR_PACKAGE_ARCH:-all}"
   sed -n 's/^Version: //p' /tmp/package-control > /tmp/test-candidate-version
   depends=$(sed -n 's/^Depends: //p' /tmp/package-control | tr ',' ' ')
   test -n "$depends"
   opkg update
   opkg install $depends firewall4 nftables-json kmod-nft-tproxy uhttpd uhttpd-mod-ubus curl
   # Verify against an online feed so a mistaken recommendation would pull the
   # package. Compare names and versions, as a dependency could replace a fork.
   opkg list-installed | sort >/tmp/stock-packages
   opkg install /tmp/verified-feed/*.ipk
   opkg list-installed | awk -v pkg="$name" '$1!=pkg' | sort >/tmp/other-packages
   cmp /tmp/stock-packages /tmp/other-packages
   opkg remove "$name"
   # The old package must own its optional dependencies for this test. An
   # explicit opkg install of all old dependencies hides the orphan removal.
   opkg install /tmp/openweir-baseline/*.ipk
   opkg list-installed | awk -v pkg="$name" '$1!=pkg' | sort >/tmp/baseline-packages
   opkg install /tmp/verified-feed/*.ipk
   opkg list-installed | awk -v pkg="$name" '$1!=pkg' | sort >/tmp/other-packages
   cmp /tmp/baseline-packages /tmp/other-packages
   opkg remove "$name"
   echo 'Native opkg installed only OpenWeir and retained the previous dependency set across upgrade'
  fi
  # Dependencies have been installed from the firmware's trusted repositories.
  for upstream in /etc/opkg/distfeeds.conf /etc/apk/repositories.d/distfeeds.list; do
   [ ! -f "$upstream" ] || mv "$upstream" "$upstream.disabled"
  done
  ;;
 offline-install)
  test -z "$(ip -4 route show default)" && test -z "$(ip -6 route show default)"
  test ! -e /usr/sbin/openweird && test ! -e /usr/libexec/openweir/manager
  set -- /tmp/verified-feed/*
  test "$#" = 1 && test -f "$1"
  case "${1##*/}" in
   luci-app-openweir-*-r[0-9]*.apk) apk --no-network --repositories-file /dev/null add --allow-untrusted "$1" ;;
   luci-app-openweir_*-[0-9]*_*.ipk) opkg install "$1" ;;
   *) echo 'Expected a single installation file' >&2; exit 1 ;;
  esac
  rm "$1"
  test -x /usr/libexec/openweir/manager && test ! -e /tmp/openweir-package-payload
  (cd /usr/share/openweir/rules && sha256sum -c SHA256SUMS)
  awk '$3 == "geoip-cn.mrs" { ip++ } $3 == "geosite-cn.mrs" { site++ }
       END { exit !(ip == 1 && site == 1) }' /usr/share/openweir/rules/CATALOG
  test -s /usr/libexec/openweir/fault-policy && test -x /usr/libexec/openweir/procd-delete
  echo "Offline runtime size: $(wc -c < /usr/libexec/openweir/manager) bytes; bundled CPU archives removed"
  for cli in openweird openweir-kernel openweir-net openweir-subscription; do
   test "$(readlink -f "/usr/sbin/$cli")" = /usr/libexec/openweir/manager
  done
  test "$(openweir-kernel status | jsonfilter -e '@.schema_version')" = 1
  test "$(openweir-subscription list </dev/null | jsonfilter -e '@.ok')" = true
  # A minimal rootfs has no procd service object. The checker reports an
  # explicit blocked result when it cannot inspect a required service.
  if openweir-net conflicts > /tmp/offline-conflicts; then
   test "$(jsonfilter -i /tmp/offline-conflicts -e '@.blocked')" = false
  else
   test "$(jsonfilter -i /tmp/offline-conflicts -e '@.blocked')" = true
   test -n "$(jsonfilter -i /tmp/offline-conflicts -e '@.resources[0].kind')"
  fi
  # check-web starts openweird and calls its authenticated RPC over loopback.
  ;;
 install-baseline)
  (cd /tmp/openweir-baseline && sha256sum -c SHA256SUMS)
  if command -v apk >/dev/null; then
   apk --no-network --repositories-file /dev/null add --allow-untrusted /tmp/openweir-baseline/*.apk
  else
   opkg install /tmp/openweir-baseline/*.ipk
  fi
  rm -r /tmp/openweir-baseline
  cat /etc/openwrt_release
  mkdir -p /etc/openweir/kernel
  echo 'upgrade-state-preserved' > /etc/openweir/kernel/package-upgrade-test
  ;;
 reject-tampered-upgrade)
  updater=/usr/libexec/openweir/package-update
  # Only the fixture's GitHub copy: no download mirrors outside the test network.
  uci set openweir.main.download_mirrors_saved=1
  uci -q delete openweir.main.download_mirror || true
  uci commit openweir
  test "$("$updater" check | jsonfilter -e '@.available')" = true
  if "$updater" apply; then echo 'Updater accepted modified package bytes' >&2; exit 1; fi
  installed=$("$updater" check | jsonfilter -e '@.installed')
  case "$installed" in 0.0.0-*) ;; *) echo 'Corrupt release changed the installed package' >&2; exit 1;; esac
  ;;
 reject-invalid-release)
  updater=/usr/libexec/openweir/package-update
  if "$updater" check || "$updater" apply; then echo 'Updater accepted a invalid official release metadata' >&2; exit 1; fi
  ;;
 reject-wrong-version)
  if detail=$(/usr/libexec/openweir/package-update apply 2>&1); then echo 'Updater accepted an incorrect embedded package version' >&2; exit 1; fi
  case "$detail" in *'identity does not match release'*) ;; *) echo "$detail" >&2; exit 1;; esac
  ;;
 upgrade)
  test "$(/usr/libexec/openweir/package-update check | jsonfilter -e '@.available')" = true
  /usr/libexec/openweir/package-update apply
  if command -v apk >/dev/null; then
   version=$(apk list -I "$name")
  else
   version=$(opkg list-installed "$name")
  fi
  case "$version" in ""|*0.0.0-*) echo 'upgrade did not select the new verified package' >&2; exit 1;; esac
  test "$(cat /etc/openweir/kernel/package-upgrade-test)" = upgrade-state-preserved
  test -s /usr/share/licenses/luci-app-openweir/LICENSE
  for cli in openweird openweir-net openweir-kernel openweir-subscription; do test -x "/usr/sbin/$cli"; done
  test -x /etc/init.d/openweir && test -x /usr/libexec/openweir/network
  test "$(id -u openweir-core)" != 0
  test ! -e /usr/sbin/mihomo
  ;;
 reject-downgrade)
  candidate=$(/usr/libexec/openweir/package-update check | jsonfilter -e '@.candidate')
  case "$candidate" in 0.0.0-*) ;; *) echo 'Expected the earlier release' >&2; exit 1;; esac
  if detail=$(/usr/libexec/openweir/package-update apply 2>&1); then echo 'Updater accepted a downgrade' >&2; exit 1; fi
  case "$detail" in *'Refusing package downgrade'*) ;; *) echo "$detail" >&2; exit 1;; esac
  ;;
 prepare-recovery)
  # Create observable owned resources only in the disposable test namespace.
  mkdir -p /var/run/openweir/network /tmp/test-dns
  echo /tmp/test-dns > /var/run/openweir/network/dns
  printf '%s\n' '# OpenWeir managed upstream' 'server=127.0.0.1#19764' > /tmp/test-dns/99-openweir-upstream.conf
  echo 'preserve' >/tmp/test-dns/foreign.conf
  nft 'add table inet openweir { comment "openweir-owned-v1"; }'
  nft add table inet foreign_test
  ;;
 uninstall-with-recovery)
  for _ in 1 2 3 4 5; do [ ! -e /tmp/block-release ] || break; sleep 1; done
  test -f /tmp/block-release
  apk del "$name"
  test ! -e /usr/sbin/openweird && test ! -e /usr/libexec/openweir/network
  test -f /tmp/openweir-recovery/pending
  rm -f /tmp/block-release
  for _ in $(seq 1 65); do [ -e /tmp/openweir-recovery/pending ] || break; sleep 1; done
  test ! -e /tmp/openweir-recovery/pending
  test ! -e /tmp/test-dns/99-openweir-upstream.conf && test -f /tmp/test-dns/foreign.conf
  # Removal keeps the user's kernels and subscriptions.
  test "$(cat /etc/openweir/kernel/package-upgrade-test)" = upgrade-state-preserved
  nft list table inet foreign_test >/dev/null
  if nft list table inet openweir >/dev/null 2>&1; then echo 'Owned firewall table survived recovery' >&2; exit 1; fi
  echo 'Verified detached recovery removed the owned DNS upstream and nft table after APK removed the package'
  ;;
 uninstall)
  if command -v apk >/dev/null; then apk del "$name"; else opkg remove "$name"; fi
  test ! -e /usr/sbin/openweird && test ! -e /usr/libexec/openweir/network
  test ! -e /usr/libexec/openweir/manager
  # Removal keeps the user's kernels and subscriptions; only a manual purge deletes them.
  [ "${2:-}" != preserved ] || test "$(cat /etc/openweir/kernel/package-upgrade-test)" = upgrade-state-preserved
  ;;
 *) exit 2 ;;
esac
