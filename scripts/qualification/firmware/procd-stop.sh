#!/bin/sh
# Disposable IPK firmware guest. /root/procd-packages holds current.ipk and an
# optional pre-fix older version (previous.ipk) for the upgrade reproduction.
set -eu
trap 'rc=$?; echo "OPENWEIR_GUEST_EXIT=$rc"; echo OPENWEIR_QUALIFICATION_END' EXIT
report() { printf 'OPENWEIR_RESULT %s=pass\n' "$1"; }
pkg=luci-app-openweir
files=/root/procd-packages
init=/etc/init.d/openweir
list() { ubus -t 3 call service list '{"name":"openweir"}'; }
pid() { list | jsonfilter -e "@.openweir.instances.$1.pid"; }
quiet_run() {
 if ! "$@" > /tmp/openweir-procd-command 2>&1; then
  cat /tmp/openweir-procd-command; return 1
 fi
 if grep -Eq 'service delete .*\(Not found\)' /tmp/openweir-procd-command; then
  cat /tmp/openweir-procd-command; return 1
 fi
}
ready() {
 for attempt in $(seq 1 30); do
  if [ -n "$(pid serve)" ] && [ -n "$(pid guard)" ] &&
     [ "$(openweird call status </dev/null | jsonfilter -e '@.phase')" = direct ]; then return 0; fi
  sleep 1
 done
 return 1
}
[ "$(cat /proc/1/comm)" = procd ]
list >/dev/null
if [ -d /root/packages ]; then opkg install /root/packages/*.ipk; fi
[ -z "$(pid serve)" ]
if [ -f "$files/previous.ipk" ]; then
 opkg install "$files/previous.ipk" >/tmp/openweir-previous-install 2>&1
 grep -E 'service delete .*\(Not found\)' /tmp/openweir-previous-install
 ready
 report original_postinst_not_found
 quiet_run opkg install "$files/current.ipk"
 ready
 report upgrade_postinst
 quiet_run opkg remove "$pkg"
fi
quiet_run opkg install "$files/current.ipk"
ready
report first_postinst
[ ! -e /var/run/openweir/stopping ]
before=$(pid serve)
# A held network transaction prevents release. A failed stop or restart must
# leave both the registry and recovery obligations intact.
exec 8>/var/run/openweir/network/lock
flock -x 8
if "$init" restart; then echo 'restart masked a failed cleanup'; exit 1; fi
[ "$(pid serve)" = "$before" ]
[ -f /var/run/openweir/stopping ]
flock -u 8
exec 8>&-
report cleanup_failure
quiet_run "$init" stop guard
quiet_run "$init" stop guard
[ -n "$(pid serve)" ]
quiet_run "$init" stop
for attempt in $(seq 1 20); do [ -z "$(pid serve)" ] && break; sleep 1; done
[ -z "$(pid serve)" ]
# Even when already stopped, remove our own leftover table; another service's
# table and the ordinary dnsmasq process must survive the stop.
nft add table inet openweir '{ comment "openweir-owned-v1"; }'
nft add table inet openweir_unrelated
quiet_run "$init" stop
if nft list table inet openweir >/dev/null 2>&1; then exit 1; fi
nft list table inet openweir_unrelated >/dev/null
pidof dnsmasq >/dev/null
quiet_run "$init" stop
report repeat_stop
quiet_run "$init" start
ready
[ ! -e /var/run/openweir/stopping ]
quiet_run "$init" stop
# Exercise a real, separate ubusd without the service object. Its Not found
# cannot prove that procd has removed OpenWeir.
mkdir -p /tmp/openweir-test-bus
ubusd -s /tmp/openweir-test-bus/socket >/dev/null 2>&1 & testbus=$!
for attempt in $(seq 1 10); do [ -S /tmp/openweir-test-bus/socket ] && break; sleep 1; done
printf '#!/bin/sh\nexec %s -s /tmp/openweir-test-bus/socket "$@"\n' "$(command -v ubus)" >/tmp/openweir-test-bus/ubus
chmod 755 /tmp/openweir-test-bus/ubus
if PATH=/tmp/openweir-test-bus:$PATH /usr/libexec/openweir/procd-delete; then exit 1; fi
kill "$testbus"
wait "$testbus" 2>/dev/null || :
report missing_supervisor
quiet_run opkg remove "$pkg"
nft list table inet openweir_unrelated >/dev/null
report daemon_lifecycle
