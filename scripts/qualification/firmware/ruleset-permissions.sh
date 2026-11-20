#!/bin/sh
# Booted stock OpenWrt. The host stages the original IPK and its SHA256SUMS in
# /root/candidate and the matching upstream launchable archive, its tag and SHA256SUMS in /root/bundles.
set -eu
trap 'echo OPENWEIR_GUEST_EXIT=$?; echo OPENWEIR_QUALIFICATION_END' EXIT
report() { printf 'OPENWEIR_RESULT %s=%s\n' "$1" "${2:-pass}"; }
call() { if [ "$#" -gt 1 ]; then printf '%s\n' "$2"; else echo '{}'; fi | openweird call "$1"; }
wait_job() {
 local id result state i
 id=$(jsonfilter -s "$1" -e '@.task')
 [ -n "$id" ]
 for i in $(seq 1 100); do
  result=$(call task "{\"task\":\"$id\"}")
  state=$(jsonfilter -s "$result" -e '@.stage')
  case "$state" in done) return 0;; running) sleep 1;; *) echo "task ended: $result"; return 1;; esac
 done
 return 1
}
. /root/setup-network
opkg print-architecture > /tmp/guest-architectures
cat /tmp/guest-architectures >> /etc/opkg.conf
printf 'arch aarch64_cortex-a53 9\n' >> /etc/opkg.conf
cd /root/candidate
sha256sum -c SHA256SUMS
opkg install ./luci-app-openweir_*.ipk
report first_postinst
for i in $(seq 1 30); do [ -S /var/run/openweir/manager.sock ] && break; sleep 1; done
uci set openweir.main.method=tproxy
uci set openweir.main.dns=1
uci set openweir.main.ipv6=0
uci commit openweir
tag=$(cat /root/bundles/release-tag)
(cd /root/bundles && sha256sum -c SHA256SUMS)
set -- /root/bundles/*.gz
[ "$#" -eq 1 ] && [ -f "$1" ]
archive=$1
bytes=$(wc -c <"$archive")
ticket=$(call kernel_upload "{\"args\":{\"bytes\":$bytes}}")
dir=$(jsonfilter -s "$ticket" -e '@.path')
[ -d "$dir" ]
cp "$archive" "$dir/"
wait_job "$(call kernel_write "{\"action\":\"install-json\",\"args\":{\"tag\":\"$tag\",\"mode\":\"double\",\"bundle\":\"$dir\"}}")"
[ -z "$(openweir-kernel status | jsonfilter -e '@.active')" ]
report daemon_official_archive_upload
dir=/etc/openweir/imports/rulesets/source-fixture
mkdir -p "$dir"
# Use the two binary fixtures shipped in the exact package being qualified.
cp /usr/share/openweir/rules/geosite-cn.mrs /usr/share/openweir/rules/geoip-cn.mrs "$dir/"
wait_job "$(call subscription_write '{"action":"configure","args":{"config":{"id":"fixture","name":"Rules","kind":"file"}}}')"
json='{"proxies":[{"name":"sample","type":"http","server":"198.18.0.33","port":1080}],"proxy-groups":[{"name":"Proxy","type":"select","proxies":["sample"]}],"rule-providers":{"domains":{"type":"file","behavior":"domain","format":"mrs","path":"./geosite-cn.mrs"},"networks":{"type":"file","behavior":"ipcidr","format":"mrs","path":"./geoip-cn.mrs"}},"rules":["RULE-SET,domains,DIRECT","RULE-SET,networks,DIRECT","MATCH,Proxy"]}'
body=$(CFG="$json" ucode -e 'printf("%J",{action:"refresh",args:{source:"fixture",content:getenv("CFG")}})')
wait_job "$(call subscription_write "$body")"
call source '{"source":"fixture"}'
call mode '{"mode":"smart"}'
# Reproduce an installed older directory, even if a prior operation prepared it.
mkdir -p /etc/openweir/rulesets
chgrp openweir-core /etc/openweir/rulesets
chmod 0710 /etc/openweir/rulesets
began=$(cut -d. -f1 /proc/uptime)
prior=
call start
for i in $(seq 1 150); do
 state=$(call status)
 phase=$(jsonfilter -s "$state" -e '@.phase')
 if [ "$phase" != "$prior" ]; then echo "lifecycle phase=$phase"; prior=$phase; fi
 [ "$phase" != running ] || break
 if [ "$phase" = fail_open ] || [ "$phase" = release_failed ]; then echo "$state"; exit 1; fi
 sleep 1
done
[ "$phase" = running ] || { echo "$state"; exit 1; }
elapsed=$(( $(cut -d. -f1 /proc/uptime)-began ))
[ "$elapsed" -ge 60 ]
report daemon_first_confirm_s "$elapsed"
[ "$(ls -ld /etc/openweir/rulesets | cut -c1-10)" = drwxr-x--- ]
count=0
for f in /etc/openweir/rulesets/*.mrs; do
 [ -f "$f" ] && [ "$(ls -l "$f" | cut -c1-10)" = -rw-r----- ]
 count=$((count+1))
done
[ "$count" -eq 2 ]
report ruleset_watch_permissions
p=$(pidof mihomo)
[ -n "$p" ]
# Confirm the running core, under its real UID, loaded both providers.
key=$(cat /etc/openweir/private/control.token)
uclient-fetch -qO /tmp/qualify-providers --header="Authorization: Bearer $key" http://127.0.0.1:19761/providers/rules
unset key
for provider in domains networks; do
 count=$(jsonfilter -i /tmp/qualify-providers -e "@.providers.$provider.ruleCount")
 [ "${count:-0}" -gt 0 ]
done
rm -f /tmp/qualify-providers
report live_rule_providers
call logs '{"limit":100,"source":"core"}' | ucode -lfs -e 'let e=json(fs.stdin.read("all"));for(let item in e.items)if(match(item.message,/permission_denied|_permission$/))exit(1);'
report core_permission_logs
nslookup -retry=1 -timeout=1 -type=A probe.openweir.invalid 192.168.41.1 | grep -q 192.0.2.1
report tproxy_dns_takeover
call stop
for i in $(seq 1 30); do [ ! -e /var/run/openweir/network/owned ] && ! pidof mihomo >/dev/null && break; sleep 1; done
[ ! -e /var/run/openweir/network/owned ] && ! pidof mihomo >/dev/null
nslookup -retry=1 -timeout=1 -type=A localhost 192.168.41.1 >/dev/null
report tproxy_dns_restored
report daemon_lifecycle
