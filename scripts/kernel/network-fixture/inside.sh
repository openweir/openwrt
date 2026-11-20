#!/bin/sh
set -eu
mkdir -p /tmp/bin /var/run/ubus /var/etc /var/run/openweir /var/run/netns
echo 'openweir-core:x:2701:' >>/etc/group
echo 'openweir-core:x:2701:2701:Core:/var/empty:/bin/false' >>/etc/passwd
/sbin/ubusd &
sleep 1
for pair in lan:50 guest:51 wan:18 unmanaged:52; do
 ns=${pair%:*}; num=${pair#*:}
 ip netns add "$ns"
 ip link add "$ns-r" type veth peer name "$ns-c" netns "$ns"
 ip link set "$ns-r" up
 ip netns exec "$ns" ip link set lo up
 ip netns exec "$ns" ip link set "$ns-c" up
 if [ "$ns" = wan ]; then prefix=198.18.0; v6=2001:db8:1; else prefix=192.168.$num; v6=fd00:$num; fi
 ip addr add "$prefix.1/24" dev "$ns-r"
 ip -6 addr add "$v6::1/64" dev "$ns-r" nodad
 ip netns exec "$ns" ip addr add "$prefix.10/24" dev "$ns-c"
 ip netns exec "$ns" ip -6 addr add "$v6::10/64" dev "$ns-c" nodad
 ip netns exec "$ns" ip route add default via "$prefix.1"
 ip netns exec "$ns" ip -6 route add default via "$v6::1"
done
ip route add default via 198.18.0.10 dev wan-r
ip -6 route add default via 2001:db8:1::10 dev wan-r
ip netns exec wan /tmp/peer server &
# Use different answers on the original WAN resolver and the real Mihomo.
# All targets are owned by this test, including hard-coded public/private DNS.
ip netns exec wan ip address add 10.66.0.53/32 dev wan-c
ip netns exec wan ip -6 address add fd00:66::53/128 dev wan-c nodad
ip netns exec wan dnsmasq --interface=wan-c --except-interface=lo --bind-interfaces \
 --conf-file=/dev/null --pid-file=/var/run/test-wan-dns.pid --no-resolv --no-hosts \
 --address=/wire.openweir.org/1.0.0.1
echo 'nameserver 198.18.0.10' >/tmp/original-resolvers
# netifd is represented only by its published interface status; all dataplane
# commands, DNS daemons and packets use the packaged Linux programs.
cat >/tmp/bin/ubus <<'SH'
#!/bin/sh
case "$2" in network.interface.lan) echo '{"l3_device":"lan-r"}';;
 network.interface.guest) echo '{"l3_device":"guest-r"}';;
 *) exec /bin/ubus "$@";; esac
SH
chmod 755 /tmp/bin/ubus
export PATH=/tmp/bin:/usr/sbin:/usr/bin:/sbin:/bin
for pair in lan:50 guest:51 unmanaged:52; do
 ns=${pair%:*}; n=${pair#*:}
 dir=/tmp/instance-$ns
 mkdir -p "$dir"
 cat >/var/etc/dnsmasq.conf.$ns <<CFG
interface=$ns-r
except-interface=lo
bind-interfaces
no-hosts
resolv-file=/tmp/original-resolvers
cache-size=0
address=/localhost/127.0.0.1
domain-needed
server=/invalid/
stop-dns-rebind
conf-dir=$dir
pid-file=/var/run/dns-$ns.pid
CFG
done
cat >/etc/init.d/dnsmasq <<'SH'
#!/bin/sh
set -eu
for name in lan guest unmanaged; do
 file=/var/run/dns-$name.pid
 if [ -e "$file" ]; then kill "$(cat "$file")" || :; fi
done
sleep 1
for name in lan guest unmanaged; do dnsmasq -C "/var/etc/dnsmasq.conf.$name"; done
SH
chmod 755 /etc/init.d/dnsmasq
/etc/init.d/dnsmasq restart
uci -q delete openweir.main.network || :
uci add_list openweir.main.network=lan
uci add_list openweir.main.network=guest
uci set openweir.main.ipv6=1
uci set openweir.main.dns=1
uci set openweir.main.dns_intercept=1
uci commit openweir
mkdir -p /etc/iproute2
echo '21998 qualified_table' >>/etc/iproute2/rt_tables
cat >/tmp/fw4 <<'NFT'
table inet fw4 {
 chain input {
  type filter hook input priority filter; policy accept;
  include "/usr/share/nftables.d/chain-pre/input/90-openweir.nft"
  iifname "guest-r" meta mark & 0xffff == 0x4f57 drop
 }
 chain forward {
  type filter hook forward priority filter; policy accept;
  include "/usr/share/nftables.d/chain-pre/forward/90-openweir.nft"
  oifname "owtun0" drop
 }
}
NFT
helper=/usr/libexec/openweir/network
if [ "${TEST_FIREWALL:-fw4}" = fw3 ]; then
 uci set 'firewall.@defaults[0].input=ACCEPT'
 uci set 'firewall.@defaults[0].forward=ACCEPT'
 uci commit firewall
 fw3 start >/tmp/fw3.log 2>&1
 test "$("$helper" environment | cut -d' ' -f1)" = fw3
 nft -f /tmp/fw4
 test "$("$helper" environment)" = ambiguous
 nft delete table inet fw4
 for xt in iptables-legacy ip6tables-legacy; do
  "$xt" -I INPUT -i guest-r -m mark --mark 0x4f57/0xffff -j DROP
  "$xt" -I FORWARD -o owtun0 -j DROP
  "$xt" -N unrelated
  "$xt" -t nat -A PREROUTING -i unmanaged-r -p udp --dport 65053 -m comment --comment fixture-foreign -j RETURN
 done
else
 nft -f /tmp/fw4
 test "$("$helper" environment | cut -d' ' -f1)" = fw4
fi
"$helper" capabilities >/tmp/capabilities
for capability in 'dns_intercept 1' 'tproxy 1' 'tun 1'; do
 grep -Fqx "$capability" /tmp/capabilities || { cat /tmp/capabilities; exit 1; }
done
# Firmware may supply capabilities without a matching opkg/apk package. Probe
# selected mode before any takeover and verify that missing options stay local.
uci set openweir.main.method=tproxy
"$helper" prerequisites >/tmp/requirements
mount -t tmpfs -o size=16k tmpfs /dev/net
"$helper" prerequisites >/tmp/requirements
"$helper" capabilities >/tmp/requirements
grep -Fqx 'tproxy 1' /tmp/requirements && grep -Fqx 'tun 0' /tmp/requirements
! grep -q '^missing ' /tmp/requirements
uci set openweir.main.method=tun
if "$helper" prerequisites >/tmp/requirements; then exit 1; fi
grep -Fqx 'missing tun_device' /tmp/requirements
umount /dev/net
uci set openweir.main.method=tproxy
mv /etc/init.d/dnsmasq /etc/init.d/dnsmasq.saved
if "$helper" prerequisites >/tmp/requirements; then exit 1; fi
grep -Fqx 'missing dnsmasq' /tmp/requirements
uci set openweir.main.dns=0
"$helper" prerequisites >/tmp/requirements
mv /etc/init.d/dnsmasq.saved /etc/init.d/dnsmasq
uci set openweir.main.dns=1
ln -s /bin/busybox /tmp/bin/ip
if "$helper" prerequisites >/tmp/requirements; then exit 1; fi
grep -Fqx 'missing iproute' /tmp/requirements
rm /tmp/bin/ip
"$helper" prerequisites >/tmp/requirements
# Inspect the effective per-instance configuration, including nested files,
# without copying DNS values into diagnostics or touching foreign directives.
mkdir -p /tmp/instance-lan/nested
printf '%s\n' 'conf-dir=/tmp/instance-lan/nested,*.conf' >/tmp/instance-lan/custom.conf
printf '%s\n' 'server=/corp.example/10.0.0.53' >/tmp/instance-lan/nested/corp.conf
printf '%s\n' 'server=10.0.0.53' >/tmp/instance-lan/nested/ignored.disabled
"$helper" prerequisites >/tmp/requirements
for item in 'server=/#/10.0.0.53:dns_default_upstream' 'servers-file=/tmp/servers:dns_servers_file'; do
 printf '%s\n' "${item%:*}" >/tmp/instance-lan/nested/test.conf
 if "$helper" prerequisites >/tmp/requirements; then echo 'accepted conflicting nested upstream'; exit 1; fi
 grep -Fqx "missing ${item#*:} lan" /tmp/requirements
 if grep -Eq '10\.0\.0\.53|/tmp/servers' /tmp/requirements; then exit 1; fi
done
rm -f /tmp/instance-lan/nested/test.conf
echo 'Selected-mode prerequisites passed for TProxy without TUN, DNS off without dnsmasq, and detection of incomplete BusyBox ip'
reload_firewall() {
 if [ "${TEST_FIREWALL:-fw4}" = fw3 ]; then fw3 reload >/tmp/fw3.log 2>&1
 else
  { flock -x 8; { echo 'delete table inet fw4'; cat /tmp/fw4; } | nft -f -; } 8>/var/run/fw4.lock
 fi
}
wire() {
 for ns in ${2:-lan guest}; do
  case "$ns" in lan) n=50;; guest) n=51;; unmanaged) n=52;; esac
  for family in 4 6; do
   case "$family:$1" in
    4:direct) expect=192.168.$n.10;; 6:direct) expect=fd00:$n::10;;
    4:proxy) expect=198.18.0.1;; 6:proxy) expect=2001:db8:1::1;;
   esac
   if [ "$family" = 4 ]; then target=198.18.0.10; else target=2001:db8:1::10; fi
   for protocol in tcp udp; do
    got=$(ip netns exec "$ns" /tmp/peer "$protocol$family" "$target")
    [ "$got" = "$expect" ] || { echo "$ns $protocol$family expected $expect got $got" >&2; return 1; }
   done
  done
 done
}
dns_wire() {
 phase=$1
 for ns in lan guest unmanaged; do
  case "$ns" in lan) subnet=50;; guest) subnet=51;; unmanaged) subnet=52;; esac
  for family in 4 6; do
   if [ "$family" = 4 ]; then gateway=192.168.$subnet.1; public=198.18.0.10; private=10.66.0.53
   else gateway=fd00:$subnet::1; public=2001:db8:1::10; private=fd00:66::53; fi
   for resolver in "$gateway" "$public" "$private"; do
    expect=1.0.0.1
    if [ "$ns" != unmanaged ]; then
     if [ "$phase" = intercept ] || { [ "$phase" = upstream ] && [ "$resolver" = "$gateway" ]; }; then expect=1.1.1.1; fi
    fi
    for protocol in tcp udp; do
     answer=$(ip netns exec "$ns" /tmp/peer dns "$protocol$family" "$resolver") || {
      echo "DNS $phase failed at $ns $protocol$family @$resolver" >&2
      ip netns exec "$ns" nslookup -type=A wire.openweir.org "$resolver" || :
      ip netns exec wan nslookup -type=A wire.openweir.org 198.18.0.10 || :
      return 1
     }
     [ "$answer" = "$expect" ] || { echo "$phase DNS $ns $protocol$family @$resolver expected $expect got $answer" >&2; return 1; }
    done
   done
  done
 done
 echo "DNS $phase passed on LAN, guest and unmanaged networks (IPv4/IPv6, TCP/UDP, gateway/public/private)"
}
start_core() {
 mkdir -p /tmp/mihomo-test
 chown openweir-core:openweir-core /tmp/mihomo-test
 /sbin/ujail -U openweir-core -G openweir-core -C /etc/openweir/core-capabilities.json -c -- /tmp/core -d /tmp/mihomo-test -f /tmp/core.yaml >/tmp/core.log 2>&1 &
 jail=$!
 sleep 1
 for attempt in 1 2 3 4 5; do
  if ! kill -0 "$jail"; then cat /tmp/core.log; exit 1; fi
  if [ "$method" = tun ]; then [ -e /sys/class/net/owtun0 ] && break
  elif grep -q ':4D32 ' /proc/net/tcp6; then break; fi
  sleep 1
 done
}
blocked_queries() {
 pids=
 for family in 4 6; do
  if [ "$family" = 4 ]; then target=198.18.0.10; gateway=192.168.50.1
  else target=2001:db8:1::10; gateway=fd00:50::1; fi
  for protocol in tcp udp; do
   (if ip netns exec lan /tmp/peer "$protocol$family" "$target" >/dev/null 2>&1; then echo "$protocol$family bypassed protection" >&2; exit 1; fi) &
   pids="$pids $!"
   (if ip netns exec lan /tmp/peer dns "$protocol$family" "$gateway" >/dev/null 2>&1; then echo "$protocol$family leaked upstream DNS" >&2; exit 1; fi) &
   pids="$pids $!"
  done
 done
 result=0
 for pid in $pids; do wait "$pid" || result=1; done
 return "$result"
}
mkdir -p /etc/openweir/private
token=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
printf '%s' "$token" >/etc/openweir/private/control.token
echo ok >/www/health.txt
/usr/sbin/uhttpd -f -p 0.0.0.0:80 -h /www >/tmp/uhttpd.log 2>&1 &
 sleep 1
 wire direct
 dns_wire direct
for method in ${TEST_METHODS:-tproxy tun}; do
 case "$method" in tproxy|tun) ;; *) exit 2 ;; esac
 echo "Testing $method"
 uci set openweir.main.method="$method"; uci commit openweir
 if [ "$method" = tproxy ]; then inbound='tproxy-port: 19762'; else inbound='tun: {enable: true, device: owtun0, stack: system, auto-route: false, auto-detect-interface: false, dns-hijack: [], inet4-address: [172.30.254.1/30], inet6-address: ["fd7e:5745:4952::1/126"]}'; fi
 cat >/tmp/core.yaml <<CFG
external-controller: 127.0.0.1:19761
secret: $token
allow-lan: true
bind-address: "*"
ipv6: true
interface-name: wan-r
log-level: warning
$inbound
rules: ['MATCH,DIRECT']
hosts:
  probe.openweir.invalid: 192.0.2.1
  wire.openweir.org: 1.1.1.1
dns:
  enable: true
  ipv6: true
  listen: 127.0.0.1:19764
  enhanced-mode: redir-host
  use-hosts: true
  nameserver: [198.18.0.10]
CFG
 start_core
 helper=/usr/libexec/openweir/network
 # Real fw4 serializes generation and nft commit with this same lock.
 # Reload repeatedly across the initial guest DNS restart and handover.
 touch /tmp/reload-fw4
 (
  while [ -f /tmp/reload-fw4 ]; do
   reload_firewall
   sleep 1
  done
 ) &
 reloader=$!
 "$helper" apply || { sh -x "$helper" apply; exit 1; }
 rm -f /tmp/reload-fw4; wait "$reloader"
 wire proxy
 grep -q '192.168.50.1:80' /var/run/openweir/network/management.json
 [ ! -e /tmp/instance-unmanaged/99-openweir-upstream.conf ]
 dns_wire intercept
 reload_firewall
 "$helper" verify
 wire proxy
 dns_wire intercept
 # The ordinary stop path must return both dnsmasq and hand-set DNS to the
 # WAN, and enabling upstream protection alone must leave hand-set DNS alone.
 "$helper" release
 wire direct
 dns_wire direct
 uci set openweir.main.dns_intercept=0
 "$helper" apply
 dns_wire upstream
 "$helper" release
 uci set openweir.main.dns_intercept=1
 "$helper" apply
 # Isolate a DNS-only failure. The API and heartbeat keep answering while both
 # transports to Mihomo DNS are blocked. Measure from fault to an uncached WAN
 # answer on the LAN, independently of when the ownership marker disappears.
 (while :; do echo ok >/var/run/openweir/new-pulse; mv -f /var/run/openweir/new-pulse /var/run/openweir/pulse; sleep 1; done) &
 dns_writer=$!
 /tmp/openweird guard &
 dns_guard=$!
 sleep 3
 [ -e /var/run/openweir/network/owned ]
 "$helper" prerequisites >/tmp/requirements
 dns_start=$(awk '{print $1}' /proc/uptime)
 nft -f - <<'NFT'
table inet dns_fault_fixture {
 chain output {
  type filter hook output priority filter; policy accept;
  ip daddr 127.0.0.1 meta l4proto { tcp, udp } th dport 19764 drop
 }
}
NFT
 missed=0; recovered=0
 for seq in $(seq 1 25); do
  if answer=$(ip netns exec lan /tmp/peer dns udp4 192.168.50.1 "recovery-$seq.wire.openweir.org." 2>/dev/null); then
   if [ "$answer" = 1.0.0.1 ]; then recovered=1; break; fi
  else missed=1; fi
  elapsed=$(awk -v start="$dns_start" '{print int($1-start)}' /proc/uptime)
  [ "$elapsed" -lt 18 ] || break
  sleep 1
 done
 awk -v start="$dns_start" -v outcome="$recovered" -v fw="${TEST_FIREWALL:-fw4}" -v mode="$method" '{
  elapsed=$1-start; printf "%s %s DNS-only fault: LAN returned an uncached upstream answer after %.2f seconds (recovered=%d)\n",fw,mode,elapsed,outcome;
  exit !(outcome == 1 && elapsed <= 18)
 }' /proc/uptime
 [ "$missed" = 1 ]
 for _ in $(seq 1 8); do [ ! -e /var/run/openweir/network/owned ] && break; sleep 1; done
 [ ! -e /var/run/openweir/network/owned ] && kill -0 "$jail"
 nft delete table inet dns_fault_fixture
 kill "$dns_guard" "$dns_writer"; wait "$dns_guard" || :; wait "$dns_writer" || :
 wire direct
 dns_wire direct
 "$helper" apply
 # Kill one side at a time. A live heartbeat writer cannot mask a dead core.
 (while :; do echo ok >/var/run/openweir/new-pulse; mv -f /var/run/openweir/new-pulse /var/run/openweir/pulse; sleep 1; done) &
 writer=$!
 /tmp/openweird guard &
 guard=$!
 sleep 8
 [ -e /var/run/openweir/network/owned ] || { echo 'healthy network was released'; exit 1; }
 if [ "$method" = tun ]; then kill "$jail"; wait "$jail" || :; else kill "$writer"; wait "$writer" || :; fi
 for i in 1 2 3 4 5 6 7 8 9 10 11 12; do [ -e /var/run/openweir/network/owned ] || break; sleep 1; done
 [ ! -e /var/run/openweir/network/owned ]
 kill "$guard"; wait "$guard" || :
 wire direct
 dns_wire direct
 if [ "${TEST_FIREWALL:-fw4}" = fw3 ]; then
  for xt in iptables-legacy ip6tables-legacy; do
   "$xt" -S unrelated >/dev/null
   "$xt" -t nat -C PREROUTING -i unmanaged-r -p udp --dport 65053 -m comment --comment fixture-foreign -j RETURN
   if "$xt" -t nat -S | grep -q openweir-owned-v1; then echo 'owned NAT rule remained after release' >&2; exit 1; fi
   "$xt" -C INPUT -i guest-r -m mark --mark 0x4f57/0xffff -j DROP
   if "$xt" -t mangle -S OPENWEIR_LAN >/dev/null 2>&1; then exit 1; fi
  done
 fi
 [ ! -e /tmp/instance-lan/99-openweir-upstream.conf ]
 if [ "$method" = tun ]; then kill "$writer"; wait "$writer" || :; else kill "$jail"; wait "$jail" || :; fi

 [ "${TEST_TRACE:-0}" != 1 ] || set -x
 # Disable automatic direct fallback for the next confirmed takeover.
 uci set openweir.main.fail_open=0
 guest_mac=$(ip netns exec guest cat /sys/class/net/guest-c/address)
 printf 'mac %s direct\n4 192.168.50.10/32 block\n6 fd00:50::10/128 block\ndefault block\n' "$guest_mac" >/var/run/openweir/device-guard.policy
 [ "$("$helper" fault)" = direct ]
 nft -f - <<'NFT'
table inet flow_fixture {
 flowtable test_ft { hook ingress priority 0; devices = { lan-r, wan-r }; }
 chain test_forward { type filter hook forward priority filter; policy accept; meta l4proto udp flow add @test_ft; }
}
NFT
 if "$helper" apply; then echo 'active offload was accepted for fault protection'; exit 1; fi
 [ "$(cat /var/run/openweir/network/error)" = fault_flow_offload ]
 [ ! -e /var/run/openweir/network/owned ]
 nft delete table inet flow_fixture
 start_core
 "$helper" apply
 wire proxy
 (while :; do echo ok >/var/run/openweir/new-pulse; mv -f /var/run/openweir/new-pulse /var/run/openweir/pulse; sleep 1; done) &
 writer=$!
 /tmp/openweird guard &
 guard=$!
 sleep 3
 if [ "$method" = tun ]; then
  kill "$jail"; wait "$jail" || :
  for fam in 4 6; do
   ip "-$fam" route show table 21998 | grep -q '^prohibit default'
   if [ "$fam" = 4 ]; then dst=198.18.0.10; else dst=2001:db8:1::10; fi
   if ip "-$fam" route get "$dst" mark 0x4f57 >/dev/null 2>&1; then echo 'dead TUN routed through WAN'; exit 1; fi
  done
 else kill "$writer"; wait "$writer" || :; fi
 for i in $(seq 1 20); do
  if [ -f /var/run/openweir/network/held ] && [ ! -f /var/run/openweir/network/owned ]; then break; fi
  sleep 1
 done
 [ -f /var/run/openweir/network/held ] && [ ! -f /var/run/openweir/network/owned ] || { echo 'guard did not hold'; cat /var/run/openweir/network/error; exit 1; }
 kill "$guard"; wait "$guard" || :
 if [ "$method" = tun ]; then kill "$writer"; wait "$writer" || :; fi
 [ "$("$helper" fault)" = protected ]
 reload_firewall
 blocked_queries
 wire direct 'guest unmanaged'
 for ns in guest unmanaged; do
  if [ "$ns" = guest ]; then n=51; else n=52; fi
  [ "$(ip netns exec "$ns" /tmp/peer dns udp4 "192.168.$n.1")" = 1.0.0.1 ]
  [ "$(ip netns exec "$ns" /tmp/peer dns tcp6 "fd00:$n::1")" = 1.0.0.1 ]
 done
 ip netns exec lan wget -q -O /dev/null http://192.168.50.1/health.txt
 # A failed candidate retains the protection until a healthy takeover or stop.
 uci set openweir.main.method=invalid
 if "$helper" apply; then echo 'invalid candidate was accepted'; exit 1; fi
 [ -f /var/run/openweir/network/held ]
 uci set openweir.main.method="$method"
 # Smart default-direct with explicit proxy exceptions replaces the old MAC
 # exemption only upon this next confirmed takeover.
 printf '4 192.168.50.10/32 block\n6 fd00:50::10/128 block\ndefault direct\n' >/var/run/openweir/device-guard.policy
 if [ "$method" = tun ]; then start_core; fi
 "$helper" apply
 [ ! -f /var/run/openweir/network/held ]
 wire proxy
 [ "$("$helper" fault)" = protected ]
 blocked_queries
 wire direct 'guest unmanaged'
 "$helper" release
 [ ! -e /var/run/openweir/network/held ]
 # Simulate init stop while the guard has already noticed a missing pulse
 # and serve has queued a retry. Both share the network lock with release.
 "$helper" apply
 touch /var/run/openweir/stopping
 "$helper" fault >/tmp/stopping-disposition &
 stopping_fault=$!
 "$helper" release &
 stopping_release=$!
 if "$helper" apply; then echo 'queued apply retook LAN during stop'; exit 1; fi
 wait "$stopping_release"; wait "$stopping_fault"
 [ "$(cat /tmp/stopping-disposition)" = direct ]
 [ ! -f /var/run/openweir/network/owned ] && [ ! -e /var/run/openweir/network/held ]
 rm -f /var/run/openweir/stopping
 wire direct
 dns_wire direct
 kill "$jail"; wait "$jail" || :
 uci set openweir.main.fail_open=1
 echo "$method hold, retry and manual release passed (IPv4/IPv6 TCP/UDP, managed/direct/unmanaged)"
done
# A pre-existing chain blocks takeover. Rules added by another owner while we
# run survive cleanup, even when they reside in or refer to our own chain.
if [ "${TEST_FIREWALL:-fw4}" = fw3 ]; then
 . /usr/libexec/openweir/firewall-backend
 state=/var/run/openweir/network
 legacy_families=4; note=openweir-owned-v1; port=19762; mark=0x4f57; method=tproxy; interfaces=lan-r; v6=0
 xt=iptables-legacy
 "$xt" -t mangle -N OPENWEIR_LAN
 if legacy_prepare; then echo 'foreign chain collision was accepted' >&2; exit 1; fi
 "$xt" -t mangle -X OPENWEIR_LAN
 legacy_prepare
 legacy_apply
 "$xt" -t mangle -A OPENWEIR_LAN -m comment --comment fixture-foreign -j RETURN
 "$xt" -t mangle -N fixture_ref
 "$xt" -t mangle -A fixture_ref -j OPENWEIR_LAN
 legacy_remove 4
 "$xt" -t mangle -C OPENWEIR_LAN -m comment --comment fixture-foreign -j RETURN
 "$xt" -t mangle -C fixture_ref -j OPENWEIR_LAN
 if "$xt" -t mangle -S PREROUTING | grep -q OPENWEIR_LAN; then exit 1; fi
fi
