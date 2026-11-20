#!/bin/sh
set -eu
mkdir -p /var/run/ubus /var/lock
ubusd >/tmp/ubusd.log 2>&1 &
for i in $(seq 1 8); do [ -S /var/run/ubus/ubus.sock ] && break; sleep 1; done
rpcd >/tmp/rpcd.log 2>&1 &
openweird serve >/tmp/manager.log 2>&1 &
manager=$!
trap 'rc=$?; if [ "$rc" != 0 ]; then cat /tmp/manager.log /tmp/rpcd.log /tmp/ubusd.log; ubus -v list openweir || :; ls -l /tmp/status /var/run/openweir || :; fi; kill "$manager" 2>/dev/null || :' EXIT
for i in $(seq 1 15); do
 if ubus call openweir status >/tmp/status 2>/dev/null && [ "$(jsonfilter -i /tmp/status -e '@.phase')" = direct ]; then break; fi
 sleep 1
done
[ "$(jsonfilter -i /tmp/status -e '@.phase')" = direct ] || { cat /tmp/manager.log; exit 1; }
run_task(){
 task=$(ubus call openweir "$1" "$2" | jsonfilter -e '@.task')
 [ -n "$task" ]
 for i in $(seq 1 15); do
  response=$(ubus call openweir task "{\"task\":\"$task\"}")
  stage=$(printf %s "$response" | jsonfilter -e '@.stage')
  case "$stage" in done) return 0;; failed|interrupted) echo "$response"; return 1;; esac
  sleep 1
 done
 return 1
}
run_task subscription_write '{"action":"configure","args":{"config":{"id":"local","kind":"file","name":"Fixture"}}}'
run_task subscription_write '{"action":"refresh","args":{"source":"local","content":"http://user:password@127.0.0.1:18888#one"}}'
ubus call openweir source '{"source":"local"}' >/dev/null
summary=$(ubus call openweir subscription_read '{"action":"nodes","args":{"source":"local"}}')
node=$(printf %s "$summary" | jsonfilter -e '@.data.items[0].id')
[ -n "$node" ] && ! printf %s "$summary" | grep -q password
choice=$(ubus call openweir select_node "{\"source\":\"local\",\"group\":\"@global\",\"node\":\"$node\"}" | jsonfilter -e '@.task')
[ "$(ubus call openweir task "{\"task\":\"$choice\"}" | jsonfilter -e '@.stage')" = saved ]
kill -TERM "$manager"; wait "$manager"
openweird serve >/tmp/manager.log 2>&1 &
manager=$!
for i in $(seq 1 15); do ubus call openweir status >/tmp/status 2>/dev/null && break; sleep 1; done
[ "$(jsonfilter -i /tmp/status -e '@.saved.source')" = local ]
ubus call openweir groups | grep -Fq "$node"
ubus call openweir clear '{"page":"connections"}' >/dev/null
ubus call openweir logs >/dev/null
