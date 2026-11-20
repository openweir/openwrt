#!/bin/sh
# Isolated ARM64 userland tests. The upstream archive is used only to verify
# the restricted execution ABI; it is not admitted to production trust.
set -eu
archive=${1:?pass the Mihomo Linux ARM64 release archive}
tag=${2:?pass the matching release tag}
expected=${3:?pass the independently verified archive SHA-256}
case "$tag" in v[0-9]*);; *) exit 2;; esac
dir=mihomo-${tag#v}-linux-arm64
version=$tag
case "$tag" in v0.0.0-alpha.*) version=alpha-${tag#v0.0.0-alpha.};; esac
work=$(mktemp -d)
cid=
cleanup() {
    if [ -n "$cid" ]; then docker rm -f "$cid" >/dev/null 2>&1 || :; fi
    rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
sum=$(openssl dgst -sha256 < "$archive" | awk '{print $NF}')
[ "$sum" = "$expected" ] || { echo "unexpected qualification fixture" >&2; exit 1; }
case "$(basename "$archive")" in
 "$dir.tar.gz") tar -xOzf "$archive" "$dir/mihomo" > "$work/mihomo" ;;
 "mihomo-linux-arm64-$version.gz") gzip -dc "$archive" > "$work/mihomo" ;;
 *) exit 2 ;;
esac
chmod 755 "$work/mihomo"
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o "$work/manager" ./cmd/openweir-kernel
cat > "$work/probe.go" <<'PROBE'
package main
import("fmt"; "os"; "strings")
func main() {
 b,e:=os.ReadFile("/proc/self/status");if e!=nil{panic(e)}
 found:=0; caps:="0000000000000000"; if os.Getenv("EXPECT_NETWORK")=="1"{caps="0000000000001000"}
 for _,s:=range strings.Split(string(b),"\n"){f:=strings.Fields(s);if len(f)<2{continue}
 switch f[0] {
 case "Uid:","Gid:": for _,n:=range f[1:]{if n!="2701"{panic(s)}};found++
 case "CapBnd:","CapEff:","CapPrm:","CapAmb:","CapInh:":if f[1]!=caps{panic(s)};found++
 case "NoNewPrivs:":if f[1]!="1"{panic(s)};found++
 default:continue
 };fmt.Println(s)}
 if found!=8{panic("missing privilege evidence")}
 if e=os.WriteFile("/etc/config/openweir-unauthorised",[]byte("write"),0600);e==nil{panic("core wrote privileged configuration")}
}
PROBE
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o "$work/probe" "$work/probe.go"
for release in 23.05.6 24.10.8 25.12.6; do
    cid=$(docker create --env CORE_TAG="$version" --cap-add NET_ADMIN --network none --platform linux/arm64 "openweir-test/openwrt:$release-arm64" sh -ec '
        echo "openweir-core:x:2701:" >>/etc/group
        echo "openweir-core:x:2701:2701:OpenWeir:/var/empty:/bin/false" >>/etc/passwd
        mkdir -p /etc/config
        mkdir -p /var/run/openweir/mihomo
        echo "mode: direct" >/tmp/config.yaml
        /tmp/manager exec-restricted /tmp/probe -v
        mkdir -p /var/run/ubus
        /sbin/ubusd &
        sleep 1
        EXPECT_NETWORK=1 /sbin/ujail -U openweir-core -G openweir-core -C /tmp/caps.json -c -e EXPECT_NETWORK -- /tmp/probe
        /tmp/manager exec-restricted /tmp/mihomo -v | grep -F "Mihomo Meta $CORE_TAG linux arm64 with "
        /tmp/manager exec-restricted /tmp/mihomo -t -d /var/run/openweir/mihomo -f /tmp/config.yaml
    ')
    docker cp files/etc/openweir/core-capabilities.json "$cid:/tmp/caps.json"
    for prog in probe mihomo manager; do docker cp "$work/$prog" "$cid:/tmp/$prog"; done
    docker start -a "$cid"
    [ "$(docker inspect -f '{{.State.ExitCode}}' "$cid")" = 0 ]
    docker rm "$cid" >/dev/null
    cid=
    echo "OpenWrt $release ARM64 restricted version/check passed"
done
