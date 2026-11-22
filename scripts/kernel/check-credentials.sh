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
# The core runs as root in the openweir-core group (2701). The restricted checks hold no
# capability; the jailed core holds CAP_NET_ADMIN, CAP_NET_BIND_SERVICE and CAP_NET_RAW (0x3400) only.
cat > "$work/probe.go" <<'PROBE'
package main
import("fmt"; "os"; "strings"; "syscall")
func main() {
 b,e:=os.ReadFile("/proc/self/status");if e!=nil{panic(e)}
 found:=0; caps:="0000000000000000"; if os.Getenv("EXPECT_NETWORK")=="1"{caps="0000000000003400"}
 for _,s:=range strings.Split(string(b),"\n"){f:=strings.Fields(s);if len(f)<1{continue}
 switch f[0] {
 case "Uid:": for _,n:=range f[1:]{if n!="0"{panic(s)}};found++
 case "Gid:": for _,n:=range f[1:]{if n!="2701"{panic(s)}};found++
 case "Groups:":if os.Getenv("EXPECT_NETWORK")!="1"&&len(f)!=1{panic(s)};found++
 case "CapBnd:","CapEff:","CapPrm:","CapAmb:","CapInh:":if len(f)<2||f[1]!=caps{panic(s)};found++
 case "NoNewPrivs:":if len(f)<2||f[1]!="1"{panic(s)};found++
 default:continue
 };fmt.Println(s)}
 if found!=9{panic("missing privilege evidence")}
 // Root without CAP_DAC_OVERRIDE, CAP_CHOWN or CAP_SETUID: another user's file stays closed
 // and the core cannot give files away or leave its identity.
 if _,e=os.ReadFile("/tmp/foreign");e==nil{panic("core read another user's file")}
 if e=os.Chown("/tmp/probe",65534,65534);e==nil{panic("core changed a file's owner")}
 if e=syscall.Setuid(65534);e==nil{panic("core changed its user")}
}
PROBE
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o "$work/probe" "$work/probe.go"
for release in 23.05.6 24.10.8 25.12.6; do
    cid=$(docker create --env CORE_TAG="$version" --cap-add NET_ADMIN --network none --platform linux/arm64 "openweir-test/openwrt:$release-arm64" sh -ec '
        echo "openweir-core:x:2701:" >>/etc/group
        echo "openweir-core:x:2701:2701:OpenWeir:/var/empty:/bin/false" >>/etc/passwd
        echo private >/tmp/foreign && chown 65534:65534 /tmp/foreign && chmod 0600 /tmp/foreign
        mkdir -p /etc/config
        mkdir -p /var/run/openweir/mihomo
        echo "mode: direct" >/tmp/config.yaml
        /tmp/manager exec-restricted /tmp/probe -v
        mkdir -p /var/run/ubus
        /sbin/ubusd &
        sleep 1
        EXPECT_NETWORK=1 /sbin/ujail -G openweir-core -C /tmp/caps.json -c -e EXPECT_NETWORK -- /tmp/probe
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
