//go:build ignore

// Test peer for an isolated router. Its reply exposes the origin seen on the
// actual wire so a fallback route cannot accidentally pass the interception test.
package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

func main() {
	if os.Args[1] == "dns" {
		// A connected TCP socket forces the resolver to use DNS length framing.
		// UDP uses a packet socket and therefore exercises the other wire path.
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		dialer := net.Dialer{}
		resolver := net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, os.Args[2], net.JoinHostPort(os.Args[3], "53"))
		}}
		name := "wire.openweir.org."
		if len(os.Args) == 5 {
			name = os.Args[4]
		}
		ips, err := resolver.LookupIP(ctx, "ip4", name)
		if err != nil || len(ips) != 1 {
			panic(fmt.Sprintf("DNS via %s %s: %v (%v)", os.Args[2], os.Args[3], ips, err))
		}
		fmt.Println(ips[0])
		return
	}
	if os.Args[1] == "server" {
		for _, family := range []string{"4", "6"} {
			address := "198.18.0.10:8080"
			if family == "6" {
				address = "[2001:db8:1::10]:8080"
			}
			tcp, e := net.Listen("tcp"+family, address)
			if e != nil {
				panic(e)
			}
			udp, e := net.ListenPacket("udp"+family, address)
			if e != nil {
				panic(e)
			}
			go func() {
				for {
					c, e := tcp.Accept()
					if e != nil {
						return
					}
					host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
					fmt.Fprintln(c, host)
					c.Close()
				}
			}()
			go func() {
				var b [64]byte
				for {
					_, a, e := udp.ReadFrom(b[:])
					if e != nil {
						return
					}
					host, _, _ := net.SplitHostPort(a.String())
					_, _ = udp.WriteTo([]byte(host), a)
				}
			}()
		}
		select {}
	}
	c, e := net.DialTimeout(os.Args[1], net.JoinHostPort(os.Args[2], "8080"), 3*time.Second)
	if e != nil {
		panic(e)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if strings.HasPrefix(os.Args[1], "udp") {
		_, _ = c.Write([]byte("origin"))
	}
	var b [64]byte
	n, e := c.Read(b[:])
	if e != nil {
		panic(e)
	}
	fmt.Println(strings.TrimSpace(string(b[:n])))
}
