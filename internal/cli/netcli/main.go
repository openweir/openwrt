package netcli

import (
	"context"
	"fmt"
	"github.com/openweir/openwrt/internal/netguard"
	"os"
	"os/signal"
	"syscall"
)

func Main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var e error
	if len(os.Args) == 2 && (os.Args[1] == "management-record" || os.Args[1] == "management-check") {
		e = netguard.Management(ctx, os.Args[1] == "management-record")
	} else if len(os.Args) >= 2 && os.Args[1] == "dns-directories" {
		e = netguard.DNSDirectories(os.Args[2:], os.Stdout)
	} else {
		e = netguard.Run(ctx, os.Args[1:], os.Stdout)
	}
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
