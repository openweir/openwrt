package main

import (
	"os"
	"path/filepath"

	"github.com/openweir/openwrt/internal/cli/kernelcli"
	"github.com/openweir/openwrt/internal/cli/netcli"
	"github.com/openweir/openwrt/internal/cli/subscriptioncli"
)

// The universal installer retains one executable for the router's CPU.
// The installed command names keep their original argument and exit conventions.
func main() {
	switch filepath.Base(os.Args[0]) {
	case "openweir-kernel":
		kernelcli.Main()
	case "openweir-net":
		netcli.Main()
	case "openweir-subscription":
		subscriptioncli.Main()
	default:
		runDaemon()
	}
}
