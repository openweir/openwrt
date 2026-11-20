package netguard

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDNSTakeoverUsesEffectiveInstanceConfiguration(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "dnsmasq.conf.lan")
	dir := filepath.Join(base, "lan")
	nested := filepath.Join(base, "nested")
	for _, path := range []string{dir, nested} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	write := func(p, text string) {
		t.Helper()
		if err := os.WriteFile(p, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	rootConfig := "interface=br-lan\nconf-dir=" + dir + ",*.conf\n"
	write(root, rootConfig)
	write(filepath.Join(dir, "ignored.disabled"), "server=192.0.2.1\n")
	write(filepath.Join(dir, ".backup.conf"), "server=192.0.2.1\n")
	write(filepath.Join(dir, "nested.conf"), "conf-file="+filepath.Join(nested, "extra")+"\n")
	write(filepath.Join(base, "dnsmasq.conf.guest"), "interface=guest\nserver=192.0.2.1\n")
	check := func(expect string, own ownership) {
		t.Helper()
		var output bytes.Buffer
		err := dnsDirectories(filepath.Join(base, "dnsmasq.conf.*"), own, []string{"br-lan"}, &output)
		if (err != nil) != strings.HasPrefix(expect, "missing ") || strings.TrimSpace(output.String()) != expect {
			t.Fatalf("result %q, error %v, want %q", output.String(), err, expect)
		}
	}
	write(filepath.Join(nested, "extra"), "server=/corp.example/10.0.0.53\nserver=/local.example/#\n")
	check(dir, ownership{})
	for _, test := range []struct{ line, issue string }{
		{"server=10.0.0.53", "dns_default_upstream"}, {"server=/#/10.0.0.53", "dns_default_upstream"},
		{"address=/#/127.0.0.1", "dns_default_upstream"},
		{"servers-file=/tmp/private", "dns_servers_file"}, {"conf-script=/bin/false", "dns_dynamic_config"},
		{"conf-file=/nonexistent/test/location", "dns_config_unreadable"},
	} {
		write(filepath.Join(nested, "extra"), test.line+"\n")
		check("missing "+test.issue+" lan", ownership{})
	}
	write(filepath.Join(nested, "extra"), "")
	write(root, rootConfig+"interface=guest\n")
	check("missing dns_shared_instance lan", ownership{})
	write(root, rootConfig)
	write(filepath.Join(base, "dnsmasq.conf.guest"), "interface=guest\nconf-dir="+dir+"\n")
	check("missing dns_include_directory lan", ownership{})
	write(filepath.Join(base, "dnsmasq.conf.guest"), "port=0\nconf-dir="+dir+"\n")
	write(filepath.Join(dir, upstreamFile), dnsInjection)
	check("missing dns_file_collision lan", ownership{})
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	check(dir, ownership{dnsDirs: map[string]bool{real: true}})
}
