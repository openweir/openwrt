package router

import "testing"

func TestDeniedOperation(t *testing.T) {
	for in, want := range map[string]string{
		`time="x" level=error msg="[tcp] dial direct (match ruleset/cn) 10.0.0.2:5000 --> api.example.com:443 error: dial tcp 1.2.3.4:443: connect: permission denied"`: "tcp dial direct match ruleset/cn <addr> --> <host>:443 error: dial tcp <addr>: connect",
		`level=error msg="start udp listener error: listen udp [::]:53: bind: permission denied"`:                                                                       "start udp listener error: listen udp <addr>: bind",
		`level=error msg="open /etc/openweir/secret/deep/file.yaml: operation not permitted"`:                                                                           "open /etc/openweir/...",
		`level=error msg="mystery"`: "",
	} {
		if got := deniedOperation(in); got != want {
			t.Errorf("%s\n got %q\nwant %q", in, got, want)
		}
	}
}
