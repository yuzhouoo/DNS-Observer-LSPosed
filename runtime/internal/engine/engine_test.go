package engine

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestConfigModes(t *testing.T) {
	c := DefaultConfig()
	if c.Validate() != nil {
		t.Fatal("off must work without core/network")
	}
	c.Mode = "dns"
	if c.Validate() == nil {
		t.Fatal("missing upstream accepted")
	}
	c.Bootstrap = "223.5.5.5"
	c.Upstreams = []Upstream{{"dns.example", 31053}}
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
	c.IPv4 = false
	c.IPv6 = false
	if c.Validate() == nil {
		t.Fatal("empty family accepted")
	}
	c = DefaultConfig()
	c.Mode = "tun"
	if c.Validate() == nil {
		t.Fatal("tun accepted")
	}
}
func TestAtomicPreservesLastFile(t *testing.T) {
	p := t.TempDir() + "/config.json"
	if e := AtomicJSON(p, map[string]string{"mode": "dns"}); e != nil {
		t.Fatal(e)
	}
	if e := AtomicJSON(p, make(chan int)); e == nil {
		t.Fatal("unserializable accepted")
	}
	b, _ := os.ReadFile(p)
	if !strings.Contains(string(b), "dns") {
		t.Fatal("old file lost")
	}
}
func TestDNSResponseAndFrames(t *testing.T) {
	q := queryPacket("example.com")
	a := append([]byte(nil), q...)
	a[2] |= 128
	if !validReply(q, a) {
		t.Fatal("valid response rejected")
	}
	bad := append([]byte(nil), a...)
	bad[0]++
	if validReply(q, bad) {
		t.Fatal("wrong ID accepted")
	}
	bad = append([]byte(nil), a...)
	bad[13] = 'x'
	if validReply(q, bad) {
		t.Fatal("different question accepted")
	}
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	go func() {
		c, e := l.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		h := make([]byte, 2)
		io.ReadFull(c, h)
		b := make([]byte, int(binary.BigEndian.Uint16(h)))
		io.ReadFull(c, b)
		b[2] |= 128
		c.Write(append([]byte{byte(len(b) >> 8), byte(len(b))}, b...))
	}()
	if _, e = exchange(context.Background(), "tcp", l.Addr().String(), q, false); e != nil {
		t.Fatal(e)
	}
}
func TestUDPOriginalDst(t *testing.T) {
	if _, e := originalDst([]byte{1, 2, 3}); e == nil {
		t.Fatal("missing metadata accepted")
	}
	if localSource(net.ParseIP("203.0.113.99")) {
		t.Fatal("remote source accepted")
	}
	if !localSource(net.ParseIP("127.0.0.1")) {
		t.Fatal("loopback rejected")
	}
}
func TestSIMMatchStrict(t *testing.T) {
	m := map[string]any{"rules": []any{"DOMAIN,example.com,DIRECT", "MATCH,old"}, "proxy-groups": []any{map[string]any{"name": "代理"}}}
	if e := rewriteMatch(m, "代理"); e != nil {
		t.Fatal(e)
	}
	if m["rules"].([]any)[1] != "MATCH,代理" {
		t.Fatal(m)
	}
	if rewriteMatch(m, "missing") == nil {
		t.Fatal("invalid group accepted")
	}
	m["rules"] = []any{"MATCH,DIRECT", "MATCH,DIRECT"}
	if rewriteMatch(m, "DIRECT") == nil {
		t.Fatal("multiple MATCH accepted")
	}
}

type fakeRunner struct {
	calls   [][]string
	blocked bool
	fail    string
}

func (f *fakeRunner) Run(a ...string) (string, error) {
	f.calls = append(f.calls, append([]string{}, a...))
	s := strings.Join(a, " ")
	if f.fail != "" && strings.Contains(s, f.fail) {
		return "", errors.New("injected failure")
	}
	if strings.Contains(s, "rule show") && f.blocked {
		return "0: from all lookup local\n100: from all unreachable\n32000: from all unreachable\n", nil
	}
	if strings.Contains(s, "-S YTDNS") {
		return "-N " + a[len(a)-1] + "\n", nil
	}
	return "", nil
}
func TestFirewallScopeAndCancellation(t *testing.T) {
	r := &fakeRunner{}
	home := t.TempDir()
	fw := Firewall{R: r, Home: home}
	c := DefaultConfig()
	c.Mode = "dns"
	c.IPv6 = true
	if e := fw.Install(c, true); e != nil {
		t.Fatal(e)
	}
	all := ""
	for _, a := range r.calls {
		all += strings.Join(a, " ") + "\n"
	}
	if strings.Contains(all, "--on-port 9898") {
		t.Fatal("DNS-only installed proxy")
	}
	if !strings.Contains(all, "--uid-owner 0") || !strings.Contains(all, "dport 53 lookup 19770") {
		t.Fatal("probe scope missing")
	}
	if strings.Contains(all, "ip4tables") {
		t.Fatal("invalid IPv4 executable")
	}
	if strings.Contains(all, "-F OUTPUT") {
		t.Fatal("global flush")
	}
	r = &fakeRunner{blocked: true}
	fw = Firewall{R: r, Home: t.TempDir()}
	if fw.Preflight(c) == nil {
		t.Fatal("foreign block ignored")
	}
	for _, a := range r.calls {
		if strings.Contains(strings.Join(a, " "), " rule del ") {
			t.Fatal("foreign block mutated")
		}
	}
	r = &fakeRunner{}
	fw = Firewall{R: r, Home: t.TempDir(), Allowed: func() bool { return false }}
	if fw.Install(c, false) == nil {
		t.Fatal("cancel ignored")
	}
	if len(r.calls) != 0 {
		t.Fatal("mutated after cancel")
	}
	r = &fakeRunner{}
	fw = Firewall{R: r, Home: t.TempDir()}
	if e := fw.Cleanup(); e != nil {
		t.Fatal(e)
	}
	if len(r.calls) != 0 {
		t.Fatal("unowned routing mutated")
	}
}
func TestOwnershipSnapshot(t *testing.T) {
	home := t.TempDir()
	r := &fakeRunner{}
	f := Firewall{R: r, Home: home}
	AtomicJSON(home+"/run/ownership.json", map[string]string{"owner": "foreign"})
	if f.Cleanup() == nil {
		t.Fatal("foreign marker accepted")
	}
	if len(r.calls) > 0 {
		t.Fatal("foreign marker mutated")
	}
	c := DefaultConfig()
	b, _ := json.Marshal(c)
	if !json.Valid(b) {
		t.Fatal("config JSON invalid")
	}
}

// Run only in an isolated network namespace. Exercises actual Linux TPROXY,
// original-destination UDP reply source, TCP framing, and own-rule teardown.
func TestKernelTPROXY(t *testing.T) {
	if os.Getenv("YUTONG_KERNEL_TEST") != "1" {
		t.Skip("privileged namespace test not enabled")
	}
	if os.Geteuid() != 0 {
		t.Fatal("kernel test requires isolated root namespace")
	}
	for _, bin := range []string{"iptables", "ip6tables", "ip"} {
		if _, e := exec.LookPath(bin); e != nil {
			t.Fatal(e)
		}
	}
	udp, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer udp.Close()
	_, port, _ := net.SplitHostPort(udp.LocalAddr().String())
	tcp, e := net.Listen("tcp4", "127.0.0.1:"+port)
	if e != nil {
		t.Fatal(e)
	}
	defer tcp.Close()
	go func() {
		for {
			b := make([]byte, 65535)
			n, a, e := udp.ReadFrom(b)
			if e != nil {
				return
			}
			b = b[:n]
			if len(b) > 12 {
				b[2] |= 128
				udp.WriteTo(b, a)
			}
		}
	}()
	go func() {
		for {
			c, e := tcp.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(time.Second))
				h := make([]byte, 2)
				if _, e := io.ReadFull(c, h); e != nil {
					return
				}
				b := make([]byte, int(binary.BigEndian.Uint16(h)))
				if _, e := io.ReadFull(c, b); e != nil {
					return
				}
				b[2] |= 128
				c.Write(append([]byte{byte(len(b) >> 8), byte(len(b))}, b...))
			}()
		}
	}()
	home := t.TempDir()
	log := NewLogger(home)
	cfg := DefaultConfig()
	cfg.Mode = "dns"
	d := NewDNS(cfg, log)
	d.ends = []endpoint{{addr: udp.LocalAddr().String(), group: 0}}
	if e := d.listenSockets(); e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	f := Firewall{R: &Commands{Log: log}, Home: home, Log: log}
	if e = f.Preflight(cfg); e != nil {
		t.Fatal(e)
	}
	defer f.Cleanup()
	if e = f.Install(cfg, true); e != nil {
		t.Fatal(e)
	}
	if e = f.Selftest(cfg); e != nil {
		t.Fatalf("probe UDP/TCP v4/v6: %v", e)
	}
	if e = f.Cleanup(); e != nil {
		t.Fatal(e)
	}
	if e = f.Install(cfg, false); e != nil {
		t.Fatal(e)
	}
	if e = f.Check(cfg); e != nil {
		t.Fatal(e)
	}
	if e = f.Selftest(cfg); e != nil {
		t.Fatal(e)
	}
	if e = f.ipt("4", "mangle", "-N", "FOREIGN_TEST"); e != nil {
		t.Fatal(e)
	}
	if e = f.ipt("4", "mangle", "-I", "OUTPUT", "1", "-j", "FOREIGN_TEST"); e != nil {
		t.Fatal(e)
	}
	if f.Check(cfg) == nil {
		t.Fatal("shadowed rules reported active")
	}
	if e = f.Cleanup(); e != nil {
		t.Fatal(e)
	}
	if e = f.ipt("4", "mangle", "-C", "OUTPUT", "-j", "FOREIGN_TEST"); e != nil {
		t.Fatal("cleanup removed foreign jump")
	}
}
