package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

type Firewall struct {
	R          Runner
	Home       string
	Log        *Logger
	Allowed    func() bool
	installing bool
}

func (f *Firewall) ipt(fam, table string, args ...string) error {
	if f.installing && f.Allowed != nil && !f.Allowed() {
		return errors.New("用户已更改模式，取消安装")
	}
	_, e := f.R.Run(append([]string{iptablesFor(fam), "-w", "1", "-t", table}, args...)...)
	return e
}
func (f *Firewall) ip(fam string, args ...string) (string, error) {
	if f.installing && f.Allowed != nil && !f.Allowed() {
		return "", errors.New("用户已更改模式，取消安装")
	}
	return f.R.Run(append([]string{"ip", "-" + fam}, args...)...)
}
func iptablesFor(fam string) string {
	if fam == "6" {
		return "ip6tables"
	}
	return "iptables"
}
func chain(suffix string) string { return Prefix + "_" + suffix }
func (f *Firewall) family(cfg Config) []string {
	a := []string{}
	if cfg.IPv4 {
		a = append(a, "4")
	}
	if cfg.IPv6 {
		a = append(a, "6")
	}
	return a
}
func (f *Firewall) blocked(fam string) error {
	s, e := f.ip(fam, "rule", "show")
	if e != nil {
		return e
	}
	for _, l := range strings.Split(s, "\n") {
		a := strings.Fields(l)
		if len(a) < 4 {
			continue
		}
		n, _ := strconv.Atoi(strings.TrimSuffix(a[0], ":"))
		if n < 9000 && a[1] == "from" && a[2] == "all" && (a[3] == "unreachable" || a[3] == "prohibit" || a[3] == "blackhole") {
			return fmt.Errorf("IPv%s 被外部早期路由阻断: %s", fam, l)
		}
	}
	return nil
}
func (f *Firewall) seed(fam, op string) error {
	nets := []string{"0.0.0.0/0"}
	if fam == "6" {
		nets = []string{"2000::/3", "fc00::/7"}
	}
	var last error
	for i, p := range []string{"udp", "tcp"} {
		for _, n := range nets {
			_, e := f.ip(fam, "rule", op, "pref", strconv.Itoa(9000+i), "to", n, "iif", "lo", "fwmark", "0x0/0x20000000", "ipproto", p, "dport", "53", "lookup", Table)
			if e != nil {
				last = e
			}
		}
	}
	return last
}

func unsupportedRuleSelector(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return (strings.Contains(s, "ipproto") || strings.Contains(s, "dport")) &&
		(strings.Contains(s, "wrong") || strings.Contains(s, "parse") || strings.Contains(s, "unknown") || strings.Contains(s, "invalid"))
}

// installInitialRoute prefers a port-scoped policy rule. Some Android ip
// binaries cannot encode FRA_IP_PROTO/FRA_DPORT even when the kernel can.
// In that case the ordinary first route is sufficient: mangle/OUTPUT marks
// DNS, then the 9100 rule performs the local re-route. Never replace this with
// a broad unmarked rule; that would loop all locally-originated traffic.
func (f *Firewall) installInitialRoute(fam string) (string, error) {
	if e := f.seed(fam, "add"); e == nil {
		return "exact", nil
	} else if !unsupportedRuleSelector(e) {
		f.seed(fam, "del")
		return "", fmt.Errorf("精确 DNS 初始路由安装失败: %w", e)
	}
	f.seed(fam, "del")
	target := "198.18.255.53"
	if fam == "6" {
		target = "2001:db8:ffff::53"
	}
	if out, e := f.ip(fam, "route", "get", target); e != nil || strings.TrimSpace(out) == "" {
		if e == nil {
			e = errors.New("无可用路由")
		}
		return "", fmt.Errorf("ip 工具不支持 ipproto/dport，且 IPv%s 无初始路由: %w", fam, e)
	}
	if f.Log != nil {
		f.Log.Event("ROUTE_SELECTOR_COMPAT", "IPv%s 的 ip 工具不支持 ipproto/dport；已验证普通初始路由，使用 OUTPUT 打标后二次选路", fam)
	}
	return "reroute", nil
}

func (f *Firewall) routeModes() map[string]string {
	b, e := os.ReadFile(f.Home + "/run/route-modes.json")
	if e != nil {
		return nil
	}
	var modes map[string]string
	if json.Unmarshal(b, &modes) != nil {
		return nil
	}
	return modes
}
func (f *Firewall) Preflight(cfg Config) error {
	if cfg.IPv4 {
		s, e := f.ip("4", "addr", "show", "dev", "lo")
		if e != nil {
			return e
		}
		if strings.Contains(s, "198.18.254.1/") {
			return errors.New("保留 loopback IPv4 地址被占用")
		}
	}
	if cfg.IPv6 {
		s, e := f.ip("6", "addr", "show", "dev", "lo")
		if e != nil {
			return e
		}
		if strings.Contains(s, "fd53:7974:6f6e::1/") {
			return errors.New("保留 loopback IPv6 地址已被占用")
		}
	}
	for _, fam := range f.family(cfg) {
		if e := f.blocked(fam); e != nil {
			return e
		}
		s, e := f.R.Run(iptablesFor(fam), "-w", "1", "-t", "mangle", "-S")
		if e != nil {
			return e
		}
		if strings.Contains(s, "DOBSR53") || strings.Contains(s, "DO6G061") {
			return errors.New("旧 APK DNS 接管仍有规则，请先在旧控制页关闭清理")
		}
		if strings.Contains(s, "-j BOX_") || strings.Contains(s, "-j DIVERT") {
			return errors.New("发现旧 Box / DIVERT 活动规则，请停止旧代理并完成卸载后重试")
		}
		rr, e := f.ip(fam, "rule", "show")
		if e != nil {
			return e
		}
		for _, l := range strings.Split(rr, "\n") {
			a := strings.Fields(l)
			if len(a) > 0 && (a[0] == "9000:" || a[0] == "9001:" || a[0] == "9100:") {
				return fmt.Errorf("保留路由优先级被占用: %s", l)
			}
		}
		rt, e := f.tableState(fam)
		if e != nil {
			return e
		}
		if strings.TrimSpace(rt) != "" {
			return errors.New("保留路由表19770非空")
		}
		for _, n := range []string{chain("OUT"), chain("PRE")} {
			if strings.Contains(s, "-N "+n+"\n") {
				return errors.New("残留规则需要先清理: " + n)
			}
		}
	}
	return nil
}
func (f *Firewall) Install(cfg Config, probe bool) error {
	if e := AtomicJSON(f.Home+"/run/ownership.json", map[string]string{"owner": "yutong-runtime-v1", "families": strings.Join(f.family(cfg), ",")}); e != nil {
		return e
	}
	f.installing = true
	defer func() { f.installing = false }()

	routeModes := map[string]string{}
	for _, fam := range f.family(cfg) {
		if e := f.blocked(fam); e != nil {
			return e
		}
		for _, c := range []string{chain("OUT"), chain("PRE")} {
			if e := f.ipt(fam, "mangle", "-N", c); e != nil {
				return e
			}
		}
		add := func(c string, a ...string) error { return f.ipt(fam, "mangle", append([]string{"-A", c}, a...)...) }
		if e := add(chain("OUT"), "-m", "mark", "--mark", "0x20000000/0x20000000", "-j", "RETURN"); e != nil {
			return e
		}
		loop := "127.0.0.0/8"
		local := "127.0.0.1"
		if fam == "6" {
			loop = "::1/128"
			local = "::1"
		}
		if e := add(chain("OUT"), "-d", loop, "-j", "RETURN"); e != nil {
			return e
		}
		for _, n := range []string{"224.0.0.0/4", "255.255.255.255/32"} {
			if fam == "4" {
				if e := add(chain("OUT"), "-d", n, "-j", "RETURN"); e != nil {
					return e
				}
			}
		}
		if fam == "6" {
			for _, n := range []string{"fe80::/10", "ff00::/8"} {
				if e := add(chain("OUT"), "-d", n, "-j", "RETURN"); e != nil {
					return e
				}
			}
		}
		// Probe only UID0; egress sockets of both workers carry a distinct bypass mark.
		for _, p := range []string{"udp", "tcp"} {
			a := []string{"-p", p, "--dport", "53"}
			if probe {
				a = append(a, "-m", "owner", "--uid-owner", "0")
			}
			if e := add(chain("OUT"), append(append([]string{}, a...), "-j", "MARK", "--set-xmark", Capture)...); e != nil {
				return e
			}
			if e := add(chain("OUT"), append(a, "-j", "ACCEPT")...); e != nil {
				return e
			}
			if e := add(chain("PRE"), "-p", p, "--dport", "53", "-j", "TPROXY", "--on-ip", local, "--on-port", strconv.Itoa(DNSPort), "--tproxy-mark", Capture); e != nil {
				return e
			}
		}
		if cfg.Mode == "proxy" && !probe {
			locals, _ := net.InterfaceAddrs()
			for _, address := range locals {
				ip, sub, e := net.ParseCIDR(address.String())
				if e != nil {
					continue
				}
				is4 := ip.To4() != nil
				if (fam == "4") != is4 {
					continue
				}
				bits := 128
				if is4 {
					bits = 32
				}
				own := ip.String() + "/" + strconv.Itoa(bits)
				if e := add(chain("OUT"), "-d", own, "-j", "RETURN"); e != nil {
					return e
				}
				if cfg.LANBypass && !ip.IsLoopback() {
					if e := add(chain("OUT"), "-d", sub.String(), "-j", "RETURN"); e != nil {
						return e
					}
				}
			}
			if cfg.LANBypass {
				nets := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"}
				if fam == "6" {
					nets = []string{"fc00::/7"}
				}
				for _, n := range nets {
					if e := add(chain("OUT"), "-d", n, "-j", "RETURN"); e != nil {
						return e
					}
				}
			}
			for _, uid := range cfg.BypassUIDs {
				if e := add(chain("OUT"), "-m", "owner", "--uid-owner", strconv.Itoa(uid), "-j", "RETURN"); e != nil {
					return e
				}
			}
			for _, p := range []string{"udp", "tcp"} {
				if e := add(chain("OUT"), "-p", p, "-j", "MARK", "--set-xmark", Capture); e != nil {
					return e
				}
				if e := add(chain("OUT"), "-p", p, "-j", "ACCEPT"); e != nil {
					return e
				}
				if e := add(chain("PRE"), "-p", p, "-j", "TPROXY", "--on-ip", local, "--on-port", strconv.Itoa(ProxyPort), "--tproxy-mark", Capture); e != nil {
					return e
				}
			}
		}
		route := []string{"route", "add", "local", "default", "dev", "lo", "table", Table}
		if fam == "4" {
			if _, e := f.ip(fam, "addr", "add", "198.18.254.1/32", "dev", "lo"); e != nil {
				return e
			}
			route = append(route, "src", "198.18.254.1")
		}
		if fam == "6" {
			if _, e := f.ip(fam, "addr", "add", "fd53:7974:6f6e::1/128", "dev", "lo"); e != nil {
				return e
			}
			route = append(route, "src", "fd53:7974:6f6e::1")
		}
		if _, e := f.ip(fam, route...); e != nil {
			return e
		}
		if _, e := f.ip(fam, "rule", "add", "pref", "9100", "fwmark", Capture, "lookup", Table); e != nil {
			return e
		}
		mode, e := f.installInitialRoute(fam)
		if e != nil {
			return e
		}
		routeModes[fam] = mode
		if e := f.ipt(fam, "mangle", "-I", "PREROUTING", "1", "-i", "lo", "-m", "mark", "--mark", Capture, "-j", chain("PRE")); e != nil {
			return e
		}
		if e := f.ipt(fam, "mangle", "-I", "OUTPUT", "1", "-j", chain("OUT")); e != nil {
			return e
		}
		if e := f.ipt(fam, "filter", "-N", chain("IN")); e != nil {
			return e
		}
		for _, p := range []string{"udp", "tcp"} {
			for _, port := range []string{"15353", "15354", "9898"} {
				if e := f.ipt(fam, "filter", "-A", chain("IN"), "!", "-i", "lo", "-p", p, "--dport", port, "-j", "REJECT"); e != nil {
					return e
				}
			}
		}
		if e := f.ipt(fam, "filter", "-I", "INPUT", "1", "-j", chain("IN")); e != nil {
			return e
		}
		if cfg.Block853 && !probe {
			if e := f.ipt(fam, "filter", "-N", chain("TLS")); e != nil {
				return e
			}
			for _, a := range [][]string{{"-m", "mark", "--mark", "0x20000000/0x20000000", "-j", "RETURN"}, {"-d", loop, "-j", "RETURN"}, {"-p", "tcp", "--dport", "853", "-j", "REJECT", "--reject-with", "tcp-reset"}, {"-p", "udp", "--dport", "853", "-j", "REJECT"}} {
				if e := f.ipt(fam, "filter", append([]string{"-A", chain("TLS")}, a...)...); e != nil {
					return e
				}
			}
			if e := f.ipt(fam, "filter", "-I", "OUTPUT", "1", "-j", chain("TLS")); e != nil {
				return e
			}
		}
	}
	if e := AtomicJSON(f.Home+"/run/route-modes.json", routeModes); e != nil {
		return e
	}
	snapshot := map[string]string{}
	for _, fam := range f.family(cfg) {
		for _, x := range []struct{ t, n string }{{"mangle", chain("OUT")}, {"mangle", chain("PRE")}, {"filter", chain("TLS")}, {"filter", chain("IN")}} {
			if x.n == chain("TLS") && (!cfg.Block853 || probe) {
				continue
			}
			s, e := f.R.Run(iptablesFor(fam), "-w", "1", "-t", x.t, "-S", x.n)
			if e != nil {
				return e
			}
			snapshot[fam+":"+x.t+":"+x.n] = s
		}
	}
	return AtomicJSON(f.Home+"/run/expected-rules.json", snapshot)
}
func (f *Firewall) Cleanup() error {
	b, e := os.ReadFile(f.Home + "/run/ownership.json")
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	var owner map[string]string
	if json.Unmarshal(b, &owner) != nil || owner["owner"] != "yutong-runtime-v1" {
		return errors.New("规则所有权记录无效，拒绝清理")
	}

	// Only exact own chain jumps, marks, table and selectors. Never flush a system chain.
	var errs []string
	for _, fam := range strings.Split(owner["families"], ",") {
		if fam != "4" && fam != "6" {
			return errors.New("所有权地址族无效")
		}
		// Read failures are not proof of absence. Missing IPv6 tables are acceptable only if no own marker exists.
		_, me := f.R.Run(iptablesFor(fam), "-w", "1", "-t", "mangle", "-S")
		if me != nil {
			errs = append(errs, me.Error())
			continue
		}
		for _, x := range []struct {
			table, parent, name string
			sel                 []string
		}{{"mangle", "OUTPUT", chain("OUT"), nil}, {"mangle", "PREROUTING", chain("PRE"), []string{"-i", "lo", "-m", "mark", "--mark", Capture}}, {"filter", "OUTPUT", chain("TLS"), nil}, {"filter", "INPUT", chain("IN"), nil}} {
			a := append(append([]string{}, x.sel...), "-j", x.name)
			for n := 0; n < 16; n++ {
				if f.ipt(fam, x.table, append([]string{"-C", x.parent}, a...)...) != nil {
					break
				}
				if e := f.ipt(fam, x.table, append([]string{"-D", x.parent}, a...)...); e != nil {
					errs = append(errs, e.Error())
					break
				}
			}
			if f.ipt(fam, x.table, "-S", x.name) == nil {
				if e := f.ipt(fam, x.table, "-F", x.name); e != nil {
					errs = append(errs, e.Error())
				}
				if e := f.ipt(fam, x.table, "-X", x.name); e != nil {
					errs = append(errs, e.Error())
				}
			}
		}
		f.seed(fam, "del")
		f.ip(fam, "rule", "del", "pref", "9100", "fwmark", Capture, "lookup", Table)
		f.ip(fam, "route", "del", "local", "default", "dev", "lo", "table", Table)
		if fam == "4" {
			s, e := f.ip(fam, "addr", "show", "dev", "lo")
			if e != nil {
				errs = append(errs, e.Error())
			} else if strings.Contains(s, "198.18.254.1/") {
				if _, e = f.ip(fam, "addr", "del", "198.18.254.1/32", "dev", "lo"); e != nil {
					errs = append(errs, e.Error())
				}
			}
		}
		if fam == "6" {
			s, e := f.ip(fam, "addr", "show", "dev", "lo")
			if e != nil {
				errs = append(errs, e.Error())
			} else if strings.Contains(s, "fd53:7974:6f6e::1/") {
				if _, e = f.ip(fam, "addr", "del", "fd53:7974:6f6e::1/128", "dev", "lo"); e != nil {
					errs = append(errs, e.Error())
				}
			}
		}
		s, e := f.R.Run(iptablesFor(fam), "-w", "1", "-t", "mangle", "-S")
		if e != nil || strings.Contains(s, Prefix+"_") {
			errs = append(errs, "IPv"+fam+" mangle 清理未确认")
		}
		s, e = f.R.Run(iptablesFor(fam), "-w", "1", "-t", "filter", "-S")
		if e != nil || strings.Contains(s, Prefix+"_") {
			errs = append(errs, "IPv"+fam+" filter 清理未确认")
		}
		s, e = f.ip(fam, "rule", "show")
		if e != nil || strings.Contains(s, "lookup "+Table) {
			errs = append(errs, "IPv"+fam+" 路由规则清理未确认")
		}
		s, e = f.tableState(fam)
		if e != nil || strings.TrimSpace(s) != "" {
			errs = append(errs, "IPv"+fam+" 路由表清理未确认")
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	os.Remove(f.Home + "/run/ownership.json")
	os.Remove(f.Home + "/run/expected-rules.json")
	os.Remove(f.Home + "/run/route-modes.json")
	return nil
}
func (f *Firewall) Check(cfg Config) error {
	b, e := os.ReadFile(f.Home + "/run/expected-rules.json")
	if e != nil {
		return e
	}
	var snapshots map[string]string
	if e = json.Unmarshal(b, &snapshots); e != nil {
		return e
	}
	for key, want := range snapshots {
		a := strings.Split(key, ":")
		if len(a) != 3 {
			return errors.New("snapshot invalid")
		}
		got, e := f.R.Run(iptablesFor(a[0]), "-w", "1", "-t", a[1], "-S", a[2])
		if e != nil || got != want {
			return fmt.Errorf("规则内容被更改: %s", key)
		}
	}
	modes := f.routeModes()
	for _, fam := range f.family(cfg) {
		if e := f.blocked(fam); e != nil {
			return e
		}
		parents := []struct{ table, parent, name string }{{"mangle", "OUTPUT", chain("OUT")}, {"mangle", "PREROUTING", chain("PRE")}, {"filter", "INPUT", chain("IN")}}
		if cfg.Block853 {
			parents = append(parents, struct{ table, parent, name string }{"filter", "OUTPUT", chain("TLS")})
		}
		for _, x := range parents {
			s, e := f.R.Run(iptablesFor(fam), "-w", "1", "-t", x.table, "-S", x.parent)
			if e != nil {
				return e
			}
			first := ""
			for _, l := range strings.Split(s, "\n") {
				if strings.HasPrefix(l, "-A ") {
					first = l
					break
				}
			}
			if !strings.HasSuffix(strings.TrimSpace(first), "-j "+x.name) {
				return errors.New("IPv" + fam + " 接管规则缺失或被覆盖: " + x.parent)
			}
		}
		rules, e := f.ip(fam, "rule", "show")
		if e != nil {
			return e
		}
		if !hasPolicy(rules, 9100, map[string]string{"fwmark": Capture, "lookup": Table}) {
			return errors.New("精确接管 mark 路由缺失")
		}
		nets := []string{"0.0.0.0/0"}
		lease := "198.18.254.1"
		if fam == "6" {
			nets = []string{"2000::/3", "fc00::/7"}
			lease = "fd53:7974:6f6e::1"
		}
		if modes[fam] == "exact" {
			for i, proto := range []string{"udp", "tcp"} {
				for _, subnet := range nets {
					if !hasPolicy(rules, 9000+i, map[string]string{"to": subnet, "iif": "lo", "fwmark": "0/0x20000000", "ipproto": proto, "dport": "53", "lookup": Table}) {
						return fmt.Errorf("IPv%s %s %s DNS 初始选路不完整", fam, subnet, proto)
					}
				}
			}
		} else if modes[fam] == "reroute" {
			target := "198.18.255.53"
			if fam == "6" {
				target = "2001:db8:ffff::53"
			}
			if out, e := f.ip(fam, "route", "get", target); e != nil || strings.TrimSpace(out) == "" {
				return fmt.Errorf("IPv%s 兼容初始路由已失效", fam)
			}
		} else {
			return fmt.Errorf("IPv%s 初始选路模式记录缺失", fam)
		}
		addr, e := f.ip(fam, "addr", "show", "dev", "lo")
		if e != nil || !strings.Contains(addr, lease+"/") {
			return errors.New("接管 loopback 源地址缺失")
		}
		route, e := f.tableState(fam)
		if e != nil {
			return e
		}
		lines := strings.Split(strings.TrimSpace(route), "\n")
		if len(lines) != 1 || !strings.HasPrefix(lines[0], "local ") || !strings.Contains(route, "dev lo") || !strings.Contains(route, "src "+lease) {
			return errors.New("接管本地路由/源地址不完整或被更改")
		}

	}
	return nil
}
func (f *Firewall) Selftest(cfg Config) error {
	if cfg.IPv4 {
		if e := f.Probe("198.18.255.53:53", false); e != nil {
			return e
		}
	}
	if cfg.IPv6 {
		if e := f.Probe("[2001:db8:ffff::53]:53", false); e != nil {
			return e
		}
	}
	return nil
}

func (f *Firewall) tableState(fam string) (string, error) {
	s, e := f.ip(fam, "route", "show", "table", Table)
	if e != nil {
		low := strings.ToLower(s)
		if strings.Contains(low, "fib table does not exist") || strings.Contains(low, "table does not exist") {
			return "", nil
		}
		return s, e
	}
	return s, nil
}

func (f *Firewall) IPv6Unavailable() error {
	if e := f.blocked("6"); e != nil {
		return e
	}
	for _, name := range []string{"all", "default", "lo"} {
		b, e := os.ReadFile("/proc/sys/net/ipv6/conf/" + name + "/disable_ipv6")
		if e != nil {
			return e
		}
		if strings.TrimSpace(string(b)) != "0" {
			return fmt.Errorf("IPv6 %s 被禁用；保留正常 IPv4", name)
		}
	}
	return nil
}

func (f *Firewall) Probe(addr string, bypass bool) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if f.Allowed != nil {
		go func() {
			ticker := time.NewTicker(200 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if !f.Allowed() {
						cancel()
						return
					}
				}
			}
		}()
	}
	return ProbeDNSContext(ctx, addr, bypass)
}

func hasPolicy(text string, pref int, want map[string]string) bool {
	for _, line := range strings.Split(text, "\n") {
		a := strings.Fields(line)
		if len(a) < 2 || a[0] != strconv.Itoa(pref)+":" {
			continue
		}
		got := map[string]string{"to": "0.0.0.0/0"}
		for i := 1; i+1 < len(a); i++ {
			switch a[i] {
			case "fwmark", "lookup", "iif", "ipproto", "dport", "to":
				got[a[i]] = a[i+1]
			}
		}
		ok := true
		for key, value := range want {
			actual := got[key]
			if key == "fwmark" {
				actual = markText(actual)
				value = markText(value)
			}
			if key == "ipproto" {
				if actual == "17" {
					actual = "udp"
				}
				if actual == "6" {
					actual = "tcp"
				}
			}
			if key == "dport" && actual == "53-53" {
				actual = "53"
			}
			if actual != value {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}
func markText(s string) string {
	a := strings.Split(s, "/")
	if len(a) != 2 {
		return s
	}
	v, e := strconv.ParseUint(a[0], 0, 32)
	if e != nil {
		return s
	}
	mask, e := strconv.ParseUint(a[1], 0, 32)
	if e != nil {
		return s
	}
	return fmt.Sprintf("%d/%d", v, mask)
}
