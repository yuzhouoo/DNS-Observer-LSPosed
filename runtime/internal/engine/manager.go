package engine

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Status struct {
	Version string `json:"version"`
	PID     int    `json:"pid"`
	Mode    string `json:"mode"`
	Phase   string `json:"phase"`
	DNS     string `json:"dns"`
	Proxy   string `json:"proxy"`
	IPv4    string `json:"ipv4"`
	IPv6    string `json:"ipv6"`
	Error   string `json:"error"`
	Updated int64  `json:"updated"`
	RetryAt int64  `json:"retry_at"`
	Network string `json:"network"`
	SIM     string `json:"sim"`
	Boot    bool   `json:"boot"`
}
type Manager struct {
	Home            string
	Log             *Logger
	R               Runner
	FW              *Firewall
	core            *Core
	dns             *DNS
	mu              sync.Mutex
	status          Status
	current         Config
	hash            [32]byte
	changed         bool
	retry           int
	lastResolve     time.Time
	lastNetwork     string
	lastSIM         time.Time
	lastHealth      time.Time
	nextRetry       time.Time
	repairRequested bool
	lastState       string
	lastWrite       time.Time
}

func NewManager(home string) *Manager {
	l := NewLogger(home)
	r := &Commands{Log: l}
	return &Manager{Home: home, Log: l, R: r, FW: &Firewall{R: r, Home: home, Log: l}, core: &Core{Home: home, Log: l, R: r}, status: Status{Version: "0.7.0-beta1", PID: os.Getpid(), Mode: "off", Phase: "initializing", DNS: "off", Proxy: "off", IPv4: "off", IPv6: "off"}}
}
func (m *Manager) state() {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, _ := json.Marshal(m.status)
	if string(b) == m.lastState && time.Since(m.lastWrite) < 15*time.Second {
		return
	}
	m.status.Updated = time.Now().UnixMilli()
	b, _ = json.Marshal(m.status)
	m.lastState = string(b)
	m.lastWrite = time.Now()
	AtomicJSON(m.Home+"/run/status.json", m.status)
}
func (m *Manager) stop() error {
	m.status.Phase = "stopping"
	m.state()
	e := m.FW.Cleanup()
	m.core.Stop()
	if m.dns != nil {
		m.dns.Close()
		m.dns = nil
	}
	m.status.DNS = "off"
	m.status.Proxy = "off"
	m.status.IPv4 = "off"
	m.status.IPv6 = "off"
	if e != nil {
		m.status.Phase = "cleanup_unconfirmed"
		m.status.Error = e.Error()
	} else {
		m.status.Phase = "off"
		m.status.Error = ""
	}
	m.state()
	m.Log.Event("STOP_RESULT", "rules-clean=%t error=%v", e == nil, e)
	return e
}
func (m *Manager) apply(c Config) error {
	if e := c.Validate(); e != nil {
		return e
	}
	requested := c
	m.FW.Allowed = func() bool {
		mp, _ := os.ReadFile(m.Home + "/runtime/module-path")
		for _, flag := range []string{"disable", "remove"} {
			if _, e := os.Stat(strings.TrimSpace(string(mp)) + "/" + flag); e == nil {
				return false
			}
		}
		wanted, e := LoadConfig(m.Home)
		if e != nil {
			return false
		}
		a, _ := json.Marshal(wanted)
		b, _ := json.Marshal(requested)
		return string(a) == string(b)
	}
	m.status.Mode = c.Mode
	m.status.Boot = c.Boot
	if e := m.stop(); e != nil {
		return e
	}
	if c.Mode == "off" {
		m.current = c
		return nil
	}
	m.status.Phase = "starting"
	m.status.Error = ""
	m.state()
	partial := ""
	if c.IPv4 && c.IPv6 {
		if e := m.FW.IPv6Unavailable(); e != nil {
			c.IPv6 = false
			partial = e.Error()
			m.Log.Event("IPV6_PENDING", "%v", e)
		}
	}
	if e := m.FW.Preflight(c); e != nil {
		return e
	}
	d := NewDNS(requested, m.Log)
	if e := d.Start(); e != nil {
		return e
	}
	m.dns = d
	if c.IPv6 && !d.ready6.Load() {
		if !c.IPv4 {
			return errors.New("IPv6 listener unavailable")
		}
		c.IPv6 = false
		partial = "IPv6 监听未就绪，正常 IPv4 保留"
	}
	m.status.DNS = "listening"
	// Ensure local relay works before any interception / proxy startup.
	if e := ProbeDNS("127.0.0.1:15353", true); e != nil {
		return e
	}
	target := ""
	if c.Mode == "proxy" {
		var e error
		target, e = m.core.SIMTarget(c)
		if e != nil {
			return e
		}
		if e = m.core.Start(c, target); e != nil {
			return e
		}
		m.status.Proxy = "ready"
		if e = ProbeDNS("127.0.0.1:1053", true); e != nil {
			return e
		}
		d.viaCore.Store(true)
	}
	probe := c
	probe.Mode = "dns"
	probe.Block853 = false
	if e := m.FW.Install(probe, true); e != nil {
		return e
	}
	if e := m.FW.Selftest(c); e != nil {
		return fmt.Errorf("受限 DNS53 原始目标/回包自检失败: %w", e)
	}
	if e := m.FW.Cleanup(); e != nil {
		return e
	}
	if e := m.FW.Install(c, false); e != nil {
		return e
	}
	if e := m.FW.Check(c); e != nil {
		return e
	}
	if e := m.FW.Selftest(c); e != nil {
		return e
	}
	m.current = c
	m.status.DNS = "verified"
	if c.IPv4 {
		m.status.IPv4 = "verified"
	}
	if c.IPv6 {
		m.status.IPv6 = "verified"
	}
	m.status.SIM = target
	m.status.Phase = "running"
	m.status.Error = ""
	if partial != "" {
		m.status.Phase = "partial"
		m.status.IPv6 = "unavailable"
		m.status.Error = partial
	}
	m.retry = 0
	m.nextRetry = time.Time{}
	m.lastResolve = time.Now()
	m.Log.Event("MODE_ACTIVE", "mode=%s ipv4=%t ipv6=%t DNS=verified proxy=%s", c.Mode, c.IPv4, c.IPv6, m.status.Proxy)
	m.state()
	return nil
}
func (m *Manager) failed(c Config, e error) {
	m.Log.Event("APPLY_FAILED", "%v", e)
	clean := m.stop()
	m.status.Mode = c.Mode
	m.status.Phase = "failed"
	m.status.Error = e.Error()
	if clean != nil {
		m.status.Error += "; rollback: " + clean.Error()
	}
	m.retry++
	seconds := 5 * (1 << min(m.retry-1, 5))
	m.nextRetry = time.Now().Add(time.Duration(seconds) * time.Second)
	m.status.RetryAt = m.nextRetry.UnixMilli()
	m.state()
}
func (m *Manager) network() string {
	a := []string{}
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		if i.Flags&net.FlagLoopback != 0 {
			continue
		}
		v, _ := i.Addrs()
		a = append(a, fmt.Sprintf("%s:%d:%v", i.Name, i.Flags, v))
	}
	return strings.Join(a, "|")
}
func (m *Manager) refreshRules(c Config) error {
	m.status.Phase = "repairing_rules"
	m.state()
	if e := m.FW.Cleanup(); e != nil {
		return e
	}
	if e := m.FW.Preflight(c); e != nil {
		return e
	}
	if e := m.FW.Install(c, false); e != nil {
		return e
	}
	if e := m.FW.Check(c); e != nil {
		return e
	}
	if e := m.FW.Selftest(c); e != nil {
		return e
	}
	m.status.Phase = "running"
	m.status.DNS = "verified"
	m.status.Error = ""
	m.state()
	m.Log.Event("RULE_REPAIR_OK", "workers retained; UDP/TCP reply verified")
	return nil
}
func (m *Manager) Serve() error {
	if e := os.MkdirAll(m.Home+"/run", 0700); e != nil {
		return e
	}
	os.MkdirAll(m.Home+"/logs", 0700)
	lock, e := os.OpenFile(m.Home+"/run/manager.lock", os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return e
	}
	defer lock.Close()
	if e = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		return errors.New("manager already running")
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	Atomic(m.Home+"/run/manager.pid", []byte(fmt.Sprint(os.Getpid())), 0600)
	// Parent manager death terminates its Mihomo child. A restarted supervisor cleans only marked own residue.
	m.Log.Event("MANAGER_START", "pid=%d version=%s", os.Getpid(), m.status.Version)
	cfg, e := LoadConfig(m.Home)
	if e != nil {
		return e
	}
	sig := make(chan os.Signal, 2)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(sig)
	dirty := make(chan struct{}, 1)
	go routeEvents(dirty)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	force := true
	pending := time.Time{}
	for {
		select {
		case <-sig:
			m.stop()
			return nil
		case <-dirty:
			pending = time.Now().Add(2 * time.Second)
		case <-ticker.C:
		}
		wanted, e := LoadConfig(m.Home)
		if e != nil {
			m.status.Error = e.Error()
			m.state()
			continue
		}
		b, _ := json.Marshal(wanted)
		hash := sha256.Sum256(b)
		if force || hash != m.hash {
			force = false
			m.hash = hash
			cfg = wanted
			m.retry = 0
			m.Log.Event("MODE_REQUEST", "mode=%s v4=%t v6=%t boot=%t", cfg.Mode, cfg.IPv4, cfg.IPv6, cfg.Boot)
			old := m.current
			wasRunning := m.dns != nil
			if e = m.apply(cfg); e != nil {
				wanted, _ := LoadConfig(m.Home)
				wb, _ := json.Marshal(wanted)
				if wanted.Mode != "off" && sha256.Sum256(wb) == hash && wasRunning && old.Mode != "off" {
					m.Log.Event("CONFIG_ROLLBACK", "new mode failed: %v; restoring previous validated configuration", e)
					if x := AtomicJSON(m.Home+"/config.json", old); x == nil {
						if x = m.apply(old); x == nil {
							m.status.Phase = "running_rolled_back"
							m.status.Error = "新配置应用失败，已恢复上一配置: " + e.Error()
							m.state()
							cfg = old
							ob, _ := json.Marshal(old)
							m.hash = sha256.Sum256(ob)
						} else {
							m.failed(old, x)
						}
					} else {
						m.failed(cfg, x)
					}
				} else {
					m.failed(cfg, e)
				}
			}
			if cfg.Mode == "off" {
				return nil
			}
			continue
		}
		if cfg.Mode == "off" {
			m.stop()
			return nil
		}
		now := time.Now()
		if !pending.IsZero() && now.After(pending) {
			pending = time.Time{}
			m.Log.Event("NETWORK_EVENT", "route/address/link changed")
			m.lastHealth = time.Time{}
			m.lastResolve = time.Time{}
		}
		if m.status.Phase == "proxy_unavailable_dns_running" {
			if cfg.Repair && now.After(m.nextRetry) {
				if e = m.apply(cfg); e != nil {
					m.failed(cfg, e)
				}
			}
			m.state()
			continue
		}
		if m.status.Phase == "failed" {
			if cfg.Repair && now.After(m.nextRetry) {
				if e = m.apply(cfg); e != nil {
					m.failed(cfg, e)
				}
			}
			m.state()
			continue
		}
		if now.Sub(m.lastHealth) < 15*time.Second {
			m.state()
			continue
		}
		m.lastHealth = now
		network := m.network()
		networkChanged := network != m.lastNetwork
		if networkChanged {
			m.lastNetwork = network
			m.status.Network = network
			m.lastResolve = time.Time{}
			m.Log.Event("NETWORK_SNAPSHOT", "%s", network)
		}
		if m.adjustFamilies(cfg) {
			m.state()
			continue
		}
		if networkChanged && cfg.Mode == "proxy" && cfg.LANBypass && cfg.Repair {
			if e = m.refreshRules(m.current); e != nil {
				m.failed(cfg, e)
				continue
			}
		}
		if cfg.Mode == "proxy" && !m.core.Alive() {
			m.status.Proxy = "exited"
			m.proxyFailed(cfg, errors.New("Mihomo owned child exited"))
			continue
		}
		if m.dns == nil {
			m.failed(cfg, errors.New("DNS worker absent"))
			continue
		}
		if e = m.FW.Check(m.current); e != nil {
			m.Log.Event("RULE_HEALTH_FAILED", "%v", e)
			if cfg.Repair {
				if e = m.refreshRules(m.current); e != nil {
					m.failed(cfg, e)
				}
			} else {
				m.status.Phase = "degraded"
				m.status.Error = e.Error()
			}
			continue
		}
		if now.Sub(m.lastResolve) > 5*time.Minute {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			e = m.dns.Resolve(ctx)
			cancel()
			m.lastResolve = now
			if e != nil {
				m.status.DNS = "upstream_unavailable"
				m.status.Phase = "upstream_unavailable"
				m.status.Error = e.Error()
				m.Log.Event("UPSTREAM_REFRESH_FAILED", "%v; retained previous endpoint set", e)
			} else {
				m.status.DNS = "verified"
				m.status.Error = ""
			}
		}
		if e = ProbeDNS("127.0.0.1:15353", true); e != nil {
			m.status.DNS = "upstream_unavailable"
			m.status.Phase = "upstream_unavailable"
			m.status.Error = e.Error()
			m.Log.Event("DNS_HEALTH_FAILED", "%v", e)
		} else {
			m.status.DNS = "verified"
			if m.status.Phase == "degraded" || m.status.Phase == "upstream_unavailable" {
				m.status.Phase = "running"
				m.status.Error = ""
			}
		}
		if cfg.Mode == "proxy" && cfg.SIMMatch {
			if e = m.core.UpdateSIM(cfg); e != nil {
				m.Log.Event("SIM_MATCH_PENDING", "%v", e)
			} else {
				m.status.SIM = m.core.group
			}
		}
		m.state()
	}
}
func routeEvents(out chan<- struct{}) {
	fd, e := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_ROUTE)
	if e != nil {
		return
	}
	defer syscall.Close(fd)
	if syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK, Groups: 1 | 0x10 | 0x100 | 0x40 | 0x400}) != nil {
		return
	}
	b := make([]byte, 8192)
	for {
		if _, _, e = syscall.Recvfrom(fd, b, 0); e != nil {
			return
		}
		select {
		case out <- struct{}{}:
		default:
		}
	}
}
func ReadStatus(home string) Status {
	s := Status{Version: "0.7.0-beta1", Mode: "off", Phase: "not_running", DNS: "off", Proxy: "off", IPv4: "off", IPv6: "off"}
	b, e := os.ReadFile(home + "/run/status.json")
	if e == nil {
		json.Unmarshal(b, &s)
	}
	if s.Phase == "off" {
		s.PID = 0
	}
	if s.PID > 1 {
		cmdline, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", s.PID))
		if e = syscall.Kill(s.PID, 0); e != nil || !strings.Contains(string(cmdline), home+"/bin/yutong\x00manager") || time.Now().UnixMilli()-s.Updated > 90000 {
			s.Phase = "manager_unconfirmed"
			s.Error = "Root 后台未确认存活；请检查 supervisor 日志与 PID 所有权"
		}
	}
	c, e := LoadConfig(home)
	if e == nil {
		s.Mode = c.Mode
		s.Boot = c.Boot
	}
	return s
}
func Export(home string) map[string]any {
	c, _ := LoadConfig(home)
	return map[string]any{"status": ReadStatus(home), "config": c, "events": Tail(home+"/logs/events.jsonl", 40000), "commands": Tail(home+"/logs/commands.jsonl", 50000), "dns": JSONLines(home + "/logs/dns.jsonl"), "supervisor": Tail(home+"/logs/supervisor.log", 16000), "mihomo": Tail(home+"/logs/mihomo.jsonl", 20000)}
}
func Launch(home string) error {
	path := home + "/runtime/supervisor.sh"
	if _, e := os.Stat(path); e != nil {
		return errors.New("KernelSU 运行文件未安装")
	}
	cmd := exec.Command("/system/bin/sh", path)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	f, e := os.OpenFile(home+"/logs/supervisor.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	cmd.Stdout = f
	cmd.Stderr = f
	if e = cmd.Start(); e != nil {
		return e
	}
	return cmd.Process.Release()
}
func IsRunning(home string) bool {
	s := ReadStatus(home)
	return s.PID > 1 && s.Phase != "manager_unconfirmed" && s.Phase != "not_running" && s.Phase != "off"
}
func CleanupCLI(home string) error {
	m := NewManager(home)
	if IsRunning(home) {
		return errors.New("后台仍运行，请先选择全部停止并等待完成")
	}
	return m.FW.Cleanup()
}

var _ = filepath.Separator

func (m *Manager) proxyFailed(cfg Config, cause error) {
	m.Log.Event("PROXY_FAILED_KEEP_DNS", "%v", cause)
	m.core.Stop()
	if m.dns == nil {
		m.failed(cfg, cause)
		return
	}
	m.dns.viaCore.Store(false)
	dnsOnly := cfg
	dnsOnly.Mode = "dns"
	if e := m.FW.Cleanup(); e != nil {
		m.failed(cfg, e)
		return
	}
	if e := m.FW.Install(dnsOnly, false); e != nil {
		m.failed(cfg, e)
		return
	}
	if e := m.FW.Selftest(dnsOnly); e != nil {
		m.failed(cfg, e)
		return
	}
	m.current = dnsOnly
	m.status.Phase = "proxy_unavailable_dns_running"
	m.status.Proxy = "failed"
	m.status.DNS = "verified"
	m.status.Error = cause.Error()
	m.nextRetry = time.Now().Add(10 * time.Second)
	m.status.RetryAt = m.nextRetry.UnixMilli()
	m.state()
}

// A blocked/lost IPv6 family must not tear down healthy IPv4 workers.
func (m *Manager) adjustFamilies(wanted Config) bool {
	if !wanted.IPv4 || !wanted.IPv6 || m.dns == nil {
		return false
	}
	reason := m.FW.IPv6Unavailable()
	if reason != nil && m.current.IPv6 {
		active := m.current
		active.IPv6 = false
		if e := m.refreshRules(active); e != nil {
			m.failed(wanted, e)
			return true
		}
		m.current = active
		m.status.IPv6 = "unavailable"
		m.status.Phase = "partial"
		m.status.Error = reason.Error()
		m.Log.Event("IPV6_PAUSED_KEEP_IPV4", "%v", reason)
		return true
	}
	if reason == nil && !m.current.IPv6 && wanted.Repair {
		if e := m.dns.listenFamily("6"); e != nil {
			m.status.IPv6 = "listener_pending"
			m.status.Error = e.Error()
			return true
		}
		if wanted.Mode == "proxy" && ProbeTCP("[::1]:9898") != nil {
			m.dns.viaCore.Store(false)
			dnsOnly := m.current
			dnsOnly.Mode = "dns"
			if e := m.refreshRules(dnsOnly); e != nil {
				m.failed(wanted, e)
				return true
			}
			m.core.Stop()
			target, e := m.core.SIMTarget(wanted)
			if e == nil {
				e = m.core.Start(wanted, target)
			}
			if e != nil {
				m.proxyFailed(wanted, e)
				return true
			}
			m.dns.viaCore.Store(true)
		}
		if e := m.refreshRules(wanted); e != nil {
			m.failed(wanted, e)
			return true
		}
		m.current = wanted
		m.status.IPv6 = "verified"
		m.status.IPv4 = "verified"
		m.status.Phase = "running"
		m.status.Error = ""
		m.Log.Event("IPV6_RECOVERED", "IPv4 worker retained")
		return true
	}
	return false
}
