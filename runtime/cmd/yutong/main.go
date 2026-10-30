package main

import (
	"dev.yz/yutong/internal/engine"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func printJSON(v any) { b, _ := json.Marshal(v); fmt.Println(string(b)) }
func run() error {
	if os.Geteuid() != 0 {
		return errors.New("ROOT_REQUIRED")
	}
	home := engine.Home
	os.MkdirAll(home+"/logs", 0700)
	os.MkdirAll(home+"/run", 0700)
	args := os.Args[1:]
	if len(args) == 0 {
		return errors.New("usage: yutong manager|status|apply|boot|cleanup|logs|import-config|proxies|select")
	}
	switch args[0] {
	case "backup-app":
		return engine.BackupApp(home)
	case "restore-app":
		return engine.RestoreApp(home)
	case "stop":
		c, e := engine.LoadConfig(home)
		if e != nil {
			return e
		}
		c.Mode = "off"
		c.Revision = fmt.Sprint(time.Now().UnixNano())
		if e = engine.AtomicJSON(home+"/config.json", c); e != nil {
			return e
		}
		printJSON(map[string]string{"accepted": "off"})
		return nil
	case "diagnose":
		log := engine.NewLogger(home)
		r := &engine.Commands{Log: log}
		out := engine.Export(home)
		sys := map[string]string{}
		commands := [][]string{{"id"}, {"getenforce"}, {"settings", "get", "global", "private_dns_mode"}, {"settings", "get", "global", "private_dns_specifier"}, {"ip", "-4", "rule", "show"}, {"ip", "-6", "rule", "show"}, {"ip", "-4", "route", "show", "table", "all"}, {"ip", "-6", "route", "show", "table", "all"}, {"ip", "-6", "addr", "show"}, {"ls", "-lZ", home + "/bin/yutong"}}
		for _, fam := range []string{"iptables", "ip6tables"} {
			for _, table := range []string{"mangle", "nat", "filter"} {
				commands = append(commands, []string{fam, "-w", "1", "-t", table, "-S"})
			}
		}
		for _, a := range commands {
			s, e := r.Run(a...)
			if len(s) > 30000 {
				s = s[:30000]
			}
			sys[strings.Join(a, " ")] = s + fmt.Sprint(e)
		}
		out["system"] = sys
		printJSON(out)
		return nil
	case "manager":
		return engine.NewManager(home).Serve()
	case "status":
		printJSON(engine.Export(home))
		return nil
	case "logs":
		printJSON(engine.Export(home))
		return nil
	case "wanted":
		c, e := engine.LoadConfig(home)
		if e != nil {
			return e
		}
		if c.Mode == "off" {
			return errors.New("MODE_OFF")
		}
		return nil
	case "boot":
		c, e := engine.LoadConfig(home)
		if e != nil {
			return e
		}
		if !c.Boot || c.Mode == "off" {
			return nil
		}
		return engine.Launch(home)
	case "apply":
		if len(args) != 2 {
			return errors.New("apply requires base64 JSON")
		}
		b, e := base64.StdEncoding.DecodeString(args[1])
		if e != nil || len(b) > 65536 {
			return errors.New("invalid configuration")
		}
		var c engine.Config
		if e = json.Unmarshal(b, &c); e != nil {
			return e
		}
		if e = c.Validate(); e != nil {
			return e
		}
		if e = engine.ValidateCore(home, c); e != nil {
			return e
		}
		c.Revision = fmt.Sprint(time.Now().UnixNano())
		if e = engine.AtomicJSON(home+"/config.json", c); e != nil {
			return e
		}
		if c.Mode != "off" && !engine.IsRunning(home) {
			if e = engine.Launch(home); e != nil {
				return e
			}
		}
		if c.Mode == "off" && !engine.IsRunning(home) {
			if e = engine.CleanupCLI(home); e != nil {
				return fmt.Errorf("停止意图已保存，但清理未确认: %w", e)
			}
			engine.AtomicJSON(home+"/run/status.json", engine.Status{Version: "0.7.0-beta1", Mode: "off", Phase: "off", DNS: "off", Proxy: "off", IPv4: "off", IPv6: "off", Boot: c.Boot, Updated: time.Now().UnixMilli()})
		}
		printJSON(map[string]string{"accepted": c.Mode, "message": "运行意图已保存；最终结果以状态校验为准"})
		return nil
	case "cleanup":
		return engine.CleanupCLI(home)
	case "import-core":
		b, e := io.ReadAll(io.LimitReader(os.Stdin, 200<<20))
		if e != nil {
			return e
		}
		if len(b) < 64 || len(b) >= 200<<20 || string(b[:4]) != "\x7fELF" || b[4] != 2 || b[18] != 183 || b[19] != 0 {
			return errors.New("需要 arm64 ELF 核心，且不能超过200MiB")
		}
		if engine.IsRunning(home) {
			return errors.New("导入核心前请全部停止")
		}
		p := home + "/mihomo/mihomo"
		if e = engine.Atomic(p, b, 0700); e != nil {
			return e
		}
		printJSON(map[string]string{"path": p})
		return nil
	case "import-config":
		if engine.IsRunning(home) {
			return errors.New("导入配置前请全部停止；防止覆盖运行中配置")
		}
		b, e := io.ReadAll(io.LimitReader(os.Stdin, 4<<20))
		if e != nil {
			return e
		}
		if len(b) == 0 || len(b) >= 4<<20 {
			return errors.New("配置为空或超过4MiB")
		}
		p := home + "/mihomo/config.yaml"
		if old, e := os.ReadFile(p); e == nil {
			if e = engine.Atomic(p+".previous", old, 0600); e != nil {
				return e
			}
		}
		if e = engine.Atomic(p, b, 0600); e != nil {
			return e
		}
		printJSON(map[string]string{"path": p, "message": "已导入；启动前会执行 Mihomo -t 验证"})
		return nil
	case "proxies", "select":
		// Secret remains root-only, never exported to the APK or a public controller.
		b, e := os.ReadFile(home + "/run/mihomo.yaml")
		if e != nil {
			return e
		}
		secret := ""
		for _, l := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(l, "secret:") {
				secret = strings.Trim(strings.TrimSpace(strings.TrimPrefix(l, "secret:")), "\"'")
			}
		}
		if secret == "" {
			return errors.New("Mihomo 尚未就绪")
		}
		method, path, body := "GET", "/proxies", ""
		if args[0] == "select" {
			if len(args) != 3 {
				return errors.New("select GROUP NODE")
			}
			g, e := base64.StdEncoding.DecodeString(args[1])
			if e != nil {
				return e
			}
			n, e := base64.StdEncoding.DecodeString(args[2])
			if e != nil {
				return e
			}
			method = "PUT"
			path = "/proxies/" + url.PathEscape(string(g))
			j, _ := json.Marshal(map[string]string{"name": string(n)})
			body = string(j)
		}
		req, e := http.NewRequest(method, "http://127.0.0.1:9097"+path, strings.NewReader(body))
		if e != nil {
			return e
		}
		req.Header.Set("Authorization", "Bearer "+secret)
		req.Header.Set("Content-Type", "application/json")
		res, e := (&http.Client{Timeout: 5 * time.Second}).Do(req)
		if e != nil {
			return e
		}
		defer res.Body.Close()
		b, e = io.ReadAll(io.LimitReader(res.Body, 2<<20))
		if e != nil {
			return e
		}
		if res.StatusCode >= 300 {
			return fmt.Errorf("Mihomo API %d: %s", res.StatusCode, string(b))
		}
		if len(b) == 0 {
			printJSON(map[string]bool{"ok": true})
		} else {
			fmt.Println(string(b))
		}
		return nil
	case "pidcheck":
		if len(args) != 2 {
			return errors.New("pid required")
		}
		pid, e := strconv.Atoi(args[1])
		if e != nil || pid <= 1 {
			return errors.New("invalid pid")
		}
		b, e := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		if e != nil {
			return e
		}
		if !strings.Contains(string(b), home+"/bin/yutong\x00manager") {
			return errors.New("PID ownership mismatch")
		}
		return nil
	default:
		return errors.New("unknown command")
	}
}
func main() {
	if e := run(); e != nil {
		printJSON(map[string]string{"error": e.Error()})
		os.Exit(1)
	}
}

var _ = filepath.Separator
