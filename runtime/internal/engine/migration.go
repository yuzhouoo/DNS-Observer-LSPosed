package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"syscall"
	"time"
)

const AppData = "/data/user/0/dev.yz.dnsobserver"
const AppPackage = "dev.yz.dnsobserver"

func copyDataTree(src, dst string, uid, gid int) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, e error) error {
		if os.IsNotExist(e) {
			return nil
		}
		if e != nil {
			return e
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("refuse symlink in app backup")
		}
		rel, e := filepath.Rel(src, path)
		if e != nil {
			return e
		}
		out := filepath.Join(dst, rel)
		if info.IsDir() {
			if e = os.MkdirAll(out, 0700); e != nil {
				return e
			}
			return os.Chown(out, uid, gid)
		}
		if !info.Mode().IsRegular() {
			return errors.New("nonregular app data")
		}
		in, e := os.Open(path)
		if e != nil {
			return e
		}
		defer in.Close()
		tmp, e := os.CreateTemp(filepath.Dir(out), ".restore-")
		if e != nil {
			return e
		}
		name := tmp.Name()
		defer os.Remove(name)
		if _, e = io.Copy(tmp, in); e == nil {
			e = tmp.Chmod(0600)
		}
		if e == nil {
			e = tmp.Chown(uid, gid)
		}
		if e == nil {
			e = tmp.Sync()
		}
		ce := tmp.Close()
		if e == nil {
			e = ce
		}
		if e == nil {
			e = os.Rename(name, out)
		}
		return e
	})
}
func stopApp() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	b, e := exec.CommandContext(ctx, "am", "force-stop", "--user", "0", AppPackage).CombinedOutput()
	if e != nil {
		return fmt.Errorf("force-stop failed: %w %s", e, b)
	}
	return nil
}
func BackupApp(home string) error {
	backup := home + "/app-backup"
	if _, e := os.Stat(backup + "/manifest.json"); e == nil {
		return nil
	}
	if _, e := os.Stat(AppData); os.IsNotExist(e) {
		return nil
	}
	if e := stopApp(); e != nil {
		return e
	}
	for _, name := range []string{"databases", "shared_prefs"} {
		src := AppData + "/" + name
		if _, e := os.Stat(src); os.IsNotExist(e) {
			continue
		}
		if e := copyDataTree(src, backup+"/"+name, 0, 0); e != nil {
			return e
		}
	}
	return AtomicJSON(backup+"/manifest.json", map[string]any{"package": AppPackage, "time": time.Now().Format(time.RFC3339), "format": 1})
}
func RestoreApp(home string) error {
	backup := home + "/app-backup"
	b, e := os.ReadFile(backup + "/manifest.json")
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	var meta map[string]any
	if json.Unmarshal(b, &meta) != nil || meta["package"] != AppPackage {
		return errors.New("backup identity invalid")
	}
	if _, e = os.Stat(backup + "/restored.json"); e == nil {
		return nil
	}
	st, e := os.Stat(AppData)
	if e != nil {
		return errors.New("请先安装新 APK，暂不要打开，再点击模块操作恢复")
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("app UID unknown")
	}
	files, _ := os.ReadDir(AppData + "/databases")
	if len(files) > 0 {
		return errors.New("新 APK 已有数据库，拒绝覆盖；请先导出新记录或清除新应用数据，再恢复")
	}
	if e = stopApp(); e != nil {
		return e
	}
	for _, name := range []string{"databases", "shared_prefs"} {
		src := backup + "/" + name
		if _, e = os.Stat(src); os.IsNotExist(e) {
			continue
		}
		if e = copyDataTree(src, AppData+"/"+name, int(stat.Uid), int(stat.Gid)); e != nil {
			return e
		}
	}
	// Old app-owned boot/repair must not compete with the module after restore.
	p := AppData + "/shared_prefs/dns_proxy.xml"
	if data, e := os.ReadFile(p); e == nil {
		re := regexp.MustCompile(`<boolean name="(?:takeover_enabled|module_backend)" value="(?:true|false)"\s*/>`)
		s := re.ReplaceAllString(string(data), "")
		s = regexp.MustCompile(`</map>`).ReplaceAllString(s, `<boolean name="takeover_enabled" value="false" /><boolean name="module_backend" value="true" /></map>`)
		if e = Atomic(p, []byte(s), 0600); e != nil {
			return e
		}
		if e = os.Chown(p, int(stat.Uid), int(stat.Gid)); e != nil {
			return e
		}
	}
	// Existing application directory labels are inherited, restorecon also fixes copied databases on enforcing ROMs.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if out, e := exec.CommandContext(ctx, "restorecon", "-RF", AppData).CombinedOutput(); e != nil {
		return fmt.Errorf("data copied but SELinux labels unconfirmed: %w %s", e, out)
	}
	return AtomicJSON(backup+"/restored.json", map[string]any{"uid": stat.Uid, "time": time.Now().Format(time.RFC3339)})
}
