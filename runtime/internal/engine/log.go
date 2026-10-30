package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

type Logger struct {
	home  string
	mu    sync.Mutex
	debug bool
}

func NewLogger(home string) *Logger { return &Logger{home: home} }
func (l *Logger) Write(kind string, v any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	os.MkdirAll(l.home+"/logs", 0700)
	p := l.home + "/logs/" + kind + ".jsonl"
	if st, e := os.Stat(p); e == nil && st.Size() > 2*1024*1024 {
		os.Rename(p+".1", p+".2")
		os.Rename(p, p+".1")
	}
	f, e := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		return
	}
	defer f.Close()
	b, _ := json.Marshal(map[string]any{"time": time.Now().Format(time.RFC3339Nano), "event": v})
	f.Write(append(b, '\n'))
}
func (l *Logger) Event(code string, format string, args ...any) {
	l.Write("events", map[string]any{"code": code, "message": fmt.Sprintf(format, args...)})
}
func (l *Logger) Command(args []string, out string, e error) {
	if len(out) > 4000 {
		out = out[:4000] + " [truncated]"
	}
	l.Write("commands", map[string]any{"args": args, "output": out, "error": fmt.Sprint(e)})
}
func Tail(path string, limit int) string {
	b, e := os.ReadFile(path)
	if e != nil {
		return ""
	}
	if len(b) > limit {
		b = b[len(b)-limit:]
		if i := strings.IndexByte(string(b), '\n'); i >= 0 {
			b = b[i+1:]
		}
	}
	return string(b)
}
