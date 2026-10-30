package engine

import (
	"context"
	"fmt"
	"os/exec"
	"sync"
	"time"
)

type Runner interface {
	Run(args ...string) (string, error)
}
type Commands struct {
	Log *Logger
	mu  sync.Mutex
}

func (c *Commands) Run(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	b, e := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
	s := string(b)
	if c.Log != nil {
		c.Log.Command(args, s, e)
	}
	if e != nil {
		return s, fmt.Errorf("%s: %w: %s", args[0], e, s)
	}
	return s, nil
}
