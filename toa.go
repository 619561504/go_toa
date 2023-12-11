/**
 * Created by wuhanjie on 2023/11/28 11:00
 */

package go_toa

import (
	"errors"
	"net"
	"sync"
)

var (
	once  sync.Once
	isRun bool
)

type options struct {
	mark          int
	maxGoroutines int
	maxRetry      int
}

type Option func(options *options)

func WithMark(mark int) Option {
	return func(opt *options) {
		opt.mark = mark
	}
}

func WithMaxGoroutines(maxGoroutines int) Option {
	return func(opt *options) {
		opt.maxGoroutines = maxGoroutines
	}
}

func WithMaxRetry(maxRetry int) Option {
	return func(opt *options) {
		opt.maxRetry = maxRetry
	}
}

func Run(opts ...Option) error {
	if isRun {
		return errors.New("toa already running")
	}
	var err error
	once.Do(func() {
		isRun = true
		err = run(opts...)
	})
	return err
}

func Dial(addr string, clientIp string, clientPort int) (net.Conn, error) {
	return dialWithRetry(addr, clientIp, clientPort)
}
func Close() error {
	return cl()
}
