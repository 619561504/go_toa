//go:build !linux

/**
 * Created by wuhanjie on 2023/11/28 11:13
 */

package go_toa

import "net"

func run(opts ...Option) error {
	return nil
}

func dialWithRetry(addr string, ip string, port int) (net.Conn, error) {
	return net.Dial("tcp", addr)
}

func cl() error {
	return nil
}
