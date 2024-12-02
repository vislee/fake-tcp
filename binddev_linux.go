//go:build linux
// +build linux

package main

import (
	"flag"
	"syscall"
)

var inf *string = nil

func init() {
	inf = flag.String("if", "", "interface")
}

func bindToDeviceFunc(fd int) error {
	if len(*inf) > 0 {
		return syscall.BindToDevice(fd, *inf)
	}
	return nil
}
