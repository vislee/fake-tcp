//go:build !linux
// +build !linux

package main

import ()

func bindToDeviceFunc(fd int) error {
	return nil
}
