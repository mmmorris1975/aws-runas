// +build !windows

package main

import (
	"os"
	"syscall"
)

func chown(f string) {
	if st, err := os.Stat(f); err == nil {
		var uid uint32
		switch s := st.Sys().(type) {
		case syscall.Stat_t:
			uid = s.Uid
		case *syscall.Stat_t:
			uid = s.Uid
		}

		if uid > 0 {
			_ = os.Chown(cookieFile, int(uid), -1)
		}
	}
}
