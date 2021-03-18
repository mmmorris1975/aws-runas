// +build !windows,!js

/*
 * Copyright (c) 2021 Michael Morris. All Rights Reserved.
 *
 * Licensed under the MIT license (the "License"). You may not use this file except in compliance
 * with the License. A copy of the License is located at
 *
 * https://github.com/mmmorris1975/aws-runas/blob/master/LICENSE
 *
 * or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License
 * for the specific language governing permissions and limitations under the License.
 */

package metadata

import (
	"fmt"
	"github.com/aws/aws-sdk-go-v2/config"
	"golang.org/x/sys/unix"
	"os"
	"runtime"
	"strconv"
	"syscall"
)

// making a bold assumption that anything non-Windows supports what we're doing ... this is probably buggy as hell.
func dropPrivileges() (err error) {
	// precedence list (1st one wins)
	// 1. SUDO_UID and SUDO_GID env vars
	// 2. ownership of default AWS config directory
	// 3. ownership of HOME env var (the pre-sudo value is retained) ... obtained via os.UserHomeDir()
	var uid, gid int

	uid, gid, err = checkSudoEnv()
	if err == nil {
		logger.Debugf("Found UID/GID from sudo env vars: UID: %d, GID: %d", uid, gid)
		return setPrivileges(uid, gid)
	}
	logger.Debugf("Error checking sudo env vars: %v", err)

	uid, gid, err = stat(config.DefaultSharedConfigFilename())
	if err == nil {
		logger.Debugf("Found UID/GID from cache directory ownership: UID: %d, GID: %d", uid, gid)
		return setPrivileges(uid, gid)
	}
	logger.Debugf("Error checking cache directory: %v", err)

	// Last option for getting pre-sudo uid/gid, fail if we see an error
	uid, gid, err = statHomeDir()
	if err == nil {
		logger.Debugf("Found UID/GID from home directory ownership: UID: %d, GID: %d", uid, gid)
		return setPrivileges(uid, gid)
	}
	logger.Debugf("Error checking home directory: %v", err)
	return err
}

func checkSudoEnv() (uid int, gid int, err error) {
	u, uok := os.LookupEnv("SUDO_UID")
	g, gok := os.LookupEnv("SUDO_GID")
	if uok && gok {
		uid, err = strconv.Atoi(u)
		if err != nil {
			return -1, -1, err
		}

		gid, err = strconv.Atoi(g)
		if err != nil {
			return -1, -1, err
		}

		return uid, gid, nil
	}
	return -1, -1, fmt.Errorf("sudo environment variables not found")
}

func stat(path string) (int, int, error) {
	if len(path) > 0 {
		st := new(unix.Stat_t)
		if err := unix.Stat(path, st); err != nil {
			// Whatever -1 will mean on the platform will certainly be better than returning 0 for the uid/gid values!
			return -1, -1, err
		}
		return int(st.Uid), int(st.Gid), nil
	}
	return -1, -1, fmt.Errorf("stat(): empty path")
}

func statHomeDir() (int, int, error) {
	h, err := os.UserHomeDir() // added in Go 1.12
	if err != nil {
		return -1, -1, err
	}
	return stat(h)
}

func setPrivileges(uid int, gid int) error {
	// REF: https://wiki.sei.cmu.edu/confluence/display/c/POS36-C.+Observe+correct+revocation+order+while+relinquishing+privileges

	if runtime.GOOS == "linux" {
		// Per https://github.com/golang/sys/blob/master/unix/syscall_linux.go, Setgid and Setuid are not supported on
		// Linux and just return an "Operation Not Supported" error, see https://github.com/golang/go/issues/1435
		// Make the raw syscalls to drop permissions until this gets resolved
		if _, _, err := syscall.Syscall(syscall.SYS_SETGID, uintptr(gid), 0, 0); err != 0 {
			return err
		}

		if _, _, err := syscall.Syscall(syscall.SYS_SETUID, uintptr(uid), 0, 0); err != 0 {
			return err
		}
		return nil
	}

	if err := unix.Setgid(gid); err != nil {
		return err
	}
	return unix.Setuid(uid)
}
