// +build !windows

package metadata

import (
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"runtime"
	"strconv"
)

func dropPrivileges() (err error) {
	// precedence list (1st one wins)
	// 1. SUDO_UID and SUDO_GID env vars
	// 2. ownership of cacheDir
	// 3. ownership of HOME env var (the pre-sudo value is retained) ... obtained via os.UserHomeDir()
	if runtime.GOOS != "windows" {
		// making a bold assumption that anything non-Windows supports what we're doing ... this is probably buggy as hell
		var uid int
		var gid int

		uid, gid, err := checkSudoEnv()
		if err != nil {
			// fall through
			log.Debugf("Error checking sudo env vars: %v", err)
		} else {
			log.Debugf("Found UID/GID from sudo env vars: UID: %d, GID: %d", uid, gid)
			return setPrivileges(uid, gid)
		}

		uid, gid, err = stat(cacheDir)
		if err != nil {
			// fall through
			log.Debugf("Error checking cache directory: %v", err)
		} else {
			log.Debugf("Found UID/GID from cache directory ownership: UID: %d, GID: %d", uid, gid)
			return setPrivileges(uid, gid)
		}

		// Last option for getting pre-sudo uid/gid, fail if we see an error
		uid, gid, err = statHomeDir()
		if err != nil {
			log.Debugf("Error checking home directory: %v", err)
			return err
		}
		log.Debugf("Found UID/GID from home directory ownership: UID: %d, GID: %d", uid, gid)
		return setPrivileges(uid, gid)
	}
	return nil
}

func checkSudoEnv() (int, int, error) {
	u, uok := os.LookupEnv("SUDO_UID")
	g, gok := os.LookupEnv("SUDO_GID")
	if uok && gok {
		uid, err := strconv.Atoi(u)
		if err != nil {
			return -1, -1, err
		}

		gid, err := strconv.Atoi(g)
		if err != nil {
			return -1, -1, err
		}

		return uid, gid, nil
	}
	return -1, -1, fmt.Errorf("sudo environment variables not found")
}

func statHomeDir() (int, int, error) {
	h, err := os.UserHomeDir() // added in Go 1.12
	if err != nil {
		return -1, -1, err
	}
	return stat(h)
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

func setPrivileges(uid int, gid int) error {
	// REF: https://wiki.sei.cmu.edu/confluence/display/c/POS36-C.+Observe+correct+revocation+order+while+relinquishing+privileges
	if err := unix.Setgid(gid); err != nil {
		return err
	}
	return unix.Setuid(uid)
}
