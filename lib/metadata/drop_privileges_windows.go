// requires windows specific build due to use of "golang.org/x/sys/unix" to manage privileges
// +build windows

package metadata

func dropPrivileges() (err error) {
	return nil
}
