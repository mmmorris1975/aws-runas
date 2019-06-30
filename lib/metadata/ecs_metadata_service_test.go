package metadata

import "testing"

func TestFindLoopback(t *testing.T) {
	a, err := setupListener()
	if err != nil {
		t.Error(err)
		return
	}
	t.Log(a.Addr())
}
