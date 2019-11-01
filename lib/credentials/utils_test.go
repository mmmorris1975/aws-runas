package credentials

import (
	"fmt"
	"os"
	"testing"
	"time"
)

func TestStdinCredProvider(t *testing.T) {
	ch := make(chan string)

	go func() {
		defer close(ch)

		u, p, err := StdinCredProvider("", "")
		if err != nil {
			t.Error(err)
			return
		}

		ch <- fmt.Sprintf("%s:%s", u, p)
	}()

	time.Sleep(100 * time.Millisecond)
	fmt.Fprintln(os.Stdin, "auser")
	time.Sleep(100 * time.Millisecond)
	fmt.Fprintln(os.Stdin, "mypassword")

	// Doesn't seem to be testable, but this should serve as some kind of sanity check
	//for c := range ch {
	//	t.Log(c)
	//	if c != "auser:mypassword" {
	//		t.Error("data mismatch")
	//		return
	//	}
	//}
}

func TestStdinMfaTokenProvider(t *testing.T) {
	ch := make(chan string)

	go func() {
		defer close(ch)

		m, err := StdinMfaTokenProvider()
		if err != nil {
			t.Error(err)
			return
		}

		ch <- m
	}()

	time.Sleep(100 * time.Millisecond)
	fmt.Fprintln(os.Stdin, "54321")

	// Doesn't seem to be testable, but this should serve as some kind of sanity check
	//for c := range ch {
	//	t.Log(c)
	//	if c != "54321" {
	//		t.Error("data mismatch")
	//		return
	//	}
	//}
}
