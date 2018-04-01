package main

import "testing"

func TestIsCumulative(t *testing.T) {
	c := new(cmdArg)
	if !c.IsCumulative() {
		t.Errorf("IsCumulative() is not true")
	}
}

func TestSetString(t *testing.T) {
	c := new(cmdArg)
	c.Set("val1")
	c.Set("val2")
	if len(*c) != 2 {
		t.Errorf("Expected 2 items, got %d", len(*c))
	}
	c.String()
}
