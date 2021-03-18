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

package cli

import (
	"flag"
	"testing"
)

func TestVerboseFlag_Apply(t *testing.T) {
	fs := new(flag.FlagSet)
	f := &verboseFlag{Name: "test", Value: new(boolSlice)}

	_ = f.Apply(fs)

	if fs.Lookup(f.Name) == nil {
		t.Error("did not find flag in flagset")
	}
}

func TestVerboseFlag_GetUsage(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		if len(new(verboseFlag).GetUsage()) > 0 {
			t.Error("usage had value")
		}
	})

	t.Run("set", func(t *testing.T) {
		f := &verboseFlag{Usage: "use me"}
		if f.GetUsage() != f.Usage {
			t.Error("usage mismatch")
		}
	})
}

func TestVerboseFlag_GetValue(t *testing.T) {
	t.Run("nil value", func(t *testing.T) {
		if len(new(verboseFlag).GetValue()) > 0 {
			t.Error("GetValue had value")
		}
	})

	t.Run("empty value", func(t *testing.T) {
		f := &verboseFlag{Value: new(boolSlice)}
		if len(f.GetValue()) < 1 {
			t.Error("GetValue was empty")
		}
	})

	t.Run("good", func(t *testing.T) {
		f := &verboseFlag{Value: &boolSlice{val: []bool{true, true}}}
		if len(f.GetValue()) < 1 {
			t.Error("GetValue was empty")
		}
	})
}

func TestVerboseFlag_IsRequired(t *testing.T) {
	t.Run("false", func(t *testing.T) {
		f := &verboseFlag{Required: false}
		if f.IsRequired() {
			t.Error("non-required flag was required")
		}
	})

	t.Run("true", func(t *testing.T) {
		f := &verboseFlag{Required: true}
		if !f.IsRequired() {
			t.Error("required flag wasn't")
		}
	})
}

func TestVerboseFlag_IsSet(t *testing.T) {
	t.Run("true", func(t *testing.T) {
		f := &verboseFlag{Value: &boolSlice{val: []bool{true, true}}}
		if !f.IsSet() {
			t.Error("IsSet returned false")
		}
	})

	t.Run("false empty", func(t *testing.T) {
		f := &verboseFlag{Value: new(boolSlice)}
		if f.IsSet() {
			t.Error("IsSet returned true")
		}
	})

	t.Run("false nil", func(t *testing.T) {
		f := &verboseFlag{Value: nil}
		if f.IsSet() {
			t.Error("IsSet returned true")
		}
	})
}

func TestVerboseFlag_Names(t *testing.T) {
	f := &verboseFlag{
		Name:    "test",
		Aliases: []string{"t", "tst"},
	}
	if len(f.Names()) != len(f.Aliases)+1 {
		t.Error("invalid count")
	}
}

func TestVerboseFlag_String(t *testing.T) {
	if len(new(verboseFlag).String()) < 1 {
		t.Error("String() was empty")
	}
}

func TestVerboseFlag_TakesValue(t *testing.T) {
	if new(verboseFlag).TakesValue() {
		t.Error("TakesValue was true")
	}
}

func TestBoolSlice_Get(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		s := boolSlice{val: nil}
		if v := s.Get(); v.([]bool) != nil {
			t.Error("v was not nil")
		}
	})

	t.Run("empty", func(t *testing.T) {
		s := boolSlice{val: []bool{}}
		if v := s.Get(); len(v.([]bool)) > 0 {
			t.Error("v had elements")
		}
	})

	t.Run("with values", func(t *testing.T) {
		s := boolSlice{val: []bool{false, true, true, false, false}}
		if v := s.Get(); len(v.([]bool)) != len(s.val) {
			t.Error("invalid length")
		}
	})
}

func TestBoolSlice_IsBoolFlag(t *testing.T) {
	if !new(boolSlice).IsBoolFlag() {
		t.Error("IsBoolFlag returned false")
	}
}

func TestBoolSlice_Set(t *testing.T) {
	t.Run("true", func(t *testing.T) {
		s := new(boolSlice)
		_ = s.Set("true")
		if len(s.val) < 1 || !s.val[0] {
			t.Error("invalid internal state")
		}
	})

	t.Run("false", func(t *testing.T) {
		// Set does not add false elements to the internal list
		s := new(boolSlice)
		_ = s.Set("false")
		if len(s.val) > 0 {
			t.Error("invalid internal state")
		}
	})
}

func TestBoolSlice_String(t *testing.T) {
	if len(new(boolSlice).String()) < 1 {
		t.Error("String() invalid")
	}
}
