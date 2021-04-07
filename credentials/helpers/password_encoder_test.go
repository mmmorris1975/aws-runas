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

package helpers

import (
	"strings"
	"testing"
)

var (
	p = NewPasswordEncoder([]byte("...mY not very Secure kEy..."))

	shortPw     = "short"
	longPw      = "something not a multiple of the encryption blocksize"
	blockSizePw = "1234567890ABCDEF"
	blockMultPw = "0123456789abcdef1234567890ABCDEF"
)

func TestPasswordEncoder_Encode(t *testing.T) {
	t.Run("short password", func(t *testing.T) {
		e, err := p.Encode(shortPw, 16)
		if err != nil {
			t.Error(err)
			return
		}

		if !strings.HasPrefix(e, "10$") {
			t.Error("bad encoding")
		}
		t.Log(e)
	})

	t.Run("long password", func(t *testing.T) {
		e, err := p.Encode(longPw, 20)
		if err != nil {
			t.Error(err)
			return
		}

		if !strings.HasPrefix(e, "14$") {
			t.Error("bad encoding")
		}
		t.Log(e)
	})

	t.Run("blocksize password", func(t *testing.T) {
		e, err := p.Encode(blockSizePw, 10)
		if err != nil {
			t.Error(err)
			return
		}

		if !strings.HasPrefix(e, "a$") {
			t.Error("bad encoding")
		}
		t.Log(e)
	})

	t.Run("blocksize multiple password", func(t *testing.T) {
		e, err := p.Encode(blockMultPw, 18)
		if err != nil {
			t.Error(err)
			return
		}

		if !strings.HasPrefix(e, "12$") {
			t.Error("bad encoding")
		}
		t.Log(e)
	})

	t.Run("zero cost", func(t *testing.T) {
		pe := NewPasswordEncoder(nil)
		if _, err := pe.Encode("[", 0); err == nil {
			t.Error("did not receive expected error")
		}
	})
}

func TestPasswordEncoder_Decode(t *testing.T) {
	t.Run("short password", func(t *testing.T) {
		s, err := p.Decode("10$QVYF6DHFP4SRM$zjim/p3MVYKCOgn8y94iV6lD3NMdEs4+T0Ydepare7Q")
		if err != nil {
			t.Error(err)
			return
		}

		if s != shortPw {
			t.Error("bad decode")
		}
		t.Log(s)
	})

	t.Run("long password", func(t *testing.T) {
		//nolint:lll
		s, err := p.Decode("14$HZRAUH2IBDVKW$RQGvVSJo8ldii4Q6dMqUMk85Y9odLyJmrVPssWBt1zk9tlcuvM8Gs0ARo3f5J+TJVokRas03m60uCWpucyepJreNRRtEUHanqRTNDnon7g4BOoeHIkFd2htQgrrviLiP")
		if err != nil {
			t.Error(err)
			return
		}

		if s != longPw {
			t.Error("bad decode")
		}
		t.Log(s)
	})

	t.Run("blocksize password", func(t *testing.T) {
		s, err := p.Decode("a$YHP4ZOTFYIFMG$gt+Xca1ZauWqgkGfVB+gaLLqDKVoC4BdSYWQurLeJzD9pRhEkJspuCcgp+CYfKLg")
		if err != nil {
			t.Error(err)
			return
		}

		if s != blockSizePw {
			t.Error("bad decode")
		}
		t.Log(s)
	})

	t.Run("blocksize multiple password", func(t *testing.T) {
		s, err := p.Decode("12$LACIR5WCCXMEW$ensp4NRwdzCyNWzxBvbAbfk7tKEqPo73yLFXC2QH84LzvLYZDD1IrKwwSRonewEKhEDZUH+NSAYiqohQ7gt6cw")
		if err != nil {
			t.Error(err)
			return
		}

		if s != blockMultPw {
			t.Error("bad decode")
		}
		t.Log(s)
	})

	t.Run("invalid format", func(t *testing.T) {
		if _, err := p.Decode("x$a"); err == nil {
			t.Error("did not receive expected error")
			return
		}
	})

	t.Run("cost overflow", func(t *testing.T) {
		if _, err := p.Decode("100$ABC$xyz"); err == nil {
			t.Error("did not receive expected error")
			return
		}
	})

	t.Run("invalid salt", func(t *testing.T) {
		if _, err := p.Decode("10$q0lxe$adb"); err == nil {
			t.Error("did not receive expected error")
			return
		}
	})
}

func Test_rot32(t *testing.T) {
	s := p.encode("TeSt!23")
	if rot32(rot32(s)) != s {
		t.Error("double rot32 did not equal original string")
	}
}
