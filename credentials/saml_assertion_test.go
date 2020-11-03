package credentials

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestSamlAssertion_RoleDetails(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		if _, err := new(SamlAssertion).RoleDetails(); err == nil {
			t.Error("did not receive expected error")
		}
	})

	t.Run("no data", func(t *testing.T) {
		data := `my mock saml assertion`
		b64 := base64.StdEncoding.EncodeToString([]byte(data))
		a := SamlAssertion(b64)

		rd, err := (&a).RoleDetails()
		if err != nil {
			t.Error(err)
			return
		}

		if len(rd.Roles()) > 0 {
			t.Error("unexpected data returned")
		}
	})

	t.Run("good", func(t *testing.T) {
		data := `
<someTag>arn:aws:iam::01234567890:role/mockRole1,arn:aws:iam::01234567890:saml-provider/mockPrincipal1</someTag>
<someTag>arn:aws:iam::01234567890:saml-provider/mockPrincipal2,arn:aws:iam::01234567890:role/mockRole2</someTag>
`
		b64 := base64.StdEncoding.EncodeToString([]byte(data))
		a := SamlAssertion(b64)
		rd, err := (&a).RoleDetails()
		if err != nil {
			t.Error(err)
			return
		}

		if len(rd.Roles()) < 2 {
			t.Error("role data mismatch")
		}

		for _, v := range rd.Roles() {
			if !strings.Contains(v, "mockRole") {
				t.Errorf("bad role name %s", v)
			}
		}

		if len(rd.Principals()) < 2 {
			t.Error("principal data mismatch")
		}

		for _, v := range rd.Principals() {
			if !strings.Contains(v, "mockPrincipal") {
				t.Errorf("bad principal name %s", v)
			}
		}
	})
}

func TestSamlAssertion_ExpiresAt(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		if _, err := new(SamlAssertion).ExpiresAt(); err == nil {
			t.Error("did not receive expected error")
		}
	})

	t.Run("no data", func(t *testing.T) {
		data := `my mock saml assertion`
		b64 := base64.StdEncoding.EncodeToString([]byte(data))
		a := SamlAssertion(b64)

		exp, err := (&a).ExpiresAt()
		if err != nil {
			t.Error(err)
			return
		}

		if exp.After(time.Now().UTC()) {
			t.Error("unexpected future expiration time")
		}
	})

	t.Run("bad time", func(t *testing.T) {
		t0 := time.Now().UTC()
		data := fmt.Sprintf(`<saml:Assertion IssueInstant="%d">`, t0.UnixNano())
		b64 := base64.StdEncoding.EncodeToString([]byte(data))
		a := SamlAssertion(b64)

		if _, err := (&a).ExpiresAt(); err == nil {
			t.Error("did not receive expected error")
		}
	})

	t.Run("good", func(t *testing.T) {
		t0 := time.Now().UTC()
		data := fmt.Sprintf(`<saml:Assertion IssueInstant="%s">`, t0.Format(time.RFC3339))
		b64 := base64.StdEncoding.EncodeToString([]byte(data))
		a := SamlAssertion(b64)

		exp, err := (&a).ExpiresAt()
		if err != nil {
			t.Error(err)
		}

		if exp.Before(time.Now().UTC()) {
			t.Error("got unexpected expired assertion")
		}
	})

	t.Run("expired", func(t *testing.T) {
		t0 := time.Now().Add(-1 * time.Hour).UTC()
		data := fmt.Sprintf(`<saml:Assertion id="mock" IssueInstant="%s" attr1="yyy">`, t0.Format(time.RFC3339))
		b64 := base64.StdEncoding.EncodeToString([]byte(data))
		a := SamlAssertion(b64)

		exp, err := (&a).ExpiresAt()
		if err != nil {
			t.Error(err)
		}

		if exp.After(time.Now().UTC()) {
			t.Error("got unexpected valid assertion")
		}
	})

	t.Run("saml2", func(t *testing.T) {
		t0 := time.Now().UTC()
		data := fmt.Sprintf(`<saml2:Assertion id="xxx" IssueInstant="%s">`, t0.Format(time.RFC3339))
		b64 := base64.StdEncoding.EncodeToString([]byte(data))
		a := SamlAssertion(b64)

		exp, err := (&a).ExpiresAt()
		if err != nil {
			t.Error(err)
		}

		if exp.Before(time.Now().UTC()) {
			t.Error("got unexpected expired assertion")
		}
	})
}

func TestSamlAssertion_Decode(t *testing.T) {
	data := `my mock saml assertion`

	t.Run("empty", func(t *testing.T) {
		if _, err := new(SamlAssertion).Decode(); err == nil {
			t.Error("did not receive expected error")
		}
	})

	t.Run("bad encoding", func(t *testing.T) {
		a := SamlAssertion(data)
		if _, err := (&a).Decode(); err == nil {
			t.Error("did not receive expected error")
		}
	})

	t.Run("good", func(t *testing.T) {
		b64 := base64.StdEncoding.EncodeToString([]byte(data))
		a := SamlAssertion(b64)
		decode, err := (&a).Decode()
		if err != nil {
			t.Error(err)
		}

		if decode != data {
			t.Error("data mismatch")
		}
	})
}

func TestSamlAssertion_RoleSessionName(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		rawData := `<RoleSessionName NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">mockUser</RoleSessionName>`
		saml := SamlAssertion(base64.StdEncoding.EncodeToString([]byte(rawData)))

		n, err := saml.RoleSessionName()
		if err != nil {
			t.Error(err)
			return
		}

		if n != "mockUser" {
			t.Error("data mismatch")
		}
	})

	t.Run("missing", func(t *testing.T) {
		saml := SamlAssertion(base64.StdEncoding.EncodeToString([]byte(`<saml></saml>`)))
		if _, err := saml.RoleSessionName(); err == nil {
			t.Error("did not receive expected error")
		}
	})

	t.Run("no regex match", func(t *testing.T) {
		rawData := `<RoleSessionName NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">In^a|id</RoleSessionName>`
		saml := SamlAssertion(base64.StdEncoding.EncodeToString([]byte(rawData)))
		if _, err := saml.RoleSessionName(); err == nil {
			t.Error("did not receive expected error")
		}
	})

	t.Run("empty", func(t *testing.T) {
		if _, err := new(SamlAssertion).RoleSessionName(); err == nil {
			t.Error("did not receive expected error")
		}
	})
}

func ExampleRoleDetails_String() {
	rd := new(roleDetails)
	rd.details = map[string]string{"mockRole1": "mockPrincipal1"}
	fmt.Print(rd.String())
	// Output:
	//   mockRole1 mockPrincipal1
}
