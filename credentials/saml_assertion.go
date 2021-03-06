package credentials

import (
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// SamlAssertion represents the base64 encoded SAML assertion document, and provides methods for extracting data
// necessary for the Assume Role with SAML operation.
type SamlAssertion string

// RoleDetails will inspect the SAML Assertion document and find the AWS IAM role, and saml-provider principal
// ARNs which are authorized for use with the AssumeRoleWithSaml API call.
func (s *SamlAssertion) RoleDetails() (*roleDetails, error) {
	saml, err := s.Decode()
	if err != nil {
		return nil, err
	}

	rd := new(roleDetails)
	rd.details = make(map[string]string)

	// static regex should never error
	re := regexp.MustCompile(`>(arn:aws:iam::\d+:(?:role|saml-provider)/.*?),(arn:aws:iam::\d+:(?:role|saml-provider)/.*?)<`)

	m := re.FindAllStringSubmatch(saml, -1)
	for _, r := range m {
		if strings.Contains(r[1], ":role/") {
			rd.details[r[1]] = r[2]
		} else {
			rd.details[r[2]] = r[1]
		}
	}

	return rd, nil
}

func (s *SamlAssertion) RoleSessionName() (string, error) {
	saml, err := s.Decode()
	if err != nil {
		return "", err
	}

	// static regex should never error
	re := regexp.MustCompile(`RoleSessionName.*?>([\w_=,.@-]+)<`)

	m := re.FindStringSubmatch(saml)
	if len(m) < 2 {
		return "", fmt.Errorf("unable to find RoleSessionName attribute in SAML doc")
	}
	return m[1], nil
}

// ExpiresAt returns the time at which this SAML Assertion is no longer valid.  AWS appears to enforce
// a maximum limit of 5 minutes, so the value returned will be slightly less than that time.
func (s *SamlAssertion) ExpiresAt() (time.Time, error) {
	t := time.Unix(0, 0)

	saml, err := s.Decode()
	if err != nil {
		return t, err
	}

	// could be saml:Assertion, or saml2:Assertion, static regex should never error
	// also handle Assertion tag without the namespace prefix (thanks Azure AD!)
	re := regexp.MustCompile(`<(?:saml\d*:)?Assertion.*\sIssueInstant="([[:graph:]]+)"`)

	m := re.FindStringSubmatch(saml)
	if m != nil {
		issueTime, err := time.Parse(time.RFC3339, m[1])
		if err != nil {
			return t, err
		}
		t = issueTime.Add(4 * time.Minute)
	}

	return t, nil
}

// Decode converts the base64 encoded SAML Assertion to the XML text form.
func (s *SamlAssertion) Decode() (string, error) {
	if s == nil || len(*s) < 1 {
		return "", errors.New("invalid saml assertion")
	}

	doc, err := base64.StdEncoding.DecodeString(string(*s))
	return string(doc), err
}

func (s *SamlAssertion) String() string {
	return string(*s)
}

// roleDetails is a SAML-specific construct which aligns the IAM SAML principal ARNs with IAM roles,
// as specified in the SAML Assertion document.
type roleDetails struct {
	details map[string]string
}

// RolePrincipal retruns the PrincipalARN strin for the specified role. The empty
// string is returned if no match was found.
func (r *roleDetails) RolePrincipal(role string) string {
	return r.details[role]
}

// Roles will enumerate the list of IAM roles found in the SAMLResponse document.
func (r *roleDetails) Roles() []string {
	rd := make([]string, len(r.details))
	i := 0

	for k := range r.details {
		rd[i] = k
		i++
	}

	return rd
}

// Principals returns the list of AWS SAML integration principal ARN values.
func (r *roleDetails) Principals() []string {
	rd := make([]string, len(r.details))
	i := 0

	for _, v := range r.details {
		rd[i] = v
		i++
	}

	return rd
}

// String iterates over the configured role and principal ARNs and returns a line-based
// string of the role/principal pairs.
func (r *roleDetails) String() string {
	sb := new(strings.Builder)
	for k, v := range r.details {
		sb.WriteString(fmt.Sprintf("  %s %s\n", k, v))
	}
	return sb.String()
}
