package metadata

type WebAuthenticationError string

func (e WebAuthenticationError) Error() string {
	return string(e)
}

func NewWebMfaRequiredError() WebAuthenticationError {
	return "MFA"
}

func NewWebAuthenticationError() WebAuthenticationError {
	return "AUTH"
}
