package identity

// Identity is the type used to store information for IAM or SAML user identity
type Identity struct {
	IdentityType string
	Provider     string
	Username     string
}

// Roles is the list of roles the identity is allowed to assume
type Roles []string

// Provider is the interface which conforming identity providers will adhere to
type Provider interface {
	// GetIdentity will return the Identity information for a user
	GetIdentity() (*Identity, error)
	// Roles returns the list of Roles the provided user is allowed to use
	Roles(user ...string) (Roles, error)
}
