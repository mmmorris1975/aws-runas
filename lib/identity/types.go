package identity

type Identity struct {
	IdentityType string
	Provider     string
	Username     string
}

type Roles []string

type Provider interface {
	GetIdentity() (*Identity, error)
	Roles(user ...string) (Roles, error)
}
