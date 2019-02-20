package cache

import "github.com/aws/aws-sdk-go/aws/credentials"

// CredentialCacher is the interface details to implement AWS credential caching
type CredentialCacher interface {
	Store(*CacheableCredentials) error
	Fetch() (*CacheableCredentials, error)
}

// CacheableCredentials is an implementation of the AWS credentials.Value type with the addition of an Expiration field
type CacheableCredentials struct {
	credentials.Value
	Expiration int64
}
