package itsdangerous

import (
	"crypto/hmac"
	"hash"
)

// SigningAlgorithm provides interfaces to generate and verify signature
type SigningAlgorithm interface {
	GetSignature(key []byte, value string) []byte
	VerifySignature(key []byte, value string, sig []byte) bool
}

// HMACAlgorithm provides signature generation using HMACs.
type HMACAlgorithm struct {
	DigestMethod func() hash.Hash
}

// GetSignature returns the signature for the given key and value.
func (a *HMACAlgorithm) GetSignature(key []byte, value string) []byte {
	h := hmac.New(a.DigestMethod, key)
	h.Write([]byte(value))
	return h.Sum(nil)
}

// VerifySignature verifies the given signature matches the expected signature.
func (a *HMACAlgorithm) VerifySignature(key []byte, value string, sig []byte) bool {
	return hmac.Equal(
		sig,
		a.GetSignature(key, value),
	)
}
