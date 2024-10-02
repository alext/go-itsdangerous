package itsdangerous

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"strings"
)

// Signer can sign bytes and unsign it and validate the signature
// provided.
//
// Salt can be used to namespace the hash, so that a signed string is only
// valid for a given namespace.  Leaving this at the default value or re-using
// a salt value across different parts of your application where the same
// signed value in one part can mean something different in another part
// is a security risk.
type Signer struct {
	SecretKey     string
	Sep           string
	Salt          string
	KeyDerivation string
	DigestMethod  func() hash.Hash
	Algorithm     SigningAlgorithm
}

// NewSigner creates a new Signer with the given secret and salt. All other
// properties will be set to match the Python itsdangerous defaults.
func NewSigner(secret, salt string) *Signer {
	return NewSignerWithOptions(secret, salt, "", "", nil, nil)
}

// NewSignerWithOptions creates a new Signer allowing overiding the default
// properties.
func NewSignerWithOptions(secret, salt, sep, derivation string, digest func() hash.Hash, algo SigningAlgorithm) *Signer {
	if salt == "" {
		salt = "itsdangerous.Signer"
	}
	if sep == "" {
		sep = "."
	}
	if derivation == "" {
		derivation = "django-concat"
	}
	if digest == nil {
		digest = sha1.New
	}
	if algo == nil {
		algo = &HMACAlgorithm{DigestMethod: digest}
	}
	return &Signer{
		SecretKey:     secret,
		Salt:          salt,
		Sep:           sep,
		KeyDerivation: derivation,
		DigestMethod:  digest,
		Algorithm:     algo,
	}
}

// deriveKey generates a key derivation. Keep in mind that the key derivation in itsdangerous
// is not intended to be used as a security method to make a complex key out of a short password.
// Instead you should use large random secret keys.
func (s *Signer) deriveKey() ([]byte, error) {
	var key []byte
	var err error

	switch s.KeyDerivation {
	case "concat":
		h := s.DigestMethod()
		h.Write([]byte(s.Salt + s.SecretKey))
		key = h.Sum(nil)
	case "django-concat":
		h := s.DigestMethod()
		h.Write([]byte(s.Salt + "signer" + s.SecretKey))
		key = h.Sum(nil)
	case "hmac":
		h := hmac.New(s.DigestMethod, []byte(s.SecretKey))
		h.Write([]byte(s.Salt))
		key = h.Sum(nil)
	case "none":
		key = []byte(s.SecretKey)
	default:
		key, err = nil, errors.New("unknown key derivation method")
	}
	return key, err
}

// getSignature returns the signature for the given value.
func (s *Signer) getSignature(value string) (string, error) {
	key, err := s.deriveKey()
	if err != nil {
		return "", err
	}

	sig := s.Algorithm.GetSignature(key, value)
	return base64Encode(sig), err
}

// verifySignature verifies the signature for the given value.
func (s *Signer) verifySignature(value, signature string) (bool, error) {
	key, err := s.deriveKey()
	if err != nil {
		return false, err
	}

	signed, err := base64Decode(signature)
	if err != nil {
		return false, err
	}
	return s.Algorithm.VerifySignature(key, value, signed), nil
}

// Sign the given string.
func (s *Signer) Sign(value string) (string, error) {
	sig, err := s.getSignature(value)
	if err != nil {
		return "", err
	}
	return value + s.Sep + sig, nil
}

// Unsign the given string.
func (s *Signer) Unsign(signed string) (string, error) {
	if !strings.Contains(signed, s.Sep) {
		return "", fmt.Errorf("no %s found in value", s.Sep)
	}

	li := strings.LastIndex(signed, s.Sep)
	value, sig := signed[:li], signed[li+len(s.Sep):]

	if ok, _ := s.verifySignature(value, sig); ok == true {
		return value, nil
	}
	return "", fmt.Errorf("signature %s does not match", sig)
}

// TimestampSigner works like the regular Signer but also records the time
// of the signing and can be used to expire signatures.
type TimestampSigner struct {
	Signer
}

// NewTimestampSigner creates a new TimestampSigner with the given secret and
// salt. All other properties will be set to match the Python itsdangerous
// defaults.
func NewTimestampSigner(secret, salt string) *TimestampSigner {
	return NewTimestampSignerWithOptions(secret, salt, "", "", nil, nil)
}

// NewTimestampSignerWithOptions creates a new TimestampSigner allowing
// overiding the default properties.
func NewTimestampSignerWithOptions(secret, salt, sep, derivation string, digest func() hash.Hash, algo SigningAlgorithm) *TimestampSigner {
	s := NewSignerWithOptions(secret, salt, sep, derivation, digest, algo)
	return &TimestampSigner{Signer: *s}
}

// Sign the given string.
func (s *TimestampSigner) Sign(value string) (string, error) {
	tsBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(tsBytes, uint64(getTimestamp()))
	// trim leading zeroes
	tsBytes = bytes.TrimLeft(tsBytes, "\x00")

	ts := base64Encode(tsBytes)
	val := value + s.Sep + ts

	return s.Signer.Sign(val)
}

// Unsign the given string.
func (s *TimestampSigner) Unsign(value string, maxAge uint32) (string, error) {
	result, err := s.Signer.Unsign(value)
	if err != nil {
		return "", err
	}

	// If there is no timestamp in the result there is something seriously wrong.
	if !strings.Contains(result, s.Sep) {
		return "", errors.New("timestamp missing")
	}

	li := strings.LastIndex(result, s.Sep)
	val, ts := result[:li], result[li+len(s.Sep):]

	tsBytes, err := base64Decode(ts)
	if err != nil {
		return "", err
	}
	// left pad up to 8 bytes
	if len(tsBytes) < 8 {
		tsBytes = append(
			make([]byte, 8-len(tsBytes)),
			tsBytes...,
		)
	}

	var timestamp = int64(binary.BigEndian.Uint64(tsBytes))

	if maxAge > 0 {
		if age := getTimestamp() - timestamp; uint32(age) > maxAge {
			return "", fmt.Errorf("signature age %d > %d seconds", age, maxAge)
		}
	}
	return val, nil
}
