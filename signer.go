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
	"time"
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
	secretKey     string
	salt          string
	sep           string
	keyDerivation string
	digestMethod  func() hash.Hash
	algorithm     SigningAlgorithm
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
		secretKey:     secret,
		salt:          salt,
		sep:           sep,
		keyDerivation: derivation,
		digestMethod:  digest,
		algorithm:     algo,
	}
}

// deriveKey generates a key derivation. Keep in mind that the key derivation in itsdangerous
// is not intended to be used as a security method to make a complex key out of a short password.
// Instead you should use large random secret keys.
func (s *Signer) deriveKey() ([]byte, error) {
	var key []byte
	var err error

	switch s.keyDerivation {
	case "concat":
		h := s.digestMethod()
		h.Write([]byte(s.salt + s.secretKey))
		key = h.Sum(nil)
	case "django-concat":
		h := s.digestMethod()
		h.Write([]byte(s.salt + "signer" + s.secretKey))
		key = h.Sum(nil)
	case "hmac":
		h := hmac.New(s.digestMethod, []byte(s.secretKey))
		h.Write([]byte(s.salt))
		key = h.Sum(nil)
	case "none":
		key = []byte(s.secretKey)
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

	sig := s.algorithm.GetSignature(key, value)
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
	return s.algorithm.VerifySignature(key, value, signed), nil
}

// Sign the given string.
func (s *Signer) Sign(value string) (string, error) {
	sig, err := s.getSignature(value)
	if err != nil {
		return "", err
	}
	return value + s.sep + sig, nil
}

// Unsign the given string.
func (s *Signer) Unsign(signed string) (string, error) {
	if !strings.Contains(signed, s.sep) {
		return "", fmt.Errorf("no %s found in value", s.sep)
	}

	li := strings.LastIndex(signed, s.sep)
	value, sig := signed[:li], signed[li+len(s.sep):]

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
	val := value + s.sep + ts

	return s.Signer.Sign(val)
}

// Unsign the given string.
func (s *TimestampSigner) Unsign(value string, maxAge time.Duration) (string, error) {
	result, err := s.Signer.Unsign(value)
	if err != nil {
		return "", err
	}

	// If there is no timestamp in the result there is something seriously wrong.
	if !strings.Contains(result, s.sep) {
		return "", errors.New("timestamp missing")
	}

	li := strings.LastIndex(result, s.sep)
	val, ts := result[:li], result[li+len(s.sep):]

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
		maxAgeSecs := int64(maxAge.Seconds())
		if age := getTimestamp() - timestamp; age > maxAgeSecs {
			return "", fmt.Errorf("signature age %d > %d seconds", age, maxAgeSecs)
		}
	}
	return val, nil
}
