package itsdangerous

import "fmt"

type InvalidSignatureError struct {
	err error
}

func (e InvalidSignatureError) Error() string { return e.err.Error() }
func (e InvalidSignatureError) Unwrap() error { return e.err }

type SignatureExpiredError struct {
	age, maxAge int64
}

func (e SignatureExpiredError) Error() string {
	return fmt.Sprintf("signature age %d > %d seconds", e.age, e.maxAge)
}

func signatureExpired(age, maxAge int64) error {
	return InvalidSignatureError{SignatureExpiredError{age: age, maxAge: maxAge}}
}
