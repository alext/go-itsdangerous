/*
Package itsdangerous implements various functions to deal with untrusted sources.
Mainly useful for web applications.

This package exists purely as a port of https://github.com/mitsuhiko/itsdangerous,
where the original version is written in Python.
*/
package itsdangerous

import (
	"encoding/base64"
	"time"
)

// Encodes a single string. The resulting string is safe for putting into URLs.
func base64Encode(src []byte) string {
	return base64.RawURLEncoding.EncodeToString(src)
}

// Decodes a single string.
func base64Decode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// Function used to obtain the current time. Defaults to time.Now, but can be
// overridden eg for unit tests to simulate a different current time.
var NowFunc = time.Now

// Returns the current timestamp.  This implementation returns the
// seconds since January 1, 1970 UTC.
func getTimestamp() int64 {
	return NowFunc().Unix()
}
