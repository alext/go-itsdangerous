/*
Package itsdangerous implements various functions to deal with untrusted sources.
Mainly useful for web applications.

This package exists purely as a port of https://github.com/mitsuhiko/itsdangerous,
where the original version is written in Python.
*/
package itsdangerous

import (
	"encoding/base64"
	"fmt"
	"strings"
	"time"
)

// Encodes a single string. The resulting string is safe for putting into URLs.
func base64Encode(src []byte) string {
	s := base64.URLEncoding.EncodeToString(src)
	return strings.Trim(s, "=")
}

// Decodes a single string.
func base64Decode(s string) ([]byte, error) {
	var padLen int

	if l := len(s) % 4; l > 0 {
		padLen = 4 - l
	} else {
		padLen = 1
	}

	b, err := base64.URLEncoding.DecodeString(s + strings.Repeat("=", padLen))
	if err != nil {
		fmt.Println(s)
		return []byte(""), err
	}
	return b, nil
}

// Function used to obtain the current time. Defaults to time.Now, but can be
// overridden eg for unit tests to simulate a different current time.
var NowFunc = time.Now

// Returns the current timestamp.  This implementation returns the
// seconds since January 1, 1970 UTC.
func getTimestamp() uint32 {
	return uint32(NowFunc().Unix())
}
