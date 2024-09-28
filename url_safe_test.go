package itsdangerous

import (
	"errors"
	"reflect"
	"testing"
)

func TestURLSafeSerializerMarshal(t *testing.T) {

	tests := []struct {
		name              string
		payload           interface{}
		expected          string
		expectCompression bool
	}{
		{name: "string", payload: "my string", expected: "Im15IHN0cmluZyI.Cm-9vjbVa2uq2UcarUKVT4ETsJM"},
		{name: "map", payload: map[string]interface{}{"foo": "bar"},
			expected: "eyJmb28iOiJiYXIifQ.6qEA6F4-V0kG0nJfqfnqdD3vQNE"},
		// payload that triggers compression
		{name: "long string", payload: "aaaaaaaaaaaaaaaaaaa", expectCompression: true},
	}
	for _, test := range tests {
		test := test
		t.Run(string(test.name), func(t *testing.T) {
			sig := NewURLSafeSerializer("secret_key", "salt")

			signed, err := sig.Marshal(test.payload)
			if err != nil {
				t.Fatalf("Sign returned error: %s", err)
			}
			if test.expectCompression {
				if signed[0] != '.' {
					t.Errorf("Marshal() got %s; expected compressed result", signed)
				}
				// Can't assert on the actual output with compression bcause
				// the Go and Python zlib implementations don't produce
				// identical bytes (probably due to different default tunings)

			} else {
				if signed[0] == '.' {
					t.Errorf("Marshal() got %s; expected non-compressed result", signed)
				}
				if signed != test.expected {
					t.Errorf("Marshal() got %s; expected %s", signed, test.expected)
				}
			}

			decoded, err := sig.Unmarshal(signed)
			if err != nil {
				t.Fatalf("Marshal result could not be unmarshalled: %s", err)
			}
			if !reflect.DeepEqual(decoded, test.payload) {
				t.Errorf("Marshal round-trip changed payload. Got %#v, want %#v", decoded, test.payload)
			}
		})
	}
}

func TestURLSafeSerializerUnmarshal(t *testing.T) {
	tests := []struct {
		input       string
		expected    interface{}
		expectError bool
	}{
		{input: "Im15IHN0cmluZyI.Cm-9vjbVa2uq2UcarUKVT4ETsJM", expected: "my string"},
		{input: "eyJmb28iOiJiYXIifQ.6qEA6F4-V0kG0nJfqfnqdD3vQNE", expected: map[string]interface{}{"foo": "bar"}},
		// Example with zlib compression
		{input: ".eJxTSsQESgBSMgd4.BTZ1azMeckx-AF_DQS-xc7A5Tn0", expected: "aaaaaaaaaaaaaaaaaaa"},
		// Altered signature
		{input: "Im15IHN0cmluZyI.aaaaaabVa2uq2UcarUKVT4ETsJM", expectError: true},
	}
	for _, test := range tests {
		test := test
		t.Run(test.input, func(t *testing.T) {
			sig := NewURLSafeSerializer("secret_key", "salt")

			actual, err := sig.Unmarshal(test.input)
			if test.expectError {
				if err == nil {
					t.Fatalf("Unmarshal(%s) expected error; got no error", test.input)
				}
				if !errors.As(err, &InvalidSignatureError{}) {
					t.Fatalf("Unmarshal(%s) expected InvalidSignatureError; got %T(%s)", test.input, err, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("Unmarshal(%s) returned error: %s", test.input, err)
				}
				if !reflect.DeepEqual(actual, test.expected) {
					t.Errorf("Unmarshal(%s) got %#v; want %#v", test.input, actual, test.expected)
				}
			}
		})
	}
}
