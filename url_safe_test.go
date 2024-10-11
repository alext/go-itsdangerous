package itsdangerous_test

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/junohq/go-itsdangerous"
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
			sig := itsdangerous.NewURLSafeSerializer("secret_key", "salt")

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

			var decoded interface{}
			err = sig.Unmarshal(signed, &decoded)
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
			sig := itsdangerous.NewURLSafeSerializer("secret_key", "salt")

			var actual interface{}
			err := sig.Unmarshal(test.input, &actual)
			if test.expectError {
				if err == nil {
					t.Fatalf("Unmarshal(%s) expected error; got no error", test.input)
				}
				if !errors.As(err, &itsdangerous.InvalidSignatureError{}) {
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

func TestURLSafeTimedSerializerMarshal(t *testing.T) {
	tests := []struct {
		name              string
		payload           interface{}
		now               time.Time
		expected          string
		expectCompression bool
	}{
		{name: "string", payload: "my string", now: time.Date(2024, 9, 27, 14, 0, 0, 0, time.UTC),
			expected: "Im15IHN0cmluZyI.Zva6YA.xuP6ANJkkE2bfIQKSLbBTlu0LfM"},
		{name: "map", payload: map[string]interface{}{"foo": "bar"}, now: time.Date(2024, 9, 27, 14, 0, 0, 0, time.UTC),
			expected: "eyJmb28iOiJiYXIifQ.Zva6YA.qsA1vSQNlWBQSAPljwFH6C1Nx2I"},
		// payload that triggers compression
		{name: "long string", payload: "aaaaaaaaaaaaaaaaaaa", now: time.Date(2024, 9, 27, 14, 0, 0, 0, time.UTC),
			expectCompression: true},
	}
	for _, test := range tests {
		test := test
		t.Run(string(test.name), func(t *testing.T) {
			if !test.now.IsZero() {
				itsdangerous.NowFunc = func() time.Time { return test.now }
				defer func() { itsdangerous.NowFunc = time.Now }()
			}

			sig := itsdangerous.NewURLSafeTimedSerializer("secret_key", "salt")

			signed, err := sig.Marshal(test.payload)
			if err != nil {
				t.Fatalf("Marshal returned error: %s", err)
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

			var decoded interface{}
			err = sig.Unmarshal(signed, &decoded, 0)
			if err != nil {
				t.Fatalf("Marshal result could not be unmarshalled: %s", err)
			}
			if !reflect.DeepEqual(decoded, test.payload) {
				t.Errorf("Marshal round-trip changed payload. Got %#v, want %#v", decoded, test.payload)
			}
		})
	}
}
func TestURLSafeTimedSerializerUnmarshal(t *testing.T) {
	tests := []struct {
		now           time.Time
		input         string
		maxAge        time.Duration
		expected      interface{}
		expectError   bool
		expectExpired bool
	}{
		/* Examples generated in Python at timestamp 2024-09-27T14:00:00Z */
		// Signature within maxAge
		{input: "Im15IHN0cmluZyI.Zva6YA.xuP6ANJkkE2bfIQKSLbBTlu0LfM", expected: "my string",
			now: time.Date(2024, 9, 27, 14, 4, 59, 0, time.UTC), maxAge: 5 * time.Minute},
		{input: "eyJmb28iOiJiYXIifQ.Zva6YA.qsA1vSQNlWBQSAPljwFH6C1Nx2I", expected: map[string]interface{}{"foo": "bar"},
			now: time.Date(2024, 9, 27, 14, 4, 59, 0, time.UTC), maxAge: 5 * time.Minute},
		// signature expired
		{input: "Im15IHN0cmluZyI.Zva6YA.xuP6ANJkkE2bfIQKSLbBTlu0LfM", expectError: true, expectExpired: true,
			now: time.Date(2024, 9, 27, 14, 5, 1, 0, time.UTC), maxAge: 5 * time.Minute},
		{input: "eyJmb28iOiJiYXIifQ.Zva6YA.qsA1vSQNlWBQSAPljwFH6C1Nx2I", expectError: true, expectExpired: true,
			now: time.Date(2024, 9, 27, 14, 5, 1, 0, time.UTC), maxAge: 5 * time.Minute},
		// Example with zlib compression
		{input: ".eJxTSsQESgBSMgd4.Zva6YA._ItIzP5np9NnMIsNlxV6TpXzFUM", expected: "aaaaaaaaaaaaaaaaaaa",
			now: time.Date(2024, 9, 27, 14, 1, 0, 0, time.UTC), maxAge: 5 * time.Minute},
		// Example without a timestamp
		{input: "Im15IHN0cmluZyI.Cm-9vjbVa2uq2UcarUKVT4ETsJM", expectError: true,
			now: time.Date(2024, 9, 27, 14, 4, 59, 0, time.UTC), maxAge: 5 * time.Minute},
	}
	for _, test := range tests {
		test := test
		t.Run(test.input, func(t *testing.T) {
			if !test.now.IsZero() {
				itsdangerous.NowFunc = func() time.Time { return test.now }
				defer func() { itsdangerous.NowFunc = time.Now }()
			}

			sig := itsdangerous.NewURLSafeTimedSerializer("secret_key", "salt")

			var actual interface{}
			err := sig.Unmarshal(test.input, &actual, test.maxAge)
			if test.expectError {
				if err == nil {
					t.Fatalf("Unmarshal(%s) expected error; got no error", test.input)
				}
				if !errors.As(err, &itsdangerous.InvalidSignatureError{}) {
					t.Fatalf("Unmarshal(%s) expected InvalidSignatureError; got %T(%s)", test.input, err, err.Error())
				}
				if test.expectExpired {
					if !errors.As(err, &itsdangerous.SignatureExpiredError{}) {
						t.Fatalf("Unmarshal(%s) expected SignatureExpiredError; got %T(%s)", test.input, err, err.Error())
					}
				} else {
					if errors.As(err, &itsdangerous.SignatureExpiredError{}) {
						t.Fatalf("Unmarshal(%s) expected not to get a SignatureExpiredError; got %s", test.input, err.Error())
					}
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
