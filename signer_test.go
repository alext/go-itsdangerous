package itsdangerous

import (
	"testing"
	"time"
)

// Example values here generated from Python using generate_examples.py script

func TestSignerSign(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{input: "my string", expected: "my string.xv0r21ogoygusbkJA01c4OxsAio"},
		{input: "aaaaaaaaaaaaaaaa", expected: "aaaaaaaaaaaaaaaa.Ot23yopX-I7Y6_e0hoZg6VKAcLk"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.input, func(t *testing.T) {
			sig := NewSigner("secret_key", "salt")

			actual := sig.Sign(test.input)
			if actual != test.expected {
				t.Errorf("Sign(%s) got %s; want %s", test.input, actual, test.expected)
			}
		})
	}
}

func TestSignerUnsign(t *testing.T) {
	tests := []struct {
		input       string
		expected    string
		expectError bool
	}{
		{input: "my string.xv0r21ogoygusbkJA01c4OxsAio", expected: "my string"},
		{input: "altered string.xv0r21ogoygusbkJA01c4OxsAio", expectError: true},
	}
	for _, test := range tests {
		test := test
		t.Run(test.input, func(t *testing.T) {
			sig := NewSigner("secret_key", "salt")

			actual, err := sig.Unsign(test.input)
			if test.expectError {
				if err == nil {
					t.Fatalf("Unsign(%s) expected error; got no error", test.input)
				}
			} else {
				if err != nil {
					t.Fatalf("Unsign(%s) returned error: %s", test.input, err)
				}
				if actual != test.expected {
					t.Errorf("Unsign(%s) got %s; want %s", test.input, actual, test.expected)
				}
			}
		})
	}
}

func TestTimestampSignerSign(t *testing.T) {
	tests := []struct {
		input    string
		now      time.Time
		expected string
	}{
		{input: "my string", now: time.Date(2024, 9, 27, 14, 0, 0, 0, time.UTC),
			expected: "my string.Zva6YA.aqBNzGvNEDkO6RGFPEX1HIhz0vU"},
		{input: "my string", now: time.Date(2024, 9, 27, 15, 0, 0, 0, time.UTC),
			expected: "my string.ZvbIcA.VVQqPkaZ-YQaLHomuudMzTiw45Q"},
		// Test with timestamp > 4 bytes
		{input: "my string", now: time.Date(2124, 9, 27, 15, 0, 0, 0, time.UTC),
			expected: "my string.ASMOinA.eGqsFVFmYbv8t7tXD8PX7LHSXdY"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.input, func(t *testing.T) {
			if !test.now.IsZero() {
				NowFunc = func() time.Time { return test.now }
				defer func() { NowFunc = time.Now }()
			}

			sig := NewTimestampSigner("secret_key", "salt")

			actual := sig.Sign(test.input)
			if actual != test.expected {
				t.Errorf("Sign(%s) got %#v; want %#v", test.input, actual, test.expected)
			}
		})
	}
}

func TestTimestampSignerUnsign(t *testing.T) {
	tests := []struct {
		input       string
		expected    string
		now         time.Time
		maxAge      time.Duration
		expectError bool
	}{
		// Signature within maxAge
		{input: "my string.Zva6YA.aqBNzGvNEDkO6RGFPEX1HIhz0vU", expected: "my string",
			now: time.Date(2024, 9, 27, 14, 4, 59, 0, time.UTC), maxAge: 5 * time.Minute},
		// signature expired
		{input: "my string.Zva6YA.aqBNzGvNEDkO6RGFPEX1HIhz0vU", expectError: true,
			now: time.Date(2024, 9, 27, 14, 5, 1, 0, time.UTC), maxAge: 5 * time.Minute},
		// maxAge zero always validates
		{input: "my string.Zva6YA.aqBNzGvNEDkO6RGFPEX1HIhz0vU", expected: "my string",
			now: time.Date(2024, 9, 27, 14, 5, 1, 0, time.UTC), maxAge: 0},
		// Test with timestamp > 4 bytes
		{input: "my string.ASMOinA.eGqsFVFmYbv8t7tXD8PX7LHSXdY", expected: "my string",
			now: time.Date(2124, 9, 27, 15, 4, 59, 0, time.UTC), maxAge: 5 * time.Minute},
		{input: "my string.ASMOinA.eGqsFVFmYbv8t7tXD8PX7LHSXdY", expectError: true,
			now: time.Date(2124, 9, 27, 15, 5, 1, 0, time.UTC), maxAge: 5 * time.Minute},
	}
	for _, test := range tests {
		test := test
		t.Run(test.input, func(t *testing.T) {
			if !test.now.IsZero() {
				NowFunc = func() time.Time { return test.now }
				defer func() { NowFunc = time.Now }()
			}

			sig := NewTimestampSigner("secret_key", "salt")

			actual, err := sig.Unsign(test.input, test.maxAge)
			if test.expectError {
				if err == nil {
					t.Fatalf("Unsign(%s) expected error; got no error", test.input)
				}
			} else {
				if err != nil {
					t.Fatalf("Unsign(%s) returned error: %s", test.input, err)
				}
				if actual != test.expected {
					t.Errorf("Unsign(%s) got %#v; want %#v", test.input, actual, test.expected)
				}
			}
		})
	}
}
