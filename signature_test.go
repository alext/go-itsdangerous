package itsdangerous

import (
	"testing"
	"time"
)

func assert(t *testing.T, actual, expected string) {
	if actual != expected {
		t.Errorf("expecting %s, got %s instead", expected, actual)
	}
}

func TestSignatureSign(t *testing.T) {
	s := NewSignature("secret-key", "", "", "", nil, nil)
	expected := "my string.wh6tMHxLgJqB6oY1uT73iMlyrOA"
	actual, _ := s.Sign("my string")
	assert(t, actual, expected)
}

func TestSignatureUnsign(t *testing.T) {
	s := NewSignature("secret-key", "", "", "", nil, nil)
	expected := "my string"
	actual, _ := s.Unsign("my string.wh6tMHxLgJqB6oY1uT73iMlyrOA")
	assert(t, actual, expected)
}

/*
Examples generated in Python as follows:
	from freezegun import freeze_time
	from itsdangerous import TimestampSigner
	with freeze_time("2024-09-27T14:00:00Z"):
		s = TimestampSigner("secret_key", "salt")
		print(s.sign("my string"))
*/

func TestTimestampSignatureSign(t *testing.T) {
	tests := []struct {
		input    string
		now      time.Time
		expected string
	}{
		{input: "my string", now: time.Date(2024, 9, 27, 14, 0, 0, 0, time.UTC),
			expected: "my string.Zva6YA.aqBNzGvNEDkO6RGFPEX1HIhz0vU"},
		{input: "my string", now: time.Date(2024, 9, 27, 15, 0, 0, 0, time.UTC),
			expected: "my string.ZvbIcA.VVQqPkaZ-YQaLHomuudMzTiw45Q"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.input, func(t *testing.T) {
			if !test.now.IsZero() {
				NowFunc = func() time.Time { return test.now }
				defer func() { NowFunc = time.Now }()
			}

			sig := NewTimestampSignature("secret_key", "salt", "", "", nil, nil)

			actual, err := sig.Sign(test.input)
			if err != nil {
				t.Fatalf("Sign(%s) returned error: %s", test.input, err)
			}
			if actual != test.expected {
				t.Errorf("Sign(%s) got %#v; want %#v", test.input, actual, test.expected)
			}
		})
	}
}

func TestTimestampSignatureUnsign(t *testing.T) {
	tests := []struct {
		input       string
		expected    string
		now         time.Time
		maxAge      uint32
		expectError bool
	}{
		// Signature within maxAge
		{input: "my string.Zva6YA.aqBNzGvNEDkO6RGFPEX1HIhz0vU", expected: "my string",
			now: time.Date(2024, 9, 27, 14, 4, 59, 0, time.UTC), maxAge: 5 * 60},
		// signature expired
		{input: "my string.Zva6YA.aqBNzGvNEDkO6RGFPEX1HIhz0vU", expectError: true,
			now: time.Date(2024, 9, 27, 14, 5, 1, 0, time.UTC), maxAge: 5 * 60},
		// maxAge zero always validates
		{input: "my string.Zva6YA.aqBNzGvNEDkO6RGFPEX1HIhz0vU", expected: "my string",
			now: time.Date(2024, 9, 27, 14, 5, 1, 0, time.UTC), maxAge: 0},
	}
	for _, test := range tests {
		test := test
		t.Run(test.input, func(t *testing.T) {
			if !test.now.IsZero() {
				NowFunc = func() time.Time { return test.now }
				defer func() { NowFunc = time.Now }()
			}

			sig := NewTimestampSignature("secret_key", "salt", "", "", nil, nil)

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
