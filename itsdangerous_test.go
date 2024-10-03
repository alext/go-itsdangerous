package itsdangerous

import (
	"reflect"
	"testing"
)

func TestBase64(t *testing.T) {

	tests := []struct {
		value   []byte
		encoded string
	}{
		{value: []byte("a"), encoded: "YQ"},
		{value: []byte("ab"), encoded: "YWI"},
		{value: []byte("abc"), encoded: "YWJj"},
		{value: []byte("abcd"), encoded: "YWJjZA"},
		{value: []byte("abcde"), encoded: "YWJjZGU"},
		{value: []byte("abcdef"), encoded: "YWJjZGVm"},
	}
	for _, test := range tests {
		test := test
		t.Run(string(test.value), func(t *testing.T) {
			actualEncoded := base64Encode(test.value)
			if actualEncoded != test.encoded {
				t.Errorf("base64Encode(%v) got %s; want %s", test.value, actualEncoded, test.encoded)
			}

			decoded, err := base64Decode(test.encoded)
			if err != nil {
				t.Errorf("base64Decode(%s) returned error: %s", test.encoded, err)
			} else if !reflect.DeepEqual(decoded, test.value) {
				t.Errorf("base64Decode(%s) got %v; want %v", test.encoded, decoded, test.value)
			}
		})
	}
}
