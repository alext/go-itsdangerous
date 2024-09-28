package itsdangerous

import (
	"bytes"
	"compress/zlib"
	"encoding/json"
	"fmt"
	"io"
)

type URLSafeSerializer struct {
	Signer
}

func NewURLSafeSerializer(secret, salt string) *URLSafeSerializer {
	s := NewSigner(secret, salt)
	return &URLSafeSerializer{Signer: *s}
}

func (s *URLSafeSerializer) Marshal(value interface{}) (string, error) {
	encoded, err := urlSafeSerialize(value)
	if err != nil {
		return "", err
	}

	return s.Signer.Sign(encoded), nil
}

func (s *URLSafeSerializer) Unmarshal(value string) (interface{}, error) {
	result, err := s.Signer.Unsign(value)
	if err != nil {
		return nil, err
	}

	return urlSafeDeserialize(result)
}

func urlSafeSerialize(value interface{}) (string, error) {
	jsonEncoded, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("error JSON marshalling payload: %w", err)
	}

	compressed := false
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	_, err = zw.Write(jsonEncoded)
	if err != nil {
		return "", fmt.Errorf("error compressing payload: %w", err)
	}
	err = zw.Close()
	if err != nil {
		return "", fmt.Errorf("error compressing payload: %w", err)
	}
	if buf.Len() < len(jsonEncoded) {
		jsonEncoded = buf.Bytes()
		compressed = true
	}

	encoded := base64Encode(jsonEncoded)
	if compressed {
		encoded = "." + encoded
	}

	return encoded, nil
}

func urlSafeDeserialize(encoded string) (interface{}, error) {
	decompress := false
	if encoded[0] == '.' {
		decompress = true
		encoded = encoded[1:]
	}

	decoded, err := base64Decode(encoded)
	if err != nil {
		return nil, err
	}

	if decompress {
		zr, err := zlib.NewReader(bytes.NewReader(decoded))
		if err != nil {
			return nil, fmt.Errorf("Error decompressing payload: %w", err)
		}
		defer zr.Close()
		decoded, err = io.ReadAll(zr)
		if err != nil {
			return nil, fmt.Errorf("Error decompressing payload: %w", err)
		}
	}

	var payload interface{}
	err = json.Unmarshal([]byte(decoded), &payload)
	if err != nil {
		return nil, fmt.Errorf("error JSON unmarshalling payload: %w", err)
	}

	return payload, nil
}
