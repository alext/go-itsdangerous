package itsdangerous

import (
	"bytes"
	"compress/zlib"
	"encoding/json"
	"fmt"
	"io"
	"time"
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

func (s *URLSafeSerializer) Unmarshal(signed string, value interface{}) error {
	encoded, err := s.Signer.Unsign(signed)
	if err != nil {
		return err
	}

	return urlSafeDeserialize(encoded, value)
}

type URLSafeTimedSerializer struct {
	TimestampSigner
}

func NewURLSafeTimedSerializer(secret, salt string) *URLSafeTimedSerializer {
	s := NewTimestampSigner(secret, salt)
	return &URLSafeTimedSerializer{TimestampSigner: *s}
}

func (s *URLSafeTimedSerializer) Marshal(value interface{}) (string, error) {
	encoded, err := urlSafeSerialize(value)
	if err != nil {
		return "", err
	}

	return s.TimestampSigner.Sign(encoded), nil
}

func (s *URLSafeTimedSerializer) Unmarshal(signed string, value interface{}, maxAge time.Duration) error {
	encoded, err := s.TimestampSigner.Unsign(signed, maxAge)
	if err != nil {
		return err
	}

	return urlSafeDeserialize(encoded, value)
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

func urlSafeDeserialize(encoded string, value interface{}) error {
	decompress := false
	if encoded[0] == '.' {
		decompress = true
		encoded = encoded[1:]
	}

	decoded, err := base64Decode(encoded)
	if err != nil {
		return err
	}

	if decompress {
		zr, err := zlib.NewReader(bytes.NewReader(decoded))
		if err != nil {
			return fmt.Errorf("Error decompressing payload: %w", err)
		}
		defer zr.Close()
		decoded, err = io.ReadAll(zr)
		if err != nil {
			return fmt.Errorf("Error decompressing payload: %w", err)
		}
	}

	err = json.Unmarshal([]byte(decoded), value)
	if err != nil {
		return fmt.Errorf("error JSON unmarshalling payload: %w", err)
	}

	return nil
}
