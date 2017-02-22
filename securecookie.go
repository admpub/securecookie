// Copyright 2012 The Gorilla Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package securecookie

import (
	"bytes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"hash"
	"strconv"
	"time"

	"golang.org/x/crypto/nacl/secretbox"

	scrypt "github.com/elithrar/simple-scrypt"
	"github.com/pkg/errors"
)

const (
	keySize   = 32
	nonceSize = 12
)

// Codec defines an interface to encode and decode cookie values.
type Codec interface {
	Encode(name string, value interface{}) (string, error)
	Decode(name, value string, dst interface{}) error
}

// Options represents optional configuration that can be passed to a new SecureCookie instance.
type Options struct {
	// RotatedKeys is a list of signing/encryption keys to attempt if the primary
	// key fails. This is useful when you wish to update the key used for
	// signing/encrypting, without immediately breaking old sessions.
	// TODO(matt): Determine whether to have a key <-> NotAfter relation?
	RotatedKeys [][32]byte
	// EncryptCookies determines whether to encrypt cookie contents. This is
	// 'false' by default: cookies are signed to prevent tampering or manipulation
	// of values, but are not encrypted. Encryption adds size overhead to the
	// cookie contents, and it should be rare than an application is storing
	// sensitive data in a cookie. If you are, use TLS (HTTPS) as the transport
	// mechanism.
	EncryptCookies bool
	// MaxAge is the maximum age of a cookie, in seconds.
	MaxAge int64
	// Serialize determines how a cookie will be serialized. Defaults to
	// encoding/gob for compatibility with all Go types. An encoding/json based
	// serializer is also provided as a built-in option for improved performance
	// and reduced overhead (in bytes).
	Serialize Serializer
}

// New returns a new SecureCookie.
//
// TODO(matt): Update this - HMAC (signed, to prevent an attacker from
// modifying values). Generate keys outside of application & persist them
// securely. securecookie can generate keys for you, but failing to persist
// (store) them means that cookies cannot be verified (or de-crypted) if the
// application is restarted.
//
// The provided key must be 32-bytes (256 bits) in length.
//
// The same key is used for both signing-only and encrypted modes, as the
// encrypted mode used an AEAD construct.
//
// hashKey is required, used to authenticate values using HMAC. Create it using
// GenerateRandomKey(). It is recommended to use a key with 32 or 64 bytes.
//
// Note that keys created using GenerateRandomKey() are not automatically
// persisted. New keys will be created when the application is restarted, and
// previously issued cookies will not be able to be decoded.
func New(key [32]byte, opts *Options) (*SecureCookie, error) {
	if len(key) != keySize {
		return nil, errInvalidKey
	}

	if opts.RotatedKeys != nil {
		for idx, v := range opts.RotatedKeys {
			// TODO(matt): If there are keys, set tryKeys = true?
			// Rotated keys are only used for decryption attempts.
		}
	}

	s := &SecureCookie{
		key:       key,
		maxAge:    86400 * 30,
		maxLength: 4096,
		sz:        GobEncoder{},
	}

	return s, nil
}

// SecureCookie encodes and decodes authenticated and optionally encrypted
// cookie values.
type SecureCookie struct {
	key       []byte
	stretched bool
	encrypter cipher.AEAD
	maxLength int
	maxAge    int64
	minAge    int64
	sz        Serializer
	opts      *Options
	// For testing purposes, the function that returns the current timestamp.
	// If not set, it will use time.Now().UTC().Unix().
	timeFunc func() int64
}

// Serializer provides an interface for providing custom serializers for cookie
// values.
type Serializer interface {
	Serialize(src interface{}) ([]byte, error)
	Deserialize(src []byte, dst interface{}) error
}

// GobEncoder encodes cookie values using encoding/gob. This is the simplest
// encoder and can handle complex types via gob.Register.
type GobEncoder struct{}

// JSONEncoder encodes cookie values using encoding/json. Users who wish to
// encode complex types need to satisfy the json.Marshaller and
// json.Unmarshaller interfaces.
type JSONEncoder struct{}

// NopEncoder does not encode cookie values, and instead simply accepts a []byte
// (as an interface{}) and returns a []byte. This is particularly useful when
// you encoding an object upstream and do not wish to re-encode it.
type NopEncoder struct{}

// MaxLength restricts the maximum length, in bytes, for the cookie value.
//
// Default is 4096, which is the maximum value accepted by Internet Explorer.
func (s *SecureCookie) MaxLength(value int) *SecureCookie {
	s.maxLength = value
	return s
}

// MaxAge restricts the maximum age, in seconds, for the cookie value.
//
// Default is 86400 * 30. Set it to 0 for no restriction.
func (s *SecureCookie) MaxAge(value int) *SecureCookie {
	s.maxAge = int64(value)
	return s
}

// MinAge restricts the minimum age, in seconds, for the cookie value.
//
// Default is 0 (no restriction).
func (s *SecureCookie) MinAge(value int) *SecureCookie {
	s.minAge = int64(value)
	return s
}

// HashFunc sets the hash function used to create HMAC.
//
// Default is crypto/sha256.New.
func (s *SecureCookie) HashFunc(f func() hash.Hash) *SecureCookie {
	s.hashFunc = f
	return s
}

// BlockFunc sets the encryption function used to create a cipher.Block.
//
// Default is crypto/aes.New.
func (s *SecureCookie) BlockFunc(f func([]byte) (cipher.Block, error)) *SecureCookie {
	if s.blockKey == nil {
		s.err = errBlockKeyNotSet
	} else if block, err := f(s.blockKey); err == nil {
		s.block = block
	} else {
		s.err = cookieError{cause: err, typ: usageError}
	}
	return s
}

// SetSerializer sets the encoding/serialization method for cookies.
//
// Default is encoding/gob.  To encode special structures using encoding/gob,
// they must be registered first using gob.Register().
func (s *SecureCookie) SetSerializer(sz Serializer) *SecureCookie {
	s.sz = sz

	return s
}

// Encode encodes a cookie value.
//
// It serializes, optionally encrypts, signs with a message authentication code,
// and finally encodes the value.
//
// The name argument is the cookie name. It is stored with the encoded value.
// The value argument is the value to be encoded. It can be any value that can
// be encoded using the currently selected serializer; see SetSerializer().
//
// It is the client's responsibility to ensure that value, when encoded using
// the current serialization/encryption settings on s and then base64-encoded,
// is shorter than the maximum permissible length.
func (s *SecureCookie) Encode(name string, value interface{}) (string, error) {
	// 1. Check that the key exists
	// 2. Check whether we have KDF'ed the key yet (once only)
	// 3. Serialize our payload
	// 4. Check whether s.encrypt == true
	// 5. Generate our payload: name.expiry.data
	// 6. sign or encrypt
	// 7. encode to base64 URL safe
	// 8. Check that the maximum length does not exceed s.maxLenght (4096 by default)
	// 9. Return string(encoded)able

	var encoded string

	if s.key == nil {
		return encoded, errHashKeyNotSet
	}

	// Run the provided key through a KDF (once only).
	if !s.stretched {
		var err error
		if s.key, err = stretchKey(s.key); err != nil {
			return "", errInvalidKey
		}
	}

	var payload []byte
	// TODO(matt): create a helper here: generatePayload?
	if s.opts.EncryptCookies {
		// Encrypt and early return
		payload = []byte(fmt.Sprintf("%s|%d", name, s.timestamp()))
		if payload, err = s.encrypt(payload); err != nil {
			return "", errEncryptionFailed
		}
	} else {
		// HMAC -> return
	}

	// base64.URLEncoding.EncodeToString
	// Check length - len(encoded) > s.maxLength
	// return encoded, nil

	var err error
	var b []byte
	// 1. Serialize.
	if b, err = s.sz.Serialize(value); err != nil {
		return "", cookieError{cause: err, typ: usageError}
	}
	// 2. Encrypt (optional).
	if s.block != nil {
		if b, err = encrypt(s.block, b); err != nil {
			return "", cookieError{cause: err, typ: usageError}
		}
	}
	b = encode(b)
	// 3. Create MAC for "name|date|value". Extra pipe to be used later.
	b = []byte(fmt.Sprintf("%s|%d|%s|", name, s.timestamp(), b))
	mac := createMac(hmac.New(s.hashFunc, s.hashKey), b[:len(b)-1])
	// Append mac, remove name.
	b = append(b, mac...)[len(name)+1:]
	// 4. Encode to base64.
	b = encode(b)
	// 5. Check length.
	if s.maxLength != 0 && len(b) > s.maxLength {
		return "", errEncodedValueTooLong
	}
	// Done.
	return string(b), nil
}

// Decode decodes a cookie value.
//
// It decodes, verifies a message authentication code, optionally decrypts and
// finally deserializes the value.
//
// The name argument is the cookie name. It must be the same name used when
// it was stored. The value argument is the encoded cookie value. The dst
// argument is where the cookie will be decoded. It must be a pointer.
func (s *SecureCookie) Decode(name, value string, dst interface{}) error {
	if s.err != nil {
		return s.err
	}
	if s.hashKey == nil {
		s.err = errHashKeyNotSet
		return s.err
	}
	// 1. Check length.
	if s.maxLength != 0 && len(value) > s.maxLength {
		return errValueToDecodeTooLong
	}
	// 2. Decode from base64.
	b, err := decode([]byte(value))
	if err != nil {
		return err
	}
	// 3. Verify MAC. Value is "date|value|mac".
	parts := bytes.SplitN(b, []byte("|"), 3)
	if len(parts) != 3 {
		return ErrMacInvalid
	}
	h := hmac.New(s.hashFunc, s.hashKey)
	b = append([]byte(name+"|"), b[:len(b)-len(parts[2])-1]...)
	if err = verifyMac(h, b, parts[2]); err != nil {
		return err
	}
	// 4. Verify date ranges.
	var t1 int64
	if t1, err = strconv.ParseInt(string(parts[0]), 10, 64); err != nil {
		return errTimestampInvalid
	}
	t2 := s.timestamp()
	if s.minAge != 0 && t1 > t2-s.minAge {
		return errTimestampTooNew
	}
	if s.maxAge != 0 && t1 < t2-s.maxAge {
		return errTimestampExpired
	}
	// 5. Decrypt (optional).
	b, err = decode(parts[1])
	if err != nil {
		return err
	}
	if s.block != nil {
		if b, err = decrypt(s.block, b); err != nil {
			return err
		}
	}
	// 6. Deserialize.
	if err = s.sz.Deserialize(b, dst); err != nil {
		return cookieError{cause: err, typ: decodeError}
	}
	// Done.
	return nil
}

// timestamp returns the current timestamp, in seconds.
//
// For testing purposes, the function that generates the timestamp can be
// overridden. If not set, it will return time.Now().UTC().Unix().
func (s *SecureCookie) timestamp() int64 {
	if s.timeFunc == nil {
		return time.Now().UTC().Unix()
	}
	return s.timeFunc()
}

// Authentication -------------------------------------------------------------

// createMac creates a message authentication code (MAC).
func createMac(h hash.Hash, value []byte) []byte {
	h.Write(value)
	return h.Sum(nil)
}

// verifyMac verifies that a message authentication code (MAC) is valid.
func verifyMac(h hash.Hash, value []byte, mac []byte) error {
	mac2 := createMac(h, value)
	// Check that both MACs are of equal length, as subtle.ConstantTimeCompare
	// does not do this prior to Go 1.4.
	if len(mac) == len(mac2) && subtle.ConstantTimeCompare(mac, mac2) == 1 {
		return nil
	}
	return ErrMacInvalid
}

// Authentication -------------------------------------------------------------

// sign returns a signature for the provided data.
//
// Internally, sign uses HMAC-SHA-512/256, which is HMAC-SHA-512 truncated to a
// 256-bit output to prevent length-extension attacks.
func (s *SecureCookie) sign(data []byte) ([]byte, error) {
	mac := hmac.New(sha512.New512_256, s.key)
	mac.Write(data)

	return mac.Sum(nil), nil
}

// verify validates that the provided data matches the given signature.
//
// verify uses HMAC-SHA-512/256 for signatures and performs a constant-time
// comparison of signatures using Go's hmac.Equal function.
func (s *SecureCookie) verify(data []byte, actualMAC []byte) bool {
	mac := hmac.New(sha512.New512_256, s.key)
	mac.Write(data)
	expected := mac.Sum(nil)

	return hmac.Equal(expected, actualMAC)
}

// Encryption -----------------------------------------------------------------

// encrypt encrypts the provided data using nacl/secretbox, and returns a
// concatenation of nonce+ciphertext.
//
// Interally, encrypt uses XSalsa20+Poly1305 (an AEAD; combining a stream
// cipher & MAC construct) and generates a random, 192-bit nonce using Go's
// crypto/rand library, which leverages /dev/urandom or the equivalent on all
// platforms. A random nonce is used to prevent nonce re-use issues, and does
// not require the package or package user to increment nonces.
func (s *SecureCookie) encrypt(data []byte) ([]byte, error) {
	// 1. Check our key is not nil
	if s.key == nil {
		return nil, errInvalidKey
	}

	// 2. Check that our data is not nil
	if data == nil {
		return nil, errInvalidData
	}

	// 3. Generate a fresh 96 bit nonce
	nonce, err := GenerateRandomBytes(12)
	if err != nil {
		return nil, errors.Wrap(err, "encryption failed")
	}

	// 4. Encrypt our data, appending the ciphertext to the nonce.
	return secretbox.Seal(nonce[:], data, nonce, s.key), nil
}

// decrypt decrypts the provided nonce+ciphertext using nacl/secretbox.
//
// It expects that the the 196-bit nonce is prepended to the ciphertext.
func (s *SecureCookie) decrypt(encrypted []byte) ([]byte, error) {
	if s.key == nil {
		return nil, errInvalidKey
	}

	if encrypted == nil || len(encrypted) < 24 {
		return nil, errDecryptionFailed
	}

	// 3. Parse our nonce
	nonce := encrypted[24:]
	ptext, ok := secretbox.Open([]byte{}, encrypted[24:], nonce, s.key)
	if !ok {
		return nil, errDecryptionFailed
	}

	return ptext, nil
}

// Encoding -------------------------------------------------------------------

// encode encodes a value using URL-safe base64.
func encode(value []byte) []byte {
	encoded := make([]byte, base64.URLEncoding.EncodedLen(len(value)))
	base64.URLEncoding.Encode(encoded, value)
	return encoded
}

// decode decodes a cookie using URL-safe base64.
func decode(value []byte) ([]byte, error) {
	decoded := make([]byte, base64.URLEncoding.DecodedLen(len(value)))
	b, err := base64.URLEncoding.Decode(decoded, value)
	if err != nil {
		return nil, cookieError{cause: err, typ: decodeError, msg: "base64 decode failed"}
	}
	return decoded[:b], nil
}

// Helpers --------------------------------------------------------------------

// GenerateRandomBytes returns securely generated random bytes.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	return b, err
}

// stretchKey passes the provided authentication/encryption key through a KDF
// (scrypt) to improve the entropy of the key used
func stretchKey(key []byte) ([]byte, error) {
	return scrypt.GenerateFromPassword(key, scrypt.DefaultParams)
}

// TODO(matt): RotatedEncrypt / RotatedDecrypt?

// CodecsFromPairs returns a slice of SecureCookie instances.
//
// It is a convenience function to create a list of codecs for key rotation. Note
// that the generated Codecs will have the default options applied: callers
// should iterate over each Codec and type-assert the underlying *SecureCookie to
// change these.
//
// Example:
//
//      codecs := securecookie.CodecsFromPairs(
//           []byte("new-hash-key"),
//           []byte("new-block-key"),
//           []byte("old-hash-key"),
//           []byte("old-block-key"),
//       )
//
//      // Modify each instance.
//      for _, s := range codecs {
//             if cookie, ok := s.(*securecookie.SecureCookie); ok {
//                 cookie.MaxAge(86400 * 7)
//                 cookie.SetSerializer(securecookie.JSONEncoder{})
//                 cookie.HashFunc(sha512.New512_256)
//             }
//         }
//
func CodecsFromPairs(keyPairs ...[]byte) []Codec {
	codecs := make([]Codec, len(keyPairs)/2+len(keyPairs)%2)
	for i := 0; i < len(keyPairs); i += 2 {
		var blockKey []byte
		if i+1 < len(keyPairs) {
			blockKey = keyPairs[i+1]
		}
		codecs[i/2] = New(keyPairs[i], blockKey)
	}
	return codecs
}

// EncodeMulti encodes a cookie value using a group of codecs.
//
// The codecs are tried in order. Multiple codecs are accepted to allow
// key rotation.
//
// On error, may return a MultiError.
func EncodeMulti(name string, value interface{}, codecs ...Codec) (string, error) {
	if len(codecs) == 0 {
		return "", errNoCodecs
	}

	var errors MultiError
	for _, codec := range codecs {
		encoded, err := codec.Encode(name, value)
		if err == nil {
			return encoded, nil
		}
		errors = append(errors, err)
	}
	return "", errors
}

// DecodeMulti decodes a cookie value using a group of codecs.
//
// The codecs are tried in order. Multiple codecs are accepted to allow
// key rotation.
//
// On error, may return a MultiError.
func DecodeMulti(name string, value string, dst interface{}, codecs ...Codec) error {
	if len(codecs) == 0 {
		return errNoCodecs
	}

	var errors MultiError
	for _, codec := range codecs {
		err := codec.Decode(name, value, dst)
		if err == nil {
			return nil
		}
		errors = append(errors, err)
	}
	return errors
}
