// Package argon2id provides a wrapper around Go's argon2 using the argon2id
// variant. It provides multiple helper functions to make a secure
// implementation easier.
package argon2id

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

var (
	// ErrPasswordRequired is returned by HashPassword or VerifyPassword if no
	// password was provided.
	ErrPasswordRequired = errors.New("argon2id: password must not be empty.")

	// ErrSaltRequired is returned by HashPassword if no salt was provided.
	ErrSaltRequired = errors.New("argon2id: salt must not be empty.")

	// ErrArgon2KeyRequired is returned by VerifyPassword if no argon2 key was
	// provided.
	ErrArgon2KeyRequired = errors.New("argon2id: argon2 key must not be empty.")

	// ErrInvalidKeyLength is returned by VerifyPassword if the provided argon2
	// key is of invalid length.
	ErrInvalidKeyLength = errors.New("argon2id: argon2 key invalid length.")

	// ErrArgonVersionMismatch is returned by VerifyPassword if the provided
	// argon2 key version is different than the one used by the package.
	ErrArgonVersionMismatch = errors.New("argon2id: argon2 key version mismatch.")

	// ErrHashNotEqualPassword is returned by VerifyPassword if the provided
	// hash does not equal the password.
	ErrHashNotEqualPassword = errors.New("argon2id: hash not equal password.")
)

// DefaultOptions contains sane defaults as of December 2021. These defaults
// are subject to change if new recommendations are released. These settings
// were chosen for usage in a web application.
var DefaultOptions = &Options{
	Time:    1,
	Memory:  64 * 1024,
	Threads: 4,
	KeyLen:  32,
}

// Options contain all the options that can be set using the argon2id
// algorithm.
type Options struct {
	Time    uint32
	Memory  uint32
	Threads uint8
	KeyLen  uint32
}

// EncodeToBase64String is a helper function that turns the given bytes into
// a base64 encoded string.
func EncodeToBase64String(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// DecodeBase64String is a helper function that decodes the given base64 string.
func DecodeBase64String(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// HashPassword takes a password and a salt and returns an argon2 key that
// can be saved in a database.
func HashPassword(password string, salt string, options *Options) (string, error) {
	if password == "" {
		return "", ErrPasswordRequired
	}

	if salt == "" {
		return "", ErrSaltRequired
	}

	hash := argon2.IDKey(
		[]byte(password), []byte(salt),
		options.Time, options.Memory, options.Threads, options.KeyLen,
	)

	b64Salt := EncodeToBase64String([]byte(salt))
	b64Hash := EncodeToBase64String(hash)

	key := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, options.Memory, options.Time, options.Threads, b64Salt, b64Hash,
	)

	return key, nil
}

// VerifyPassword takes a password and an argon2 key and compares both. It will
// return an error if they are not equal.
func VerifyPassword(password string, key string) error {
	if password == "" {
		return ErrPasswordRequired
	}

	if key == "" {
		return ErrArgon2KeyRequired
	}

	decodedKey := strings.Split(key, "$")
	if len(decodedKey) != 6 {
		return ErrInvalidKeyLength
	}

	p := Options{}
	version := argon2.Version

	if _, err := fmt.Sscanf(decodedKey[2], "v=%d", &version); err != nil {
		return err
	}

	if version != argon2.Version {
		return ErrArgonVersionMismatch
	}

	if _, err := fmt.Sscanf(decodedKey[3], "m=%d,t=%d,p=%d",
		&p.Memory, &p.Time, &p.Threads,
	); err != nil {
		return err
	}

	salt, err := DecodeBase64String(decodedKey[4])
	if err != nil {
		return err
	}

	hash, err := DecodeBase64String(decodedKey[5])
	if err != nil {
		return err
	}

	p.KeyLen = uint32(len(hash))

	control := argon2.IDKey(
		[]byte(password), []byte(salt),
		p.Time, p.Memory, p.Threads, p.KeyLen,
	)

	if subtle.ConstantTimeCompare(hash, control) == 1 {
		return nil
	}

	return ErrHashNotEqualPassword
}
