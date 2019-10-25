package argon2

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"strings"

	"golang.org/x/crypto/argon2"
)

var (
	// ErrInvalidHash is returned when the encoded hash has an incorrect format.
	ErrInvalidHash = errors.New("the encoded hash is not in the correct format")
	// ErrIncompatibleVersion is returned when an incompatible version of the algorithm is used.
	ErrIncompatibleVersion = errors.New("incompatible version of argon2")
)

// Params are the argon2id parameters.
type Params struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// Hasher implements the argon2 hashing algorithm.
type Hasher struct {
	Params Params
}

// DefaultParams returns the default argon2 params.
func DefaultParams() Params {
	parallelism := runtime.NumCPU()

	if parallelism > 2 {
		parallelism = 2
	}

	p := Params{
		Memory:      64 * 1024,
		Iterations:  3,
		Parallelism: uint8(parallelism),
		SaltLength:  16,
		KeyLength:   32,
	}

	return p
}

// New returns a new argon2 hasher.
func New(params Params) *Hasher {
	return &Hasher{
		Params: params,
	}
}

// NewDefault returns a new argon2 hasher with default parameters.
func NewDefault() *Hasher {
	return New(DefaultParams())
}

// Hash hashes a byte array using the argon2 algorithm.
func (h *Hasher) Hash(value []byte) ([]byte, error) {
	salt, err := generateSalt(h.Params.SaltLength)

	if err != nil {
		return nil, err
	}

	hash := argon2.IDKey(value, salt, h.Params.Iterations, h.Params.Memory, h.Params.Parallelism, h.Params.KeyLength)

	return []byte(h.encode(salt, hash)), nil
}

// Verify verifies the value against the encoded value.
func (h *Hasher) Verify(value, encoded []byte) (bool, error) {
	p, salt, hash, err := decode(encoded)

	if err != nil {
		return false, err
	}

	valueHash := argon2.IDKey(value, salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)

	if subtle.ConstantTimeCompare(hash, valueHash) == 1 {
		return true, nil
	}

	return false, nil
}

func generateSalt(length uint32) ([]byte, error) {
	salt := make([]byte, length)

	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	return salt, nil
}

func (h *Hasher) encode(salt []byte, hash []byte) []byte {
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	return []byte(fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, h.Params.Memory, h.Params.Iterations, h.Params.Parallelism, b64Salt, b64Hash))
}

func decode(encoded []byte) (p *Params, salt, hash []byte, err error) {
	vals := strings.Split(string(encoded), "$")

	if len(vals) != 6 {
		return nil, nil, nil, ErrInvalidHash
	}

	var version int

	_, err = fmt.Sscanf(vals[2], "v=%d", &version)
	if err != nil {
		return nil, nil, nil, err
	}

	if version != argon2.Version {
		return nil, nil, nil, ErrIncompatibleVersion
	}

	p = &Params{}
	_, err = fmt.Sscanf(vals[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Iterations, &p.Parallelism)
	if err != nil {
		return nil, nil, nil, err
	}

	salt, err = base64.RawStdEncoding.DecodeString(vals[4])
	if err != nil {
		return nil, nil, nil, err
	}

	p.SaltLength = uint32(len(salt))

	hash, err = base64.RawStdEncoding.DecodeString(vals[5])
	if err != nil {
		return nil, nil, nil, err
	}

	p.KeyLength = uint32(len(hash))

	return p, salt, hash, nil
}
