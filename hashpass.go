package hashpass

import (
	"fmt"
	"sync"

	"github.com/bounoable/hashpass/argon2"
)

// Hasher hashes and validates values.
type Hasher interface {
	Hash(value []byte) ([]byte, error)
	Verify(value, encoded []byte) (bool, error)
}

// Hashpass ...
type Hashpass struct {
	lock             sync.RWMutex
	hashers          map[string]Hasher
	DefaultAlgorithm string
}

// UnregisteredHasherError is returned when trying to hash with an algorithm that's not registered.
type UnregisteredHasherError struct {
	Name string
}

// New returns a new Hashpass instance.
func New() *Hashpass {
	return &Hashpass{
		hashers: make(map[string]Hasher),
	}
}

// NewDefault returns a new Hashpass instance with default algorithms.
func NewDefault() *Hashpass {
	hp := New()
	hp.Register("argon2", argon2.NewDefault())
	hp.DefaultAlgorithm = "argon2"
	return hp
}

// Register registers a hasher.
func (hp *Hashpass) Register(name string, hasher Hasher) {
	hp.lock.Lock()
	hp.hashers[name] = hasher
	hp.lock.Unlock()
}

// RegisterMany registered multiple hashers.
func (hp *Hashpass) RegisterMany(hashers map[string]Hasher) {
	hp.lock.Lock()
	for name, hasher := range hashers {
		hp.hashers[name] = hasher
	}
	hp.lock.Unlock()
}

// Hash hashes the value with the default algorithm.
func (hp *Hashpass) Hash(value []byte) ([]byte, error) {
	return hp.HashWith(hp.DefaultAlgorithm, value)
}

// HashWith hashes a value with the specified algorithm.
func (hp *Hashpass) HashWith(algo string, value []byte) ([]byte, error) {
	hasher, err := hp.hasher(algo)

	if err != nil {
		return nil, err
	}

	return hasher.Hash(value)
}

// HashString hashes a string with the default algorithm.
func (hp *Hashpass) HashString(value string) (string, error) {
	hash, err := hp.Hash([]byte(value))

	if err != nil {
		return "", err
	}

	return string(hash), nil
}

// HashStringWith hashes a string with the specified algorithm.
func (hp *Hashpass) HashStringWith(algo, value string) (string, error) {
	hash, err := hp.HashWith(algo, []byte(value))

	if err != nil {
		return "", err
	}

	return string(hash), nil
}

// Verify verifies a value against the encoded value using the default algorithm.
func (hp *Hashpass) Verify(value, encoded []byte) (bool, error) {
	return hp.VerifyWith(hp.DefaultAlgorithm, value, encoded)
}

// VerifyWith verifies a value against the encoded value.
func (hp *Hashpass) VerifyWith(algo string, value, encoded []byte) (bool, error) {
	hasher, err := hp.hasher(algo)

	if err != nil {
		return false, err
	}

	return hasher.Verify(value, encoded)
}

// VerifyString verifies a value against the encoded value using the default algorithm.
func (hp *Hashpass) VerifyString(value, encoded string) (bool, error) {
	return hp.Verify([]byte(value), []byte(encoded))
}

// VerifyStringWith verifies a value against the encoded value.
func (hp *Hashpass) VerifyStringWith(algo string, value, encoded string) (bool, error) {
	return hp.VerifyWith(algo, []byte(value), []byte(encoded))
}

func (hp *Hashpass) hasher(name string) (Hasher, error) {
	hp.lock.RLock()
	hasher, ok := hp.hashers[name]
	hp.lock.RUnlock()

	if !ok {
		return nil, UnregisteredHasherError{Name: name}
	}

	return hasher, nil
}

func (err UnregisteredHasherError) Error() string {
	return fmt.Sprintf("tried to retrieve non registered algorithm '%s'", err.Name)
}
