package wile

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"io"

	"github.com/pkg/errors"
	"golang.org/x/net/context"

	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/crypto/hkdf"
)

type EncryptingCache struct {
	impl autocert.Cache
	kh   []byte
	aead cipher.AEAD
}

func NewEncryptingCache(impl autocert.Cache, key []byte) (*EncryptingCache, error) {
	keyReader := hkdf.New(sha256.New, key, nil, []byte("autocert keys"))

	var kh [16]byte
	_, err := io.ReadFull(keyReader, kh[:])
	if err != nil {
		return nil, errors.Wrap(err, "failed to read key for hash")
	}

	var kaes [16]byte
	_, err = io.ReadFull(keyReader, kaes[:])
	if err != nil {
		return nil, errors.Wrap(err, "failed to read key for cipher")
	}

	block, err := aes.NewCipher(kaes[:])
	if err != nil {
		return nil, errors.Wrap(err, "failed to create cipher")
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create GCM AEAD")
	}

	return &EncryptingCache{
		impl: impl,
		kh:   kh[:],
		aead: aead,
	}, nil
}

func (e *EncryptingCache) Get(ctx context.Context, key string) ([]byte, error) {
	val, err := e.impl.Get(ctx, e.hashKey(key))
	if err != nil {
		return nil, err
	}

	n := e.aead.NonceSize()

	if len(val) < n {
		return nil, fmt.Errorf("For key %v, found too-small value.", key)
	}

	return e.aead.Open(nil, val[:n], val[n:], []byte(key))
}

func (e *EncryptingCache) Put(ctx context.Context, key string, data []byte) error {
	nonce := make([]byte, e.aead.NonceSize())
	_, err := io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return errors.Wrap(err, "failed to read nonce")
	}

	ciphertext := e.aead.Seal(nil, nonce, data, []byte(key))

	var final []byte
	final = append(final, nonce...)
	final = append(final, ciphertext...)

	return e.impl.Put(ctx, e.hashKey(key), final)
}

func (e *EncryptingCache) Delete(ctx context.Context, key string) error {
	return e.impl.Delete(ctx, e.hashKey(key))
}

func (e *EncryptingCache) hashKey(key string) string {
	hash := hmac.New(sha256.New, e.kh)
	_, err := io.WriteString(hash, key)
	if err != nil {
		panic(err)
	}

	return base32.HexEncoding.EncodeToString(hash.Sum(nil))
}
