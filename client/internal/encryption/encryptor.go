package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"io"

	"github.com/cosmos/go-bip39"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/hkdf"
)

type Encryptor struct {
	key []byte
}

func NewEncryptor(words string) *Encryptor {
	key, err := GenerateKeyFromWords(words)
	if err != nil {
		log.Error(err)
	}

	return &Encryptor{
		key: key,
	}
}

func DeriveKey(seed []byte) ([]byte, error) {
	hkdf := hkdf.New(sha256.New, seed, nil, []byte("goph-keeper"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf, key); err != nil {
		return nil, err
	}
	return key, nil
}

func (e *Encryptor) Encrypt(plaintext []byte) ([]byte, error) {
	log.Info("key while encrypting: ", e.key)
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

func (e *Encryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	log.Info("key while decrypting: ", e.key)

	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, err
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func GenerateKeyFromWords(words string) ([]byte, error) {
	passphrase := ""
	seed := bip39.NewSeed(words, passphrase)

	key, err := DeriveKey(seed)
	if err != nil {
		return nil, err
	}

	return key, nil
}
