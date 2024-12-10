package packers

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"

	"github.com/ProtonMail/go-crypto/openpgp/aes/keywrap"
	jose "github.com/go-jose/go-jose/v4"
	"golang.org/x/crypto/hkdf"
)

type headers map[string]string

func newHeadersFromBytes(h []byte) (headers, error) {
	var m map[string]string
	err := json.Unmarshal(h, &m)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal headers: %w", err)
	}
	return m, nil
}

func (h headers) epk() (*ecdh.PublicKey, error) {
	epk := h["epk"]
	if epk == "" {
		return nil, fmt.Errorf("epk not found in headers")
	}
	epkBytes, err := base64.URLEncoding.DecodeString(epk)
	if err != nil {
		return nil, fmt.Errorf("failed to decode epk: %w", err)
	}
	p, err := ecdh.P256().NewPublicKey(epkBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create public key: %w", err)
	}
	return p, nil
}

func (h headers) kid() string {
	return h["kid"]
}

func (h headers) alg() string {
	return h["alg"]
}

func (h headers) enc() string {
	return h["enc"]
}

const (
	keyManagmentAlg = "ECDH-1PU+A256KW"
	contentEncAlg   = "A256CBC-HS512"
)

type GetKeyFunc func(kid string) (*ecdh.PrivateKey, error)

type Authcrypt struct {
	kr KeyResolverHandlerFunc
}

type DecryptOption func(*decryptOptions)

type decryptOptions struct {
	kid string
}

func WithKid(kid string) DecryptOption {
	return func(opts *decryptOptions) {
		opts.kid = kid
	}
}

type zxPair struct {
	p   *ecdh.PrivateKey
	pub *ecdh.PublicKey
}

func (z zxPair) zx() ([]byte, error) {
	zx, err := z.p.ECDH(z.pub)
	if err != nil {
		return nil, fmt.Errorf("failed to generate shared secret: %w", err)
	}
	return zx, nil
}

func newECDHPU1Key(zecalc, zscalc zxPair) ([]byte, error) {
	ze, err := zecalc.zx()
	if err != nil {
		return nil, fmt.Errorf("failed to generate shared ze secret: %w", err)
	}
	zs, err := zscalc.zx()
	if err != nil {
		return nil, fmt.Errorf("failed to generate shared zs secret: %w", err)
	}
	z := append(ze, zs...)
	kekReader := hkdf.New(sha256.New, z, nil, nil)
	kek := make([]byte, 32)
	_, err = io.ReadFull(kekReader, kek)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key from z: %w", err)
	}
	return kek, nil
}

func hmacHash(key, iv, ciphertext, headersBytes []byte) []byte {
	h := hmac.New(sha512.New, key)
	h.Write(iv)
	h.Write(ciphertext)
	h.Write(headersBytes)
	return h.Sum(nil)[:32]
}

// Encrypt encrypts the message using the Authcrypt scheme
func (a *Authcrypt) Encrypt(recipientJWK jose.JSONWebKey, senderKid string, message []byte) (string, error) {
	recipient, err := extractECDHFromJWK(recipientJWK)
	if err != nil {
		return "", fmt.Errorf("failed to convert recipient key to ECDH: %w", err)
	}
	if recipient.Curve() != ecdh.P256() {
		return "", fmt.Errorf("supported curve is P-256")
	}

	p, err := a.kr(senderKid)
	if err != nil {
		return "", fmt.Errorf("failed to get sender key: %w", err)
	}
	sender, ok := p.(*ecdh.PrivateKey)
	if !ok {
		return "", fmt.Errorf("invalid sender key type")
	}

	ephemeral, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	kek, err := newECDHPU1Key(
		zxPair{p: ephemeral, pub: recipient},
		zxPair{p: sender, pub: recipient},
	)
	if err != nil {
		return "", fmt.Errorf("failed to derive kek: %w", err)
	}

	cek := make([]byte, 64)
	_, err = io.ReadFull(rand.Reader, cek)
	if err != nil {
		return "", fmt.Errorf("failed to generate cek: %w", err)
	}
	aesKey := cek[:32]
	hmacKey := cek[32:]

	ciphertext, iv, err := aesEncrypt(aesKey, message)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt message: %w", err)
	}

	apuBytes := append(ephemeral.PublicKey().Bytes(), sender.PublicKey().Bytes()...)
	headers := map[jose.HeaderKey]interface{}{
		"skid": senderKid,
		"alg":  keyManagmentAlg,
		"enc":  contentEncAlg,
		"apu":  base64.URLEncoding.EncodeToString(sha256.New().Sum(apuBytes)),
		"apv":  base64.URLEncoding.EncodeToString(sha256.New().Sum(recipient.Bytes())),
		"epk":  base64.URLEncoding.EncodeToString(ephemeral.PublicKey().Bytes()),
	}
	if recipientJWK.KeyID != "" {
		headers["kid"] = recipientJWK.KeyID
	}
	headersBytes, err := json.Marshal(headers)
	if err != nil {
		return "", fmt.Errorf("failed to marshal headers: %w", err)
	}

	authTag := hmacHash(hmacKey, iv, ciphertext, headersBytes)

	cekEcnrypted, err := keywrap.Wrap(kek, cek)
	if err != nil {
		return "", fmt.Errorf("failed to wrap cek: %w", err)
	}

	compactToken := fmt.Sprintf(
		"%s.%s.%s.%s.%s",
		base64.URLEncoding.EncodeToString(headersBytes),
		base64.URLEncoding.EncodeToString(cekEcnrypted),
		base64.URLEncoding.EncodeToString(iv),
		base64.URLEncoding.EncodeToString(ciphertext),
		base64.URLEncoding.EncodeToString(authTag),
	)

	return compactToken, nil
}

func (a *Authcrypt) Decrypt(jwe string, senderPublicKey *ecdh.PublicKey, opts ...DecryptOption) (string, error) {
	options := &decryptOptions{}
	for _, opt := range opts {
		opt(options)
	}

	kid := options.kid

	headers, cekEncrypted, iv, ciphertext, authTag, err := uncompressJWE(jwe)
	if err != nil {
		return "", fmt.Errorf("failed to uncompress JWE: %w", err)
	}
	headersMap, err := newHeadersFromBytes(headers)
	if err != nil {
		return "", fmt.Errorf("failed to create headers map: %w", err)
	}
	if headersMap.alg() != keyManagmentAlg || headersMap.enc() != contentEncAlg {
		return "", fmt.Errorf("unsupported jwt alg or enc type")
	}

	epk, err := headersMap.epk()
	if err != nil {
		return "", fmt.Errorf("failed to extract epk: %w", err)
	}
	if kid == "" {
		kid = headersMap.kid()
	}

	r, err := a.kr(kid)
	if err != nil {
		return "", fmt.Errorf("failed to get recipient key: %w", err)
	}
	recipient, ok := r.(*ecdh.PrivateKey)
	if !ok {
		return "", fmt.Errorf("invalid recipient key type")
	}

	kek, err := newECDHPU1Key(
		zxPair{p: recipient, pub: epk},
		zxPair{p: recipient, pub: senderPublicKey},
	)
	if err != nil {
		return "", fmt.Errorf("failed to derive kek: %w", err)
	}

	cek, err := keywrap.Unwrap(kek, cekEncrypted)
	if err != nil {
		return "", fmt.Errorf("failed to unwrap cek: %w", err)
	}

	aesKey := cek[:32]
	hmacKey := cek[32:]

	actualAuthTag := hmacHash(hmacKey, iv, ciphertext, headers)
	if !bytes.Equal(authTag, actualAuthTag) {
		return "", fmt.Errorf("auth tags do not match")
	}

	plain, err := aesDecrypt(aesKey, ciphertext, iv)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt ciphertext: %w", err)
	}

	return string(plain), nil
}

func extractEPK(headers []byte) (*ecdh.PublicKey, error) {
	var m map[string]interface{}
	if err := json.Unmarshal(headers, &m); err != nil {
		return nil, fmt.Errorf("failed to unmarshal headers: %w", err)
	}

	epk, ok := m["epk"]
	if !ok {
		return nil, fmt.Errorf("epk not found in headers")
	}

	epkBytes, err := base64.URLEncoding.DecodeString(epk.(string))
	if err != nil {
		return nil, fmt.Errorf("failed to decode epk: %w", err)
	}

	return ecdh.P256().NewPublicKey(epkBytes)
}

func uncompressJWE(jwe string) (headers, cekEncrypted, iv, ciphertext, authTag []byte, err error) {
	parts := bytes.Split([]byte(jwe), []byte("."))
	if len(parts) != 5 {
		err = fmt.Errorf("invalid JWE format")
		return
	}

	headers, err = base64.URLEncoding.DecodeString(string(parts[0]))
	if err != nil {
		err = fmt.Errorf("failed to decode headers: %w", err)
		return
	}

	cekEncrypted, err = base64.URLEncoding.DecodeString(string(parts[1]))
	if err != nil {
		err = fmt.Errorf("failed to decode cek: %w", err)
		return
	}

	iv, err = base64.URLEncoding.DecodeString(string(parts[2]))
	if err != nil {
		err = fmt.Errorf("failed to decode IV: %w", err)
		return
	}

	ciphertext, err = base64.URLEncoding.DecodeString(string(parts[3]))
	if err != nil {
		err = fmt.Errorf("failed to decode ciphertext: %w", err)
		return
	}

	authTag, err = base64.URLEncoding.DecodeString(string(parts[4]))
	if err != nil {
		err = fmt.Errorf("failed to decode auth tag: %w", err)
		return
	}

	return
}

func pad(plaintext []byte, blockSize int) []byte {
	padding := blockSize - len(plaintext)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(plaintext, padText...)
}

func unpad(paddedText []byte, blockSize int) ([]byte, error) {
	length := len(paddedText)
	if length == 0 || length%blockSize != 0 {
		return nil, fmt.Errorf("invalid padded text length")
	}
	padding := int(paddedText[length-1])
	if padding > blockSize || padding == 0 {
		return nil, fmt.Errorf("invalid padding size")
	}
	for _, v := range paddedText[length-padding:] {
		if int(v) != padding {
			return nil, fmt.Errorf("invalid padding")
		}
	}
	return paddedText[:length-padding], nil
}

func aesDecrypt(key, ciphertext, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of the block size")
	}

	paddedPlaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(paddedPlaintext, ciphertext)
	plain, err := unpad(paddedPlaintext, aes.BlockSize)
	if err != nil {
		return nil, fmt.Errorf("failed to unpad plaintext: %w", err)
	}
	return plain, nil
}

func aesEncrypt(key, message []byte) (ciphertext, vi []byte, error error) {
	cekBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	iv := make([]byte, aes.BlockSize)
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return nil, nil, fmt.Errorf("failed to generate IV: %w", err)
	}
	plaintext := pad(message, aes.BlockSize)
	ciphertext = make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(cekBlock, iv).CryptBlocks(ciphertext, plaintext)
	return ciphertext, iv, nil
}

func extractECDHFromJWK(jwk jose.JSONWebKey) (*ecdh.PublicKey, error) {
	if !jwk.IsPublic() {
		return nil, fmt.Errorf("invalid key type")
	}

	r, ok := jwk.Key.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("invalid key type")
	}
	return ecdsaToECDH(r)
}

func ecdsaToECDH(p *ecdsa.PublicKey) (pub *ecdh.PublicKey, err error) {
	pub, err = p.ECDH()
	if err != nil {
		return nil, fmt.Errorf("failed to convert public key: %w", err)
	}
	return
}

func echdToECDSA(p *ecdh.PublicKey) (*ecdsa.PublicKey, error) {
	x, y := elliptic.Unmarshal(elliptic.P256(), p.Bytes())
	if x == nil || y == nil {
		return nil, fmt.Errorf("failed to convert public key")
	}

	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}, nil
}
