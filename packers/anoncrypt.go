package packers

import (
	"crypto"
	"encoding/json"
	"github.com/iden3/iden3comm"
	"github.com/pkg/errors"

	jose "gopkg.in/square/go-jose.v2"
)

// MediaTypeEncryptedMessage is media type for ecnrypted message
const MediaTypeEncryptedMessage iden3comm.MediaType = "application/iden3comm-encrypted-json"

// AnoncryptPacker is  packer for anon encryption / decryption
type AnoncryptPacker struct {
}
type KeyPair struct {
	crypto.PublicKey
	crypto.PrivateKey
}

// Pack returns packed message to transport envelope
func (p *AnoncryptPacker) Pack(payload []byte, senderKeyPair KeyPair, receiverPubKey []byte) ([]byte, error) {

	encryptor, err := jose.NewEncrypter(jose.A256CBC_HS512, jose.Recipient{
		Algorithm: jose.ECDH_ES_A256KW,
		Key:       receiverPubKey,
		KeyID:     "kid",
	}, new(jose.EncrypterOptions).WithType(jose.ContentType(MediaTypeEncryptedMessage)))
	if err != nil {
		return nil, err
	}
	jwe, err := encryptor.Encrypt(payload)
	if err != nil {
		return nil, err
	}
	jweString, err := jwe.CompactSerialize()
	if err != nil {
		return nil, err
	}
	return []byte(jweString), nil

}

// Unpack returns unpacked message from transport envelope
func (p *AnoncryptPacker) Unpack(envelope []byte) (*iden3comm.BasicMessage, error) {

	var msg iden3comm.BasicMessage
	err := json.Unmarshal(envelope, &msg)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return &msg, err
}

// MediaType for iden3comm
func (p *AnoncryptPacker) MediaType() iden3comm.MediaType {
	return MediaTypeEncryptedMessage
}
