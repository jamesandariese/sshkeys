package sshkeys

import (
	"crypto/rsa"
	"errors"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"math/big"
)

// RSAPublicKey is the format an RSA public key takes in memory
type rsaPublicKey struct {
	Keytype  string
	Exponent *big.Int
	Modulus  *big.Int
}

var UnrecognizedKeyError = errors.New("Unrecognized Key Type")

func DecodePublicKeyBytes(bytes []byte) (interface{}, error) {
	pk, comment, options, rest, err := ssh.ParseAuthorizedKey(bytes)
	_, _, _ = comment, options, rest
	if err != nil {
		return nil, err
	}
	if pk.Type() == ssh.KeyAlgoRSA {
		rsaKey := &rsaPublicKey{}
		if err := ssh.Unmarshal(pk.Marshal(), rsaKey); err != nil {
			return nil, err
		}
		return &rsa.PublicKey{rsaKey.Modulus, int(rsaKey.Exponent.Int64())}, nil
	}
	return nil, UnrecognizedKeyError
}

// DecodePrivateKeyBytes decodes a private key
func DecodePrivateKeyBytes(bytes []byte) (interface{}, error) {
	key, err := ssh.ParseRawPrivateKey(bytes)
	return key, err
}

// ReadPrivateKeyFile decodes a private key file
func ReadPrivateKeyFile(file string) (interface{}, error) {
	privateKeyData, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	key, err := ssh.ParseRawPrivateKey(privateKeyData)
	if err != nil {
		return nil, err
	}
	return key, nil
}
