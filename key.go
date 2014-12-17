// Copyright 2014 Matthew Endsley
// All rights reserved
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted providing that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
// OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
// IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package gojwk

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

type Key struct {
	Keys []*Key `json:"keys,omitempty"`

	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid,omitempty"`
	Alg string `json:"alg,omitempty"`

	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	D   string `json:"d,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	K   string `json:"k,omitempty"`
}

// Wrapper to unmarshal a JSON octet stream to a structured JWK
func Unmarshal(jwt []byte) (*Key, error) {
	key := new(Key)
	err := json.Unmarshal(jwt, key)
	return key, err
}

// Decode as a public key
func (key *Key) DecodePublicKey() (crypto.PublicKey, error) {
	switch key.Kty {
	case "RSA":
		if key.N == "" || key.E == "" {
			return nil, errors.New("Malformed JWK RSA key")
		}

		// decode exponent
		data, err := safeDecode(key.E)
		if err != nil {
			return nil, errors.New("Malformed JWK RSA key")
		}
		if len(data) < 4 {
			ndata := make([]byte, 4)
			copy(ndata[4-len(data):], data)
			data = ndata
		}

		pubKey := &rsa.PublicKey{
			N: &big.Int{},
			E: int(binary.BigEndian.Uint32(data[:])),
		}

		data, err = safeDecode(key.N)
		if err != nil {
			return nil, errors.New("Malformed JWK RSA key")
		}
		pubKey.N.SetBytes(data)

		return pubKey, nil

	case "EC":
		if key.Crv == "" || key.X == "" || key.Y == "" {
			return nil, errors.New("Malformed JWK EC key")
		}

		var curve elliptic.Curve
		switch key.Crv {
		case "P-224":
			curve = elliptic.P224()
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("Unknown curve type: %s", key.Crv)
		}

		pubKey := &ecdsa.PublicKey{
			Curve: curve,
			X:     &big.Int{},
			Y:     &big.Int{},
		}

		data, err := safeDecode(key.X)
		if err != nil {
			return nil, fmt.Errorf("Malformed JWK EC key")
		}
		pubKey.X.SetBytes(data)

		data, err = safeDecode(key.Y)
		if err != nil {
			return nil, fmt.Errorf("Malformed JWK EC key")
		}
		pubKey.Y.SetBytes(data)

		return pubKey, nil

	case "oct":
		if key.K == "" {
			return nil, errors.New("Malformed JWK octect key")
		}

		data, err := safeDecode(key.K)
		if err != nil {
			return nil, errors.New("Malformed JWK octect key")
		}

		return data, nil

	default:
		return nil, fmt.Errorf("Unknown JWK key type %s", key.Kty)
	}
}

// Decodes as a private key
func (key *Key) DecodePrivateKey() (crypto.PrivateKey, error) {
	switch key.Kty {
	case "RSA":
		if key.D == "" {
			return nil, errors.New("Malformed JWK RSA key")
		}

		pub, err := key.DecodePublicKey()
		if err != nil {
			return nil, err
		}

		privKey := &rsa.PrivateKey{
			PublicKey: *pub.(*rsa.PublicKey),
			D:         &big.Int{},
		}

		data, err := safeDecode(key.D)
		if err != nil {
			return nil, errors.New("Malformed JWK RSA key")
		}
		privKey.D.SetBytes(data)

		return privKey, nil

	case "EC":
		if key.D == "" {
			return nil, errors.New("Malformed JWK EC key")
		}

		pub, err := key.DecodePublicKey()
		if err != nil {
			return nil, err
		}

		privKey := &ecdsa.PrivateKey{
			PublicKey: *pub.(*ecdsa.PublicKey),
			D:         &big.Int{},
		}

		data, err := safeDecode(key.D)
		if err != nil {
			return nil, fmt.Errorf("Malformed JWK EC key")
		}
		privKey.D.SetBytes(data)

		return privKey, nil

	case "oct":
		return key.DecodePublicKey()

	default:
		return nil, fmt.Errorf("Unknown JWK key type %s", key.Kty)
	}
}
