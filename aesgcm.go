/**
 * AES with GCM
 *
 * An implementation of Galois/Counter Mode (GCM) with Advanced Encryption System (AES).
 *
 * Copyright (c) 2018. Aryo Karbhawono. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by the copyright holder.
 * 4. Neither the name of the copyright holder nor the
 *    names of its contributors may be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"io"
)

/**
 * Example Usage
 *
 * @return {[type]} [returning object]
 *
 * func main() {
 *   fmt.Printf("%x\n", Encrypt("AES256Key-32Characters1234567890", "testing 123"))
 *   fmt.Printf("%s\n", Decrypt("AES256Key-32Characters1234567890", "da269a9651869d87d3f5711074bb1652f7177db9dece2f466fb690", "13298648720762faad1b678e"))
 * }
 *
 */

type EncryptMessage struct {
	Nonce         []byte
	EncryptedText []byte
}
type DecryptMessage struct {
	DecryptedText string
}

/**
 * Encrypt Message
 *
 * @param {[type]} chiperkey string  [The key argument should be the AES key, either 16 or 32 bytes to select AES-128 or AES-256]
 * @param {[type]} msg       string  [The nonce]
 * @return {[type]} em       EncryptMessage [returning object]
 */
func Encrypt(chiperkey string, msg string) (em EncryptMessage) {

	key := []byte(chiperkey)

	plaintext := []byte(msg)

	block, err := aes.NewCipher(key)

	if err != nil {
		panic(err.Error())
	}

	nonce := make([]byte, 12)

	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)

	if err != nil {
		panic(err.Error())
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)

	em = EncryptMessage{
		Nonce:         nonce,
		EncryptedText: ciphertext,
	}

	return em
}

/**
 * Decrypt Message
 *
 * @param {[type]} dechiperkey   string  [The key argument should be the AES key, either 16 or 32 bytes to select AES-128 or AES-256]
 * @param {[type]} decmsg        string  [The encrypted message]
 * @param {[type]} auth          string  [The nonce]
 * @return {[type]} em           DecryptMessage [returning object]
 */
func Decrypt(dechiperkey string, decmsg string, token string) (dm DecryptMessage) {

	key := []byte(dechiperkey)

	ciphertext, _ := hex.DecodeString(decmsg)

	nonce, _ := hex.DecodeString(token)

	block, err := aes.NewCipher(key)

	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)

	if err != nil {
		panic(err.Error())
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)

	if err != nil {
		panic(err.Error())
	}

	dm = DecryptMessage{
		DecryptedText: string(plaintext),
	}

	return dm
}
