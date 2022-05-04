/*
Copyright Suzhou Tongji Fintech Research Institute 2017 All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

                 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

sm4 acceleration
modified by Jack, 2017 Oct
*/

//go:build GM
// +build GM

package aes

import (
	"crypto/cipher"
	"crypto/sm4"
	"strconv"
)

const BlockSize = 16

type KeySizeError int

func (k KeySizeError) Error() string {
	return "crypto/aes: invalid key size " + strconv.Itoa(int(k))
}

func NewCipher(key []byte) (cipher.Block, error) {
	l := len(key)
	if l == 32 || l == 24 {
		key = key[0:16]
	}
	return sm4.NewCipher(key)
}
