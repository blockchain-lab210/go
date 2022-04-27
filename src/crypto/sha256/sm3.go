// Copyright 2022 Lab210. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This is a wrapper that replace sha256 with GM sm3

//go:build GM
// +build GM

package sha256

import (
	"crypto"
	"crypto/gm/sm3"
	"fmt"
	"hash"
)

func init() {
	fmt.Println("Init GM sm3 wrapper for Go lib crypto/sha256.")
	crypto.RegisterHash(crypto.SHA224, New224)
	crypto.RegisterHash(crypto.SHA256, New)
}

// The size of a SHA256 checksum in bytes.
const Size = 32

// The size of a SHA224 checksum in bytes.
const Size224 = 28

// The blocksize of SHA256 and SHA224 in bytes.
const BlockSize = 64

// digest represents the partial evaluation of a checksum.
type digest struct {
	sm3.SM3
	is224 bool // mark if this digest is SHA-224
}

// New returns a new hash.Hash computing the SHA256 checksum. The Hash
// also implements encoding.BinaryMarshaler and
// encoding.BinaryUnmarshaler to marshal and unmarshal the internal
// state of the hash.
func New() hash.Hash {
	d := new(digest)
	d.Reset()
	return d
}

// New224 returns a new hash.Hash computing the SHA224 checksum.
func New224() hash.Hash {
	d := new(digest)
	d.is224 = true
	d.Reset()
	return d
}

func (d *digest) Size() int {
	if !d.is224 {
		return Size
	}
	return Size224
}

func (d *digest) BlockSize() int { return BlockSize }

func (d *digest) Sum(in []byte) []byte {
	// Make a copy of d so that caller can keep writing and summing.
	d0 := *d
	hash := d0.SM3.Sum(in)
	if d0.is224 {
		return append(in, hash[:Size224]...)
	}
	return append(in, hash[:]...)
}

// Sum256 returns the SHA256 checksum of the data.
func Sum256(data []byte) (sum256 [Size]byte) {
	sum := sm3.Sm3Sum(data)
	copy(sum256[:], sum[:Size])
	return
}

// Sum224 returns the SHA224 checksum of the data.
func Sum224(data []byte) (sum224 [Size224]byte) {
	sum := sm3.Sm3Sum(data)
	copy(sum224[:], sum[:Size224])
	return
}
