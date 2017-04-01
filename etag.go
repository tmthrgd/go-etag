// Copyright 2017 Tom Thorogood. All rights reserved.
// Use of this source code is governed by a
// Modified BSD License license that can be found in
// the LICENSE file.

package etag

import (
	"hash"

	"github.com/tmthrgd/go-hex"
)

const defaultLength = 32

// Etag wraps a hash.Hash and provides
// methods to get strong and weak Etags
// from the underlying hash.Hash.
type Etag struct {
	hash.Hash

	Length int
}

// Etag returns a strong ETag constructed by
// hex encoding the return of Sum.
func (e *Etag) Etag() string {
	length := e.length()

	hash := e.Hash.Sum(nil)

	var etagBuf [2 + 64]byte
	etag := buffer(2+length, etagBuf[:0])

	etag[0] = '"'
	hex.Encode(etag[1:], hash[:(length+1)/2])
	etag[1+length] = '"'

	return string(etag[:2+length])
}

// WeakEtag returns a weak ETag constructed by
// hex encoding the return of Sum.
func (e *Etag) WeakEtag() string {
	length := e.length()

	hash := e.Hash.Sum(nil)

	var etagBuf [4 + 64]byte
	etag := buffer(4+length, etagBuf[:0])

	etag[0] = 'W'
	etag[1] = '/'
	etag[2] = '"'
	hex.Encode(etag[3:], hash[:(length+1)/2])
	etag[3+length] = '"'

	return string(etag[:4+length])
}

func (e *Etag) length() int {
	l := defaultLength
	if e.Length != 0 {
		l = e.Length
	}

	if size := e.Hash.Size(); l >= 2*size {
		return 2 * size
	}

	return l
}

func buffer(l int, p []byte) []byte {
	if cap(p) >= l {
		return p[:l]
	}

	return make([]byte, l)
}