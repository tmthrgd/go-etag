// Copyright 2017 Tom Thorogood. All rights reserved.
// Use of this source code is governed by a
// Modified BSD License license that can be found in
// the LICENSE file.

package etag

import (
	"fmt"
	"regexp"
	"testing"
	"testing/quick"

	"crypto/sha512"
	"encoding/hex"
)

type dummyHash []byte

func (dummyHash) BlockSize() int { return 1 }
func (dummyHash) Reset()         {}
func (h dummyHash) Size() int    { return len(h) }

func (dummyHash) Write(p []byte) (int, error) {
	return len(p), nil
}

func (h dummyHash) Sum(p []byte) []byte {
	return append(p, h...)
}

func TestEtag(t *testing.T) {
	for i := 1; i <= 128; i++ {
		etag := (&Etag{
			Hash:   dummyHash(make([]byte, 128)),
			Length: i,
		}).Etag()
		if !regexp.MustCompile(fmt.Sprintf(`"0{%d}"`, i)).MatchString(etag) {
			t.Errorf("invalid format for length of %d: %s", i, etag)
		}
	}
}

func TestWeakEtag(t *testing.T) {
	for i := 1; i <= 128; i++ {
		etag := (&Etag{
			Hash:   dummyHash(make([]byte, 128)),
			Length: i,
		}).WeakEtag()
		if !regexp.MustCompile(fmt.Sprintf(`W/"0{%d}"`, i)).MatchString(etag) {
			t.Errorf("invalid format for length of %d: %s", i, etag)
		}
	}
}

func TestCorrect(t *testing.T) {
	if err := quick.CheckEqual(func(p []byte, s uint) string {
		s &= ^uint(0) >> 1
		return (&Etag{
			Hash:   dummyHash(p),
			Length: int(s),
		}).Etag()
	}, func(p []byte, s uint) string {
		s &= ^uint(0) >> 1
		if s == 0 {
			s = defaultLength
		}

		enc := hex.EncodeToString(p)
		if s > uint(len(enc)) {
			s = uint(len(enc))
		}

		return `"` + enc[:s] + `"`
	}, nil); err != nil {
		t.Fatal(err)
	}
}

func BenchmarkEtag(b *testing.B) {
	for i := 16; i <= 128; i *= 2 {
		b.Run(fmt.Sprint(i), func(b *testing.B) {
			h := &Etag{
				Hash:   dummyHash(make([]byte, i)),
				Length: i,
			}

			for n := 0; n < b.N; n++ {
				h.Etag()
			}
		})
	}
}

func BenchmarkEtag_SHA512_256(b *testing.B) {
	h := sha512.New512_256()

	for i := 16; i <= 2*h.Size(); i *= 2 {
		b.Run(fmt.Sprint(i), func(b *testing.B) {
			h := &Etag{h, i}

			for n := 0; n < b.N; n++ {
				h.Etag()
			}
		})
	}
}
