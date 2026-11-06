package hashstream

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"io"
)

// DualHasher wraps an io.Reader and computes both linear SHA-256 and SHA-1 digests
// in a single pass as bytes are read through the stream.
type DualHasher struct {
	reader    io.Reader
	sha256    hash.Hash
	sha1      hash.Hash
	bytesRead int64
}

// NewReader returns a DualHasher that tees all reads from r into SHA-256 and SHA-1 hashers.
func NewReader(r io.Reader) *DualHasher {
	h256 := sha256.New()
	h1 := sha1.New()
	multi := io.MultiWriter(h256, h1)
	return &DualHasher{
		reader: io.TeeReader(r, multi),
		sha256: h256,
		sha1:   h1,
	}
}

// Read implements io.Reader.
func (d *DualHasher) Read(p []byte) (int, error) {
	n, err := d.reader.Read(p)
	if n > 0 {
		d.bytesRead += int64(n)
	}
	return n, err
}

// Sums returns the hex-encoded full-stream SHA-256 and SHA-1 digests and total bytes read.
func (d *DualHasher) Sums() (sha256Hex string, sha1Hex string, totalBytes int64) {
	return hex.EncodeToString(d.sha256.Sum(nil)), hex.EncodeToString(d.sha1.Sum(nil)), d.bytesRead
}

