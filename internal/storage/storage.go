package storage

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"s3web/internal/hashstream"
	"s3web/internal/model"
)

var (
	ErrObjectNotFound = errors.New("object not found in storage")
	ErrInvalidRange   = errors.New("invalid byte range")
)

// PutResult contains the calculated full-file linear SHA-256 and SHA-1 digests
// and S3 metadata produced during a streaming upload.
type PutResult struct {
	Key             string
	Size            int64
	SHA256          string
	SHA1            string
	ETag            string
	StorageClass    string
	IntelligentTier model.IntelligentTier
	UpdatedAt       time.Time
}

// GetResult wraps a readable object stream and its range/length headers.
type GetResult struct {
	Body          io.ReadCloser
	ContentLength int64
	TotalSize     int64
	ContentRange  string
	IsPartial     bool
	LastModified  time.Time
}

// ObjectStorage abstracts Amazon S3 (via VPC Gateway Endpoint) and local disk storage.
type ObjectStorage interface {
	// PutStream streams r to storage while computing full-file linear SHA-256 and SHA-1 in a single pass.
	PutStream(ctx context.Context, key string, r io.Reader, contentType string) (*PutResult, error)
	// GetStream opens a stream for key, optionally supporting HTTP Range requests ("bytes=start-end").
	GetStream(ctx context.Context, key string, rangeHeader string) (*GetResult, error)
	// Delete removes the object from storage.
	Delete(ctx context.Context, key string) error
	// Restore initiates an asynchronous S3 RestoreObject request for ARCHIVE_ACCESS / DEEP_ARCHIVE_ACCESS items.
	Restore(ctx context.Context, key string, days int) error
}

// LocalFSStorage stores objects on the local filesystem while faithfully implementing
// streaming SHA-256 + SHA-1 computation, HTTP Range requests, and S3 Intelligent-Tiering semantics.
type LocalFSStorage struct {
	rootDir string
}

// NewLocalFSStorage creates a LocalFSStorage rooted at rootDir.
func NewLocalFSStorage(rootDir string) (*LocalFSStorage, error) {
	objectsDir := filepath.Join(rootDir, "objects")
	if err := os.MkdirAll(objectsDir, 0o755); err != nil {
		return nil, fmt.Errorf("create objects dir: %w", err)
	}
	return &LocalFSStorage{rootDir: objectsDir}, nil
}

func (l *LocalFSStorage) safePath(key string) (string, error) {
	cleaned := filepath.Clean(strings.TrimLeft(key, "/"))
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", errors.New("invalid object key path")
	}
	full := filepath.Join(l.rootDir, cleaned)
	if !strings.HasPrefix(full, filepath.Clean(l.rootDir)+string(os.PathSeparator)) {
		return "", errors.New("path traversal rejected")
	}
	return full, nil
}

func (l *LocalFSStorage) PutStream(_ context.Context, key string, r io.Reader, _ string) (*PutResult, error) {
	destPath, err := l.safePath(key)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		return nil, fmt.Errorf("mkdir parent: %w", err)
	}

	tmpPath := fmt.Sprintf("%s.upload-%d.tmp", destPath, time.Now().UnixNano())
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open temp file: %w", err)
	}
	defer func() {
		_ = f.Close()
		_ = os.Remove(tmpPath)
	}()

	// Stream through DualHasher (SHA-256 + SHA-1) and MD5 (for S3 ETag compatibility) in one pass
	dualHasher := hashstream.NewReader(r)
	md5Hasher := md5.New()
	writer := io.MultiWriter(f, md5Hasher)

	buf := make([]byte, 256*1024) // 256 KB streaming buffer
	if _, err := io.CopyBuffer(writer, dualHasher, buf); err != nil {
		return nil, fmt.Errorf("stream upload: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("close file: %w", err)
	}
	if err := os.Rename(tmpPath, destPath); err != nil {
		return nil, fmt.Errorf("commit uploaded file: %w", err)
	}

	sha256Hex, sha1Hex, totalBytes := dualHasher.Sums()
	etag := hex.EncodeToString(md5Hasher.Sum(nil))

	return &PutResult{
		Key:             strings.TrimLeft(key, "/"),
		Size:            totalBytes,
		SHA256:          sha256Hex,
		SHA1:            sha1Hex,
		ETag:            etag,
		StorageClass:    "INTELLIGENT_TIERING",
		IntelligentTier: model.TierFrequentAccess,
		UpdatedAt:       time.Now().UTC(),
	}, nil
}

func (l *LocalFSStorage) GetStream(_ context.Context, key string, rangeHeader string) (*GetResult, error) {
	destPath, err := l.safePath(key)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(destPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrObjectNotFound
		}
		return nil, err
	}
	stat, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	totalSize := stat.Size()

	if strings.TrimSpace(rangeHeader) == "" {
		return &GetResult{
			Body:          f,
			ContentLength: totalSize,
			TotalSize:     totalSize,
			IsPartial:     false,
			LastModified:  stat.ModTime().UTC(),
		}, nil
	}

	start, end, err := parseByteRange(rangeHeader, totalSize)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		_ = f.Close()
		return nil, err
	}
	length := (end - start) + 1
	return &GetResult{
		Body: &limitedReadCloser{
			Reader: io.LimitReader(f, length),
			Closer: f,
		},
		ContentLength: length,
		TotalSize:     totalSize,
		ContentRange:  fmt.Sprintf("bytes %d-%d/%d", start, end, totalSize),
		IsPartial:     true,
		LastModified:  stat.ModTime().UTC(),
	}, nil
}

func (l *LocalFSStorage) Delete(_ context.Context, key string) error {
	destPath, err := l.safePath(key)
	if err != nil {
		return err
	}
	if err := os.Remove(destPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (l *LocalFSStorage) Restore(_ context.Context, key string, _ int) error {
	destPath, err := l.safePath(key)
	if err != nil {
		return err
	}
	if _, err := os.Stat(destPath); err != nil {
		if os.IsNotExist(err) {
			return ErrObjectNotFound
		}
		return err
	}
	return nil
}

type limitedReadCloser struct {
	io.Reader
	io.Closer
}

func parseByteRange(header string, size int64) (int64, int64, error) {
	if size <= 0 {
		return 0, 0, ErrInvalidRange
	}
	if !strings.HasPrefix(header, "bytes=") {
		return 0, 0, ErrInvalidRange
	}
	spec := strings.TrimPrefix(header, "bytes=")
	if strings.Contains(spec, ",") {
		// Only single range supported for simplicity
		spec = strings.Split(spec, ",")[0]
	}
	parts := strings.SplitN(strings.TrimSpace(spec), "-", 2)
	if len(parts) != 2 {
		return 0, 0, ErrInvalidRange
	}
	var start, end int64
	var err error
	if parts[0] == "" {
		// suffix range: "-500"
		suffix, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil || suffix <= 0 {
			return 0, 0, ErrInvalidRange
		}
		if suffix > size {
			suffix = size
		}
		start = size - suffix
		end = size - 1
	} else {
		start, err = strconv.ParseInt(parts[0], 10, 64)
		if err != nil || start < 0 || start >= size {
			return 0, 0, ErrInvalidRange
		}
		if parts[1] == "" {
			end = size - 1
		} else {
			end, err = strconv.ParseInt(parts[1], 10, 64)
			if err != nil || end < start {
				return 0, 0, ErrInvalidRange
			}
			if end >= size {
				end = size - 1
			}
		}
	}
	return start, end, nil
}

