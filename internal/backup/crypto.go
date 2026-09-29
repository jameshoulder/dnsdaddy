// Package backup creates authenticated, encrypted recovery packages and
// restores them offline into a directory that does not already exist.
package backup

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	"golang.org/x/crypto/scrypt"
)

// The version fixes every cryptographic parameter. The file cannot ask the
// reader to allocate an attacker-selected KDF cost or record size.
const (
	FormatVersion         = 1
	chunkSize             = 1 << 20
	saltSize              = 32
	headerSize            = 16 + saltSize + 4
	MaxArchiveBytes int64 = 1 << 30
)

var magic = [16]byte{'D', 'N', 'S', 'D', 'A', 'D', 'D', 'Y', 'B', 'A', 'C', 'K', 'U', 'P', 0, FormatVersion}

var (
	ErrPassphrase     = errors.New("backup passphrase must contain 12 to 1024 UTF-8 bytes")
	ErrAuthentication = errors.New("backup authentication failed: wrong passphrase, damaged file, or incomplete package")
	ErrLimit          = errors.New("backup exceeds its supported size or file-count limit")
	ErrBusy           = errors.New("a backup is already running")
)

func ValidatePassphrase(p []byte) error {
	if len(p) < 12 || len(p) > 1024 || !utf8.Valid(p) {
		return ErrPassphrase
	}
	return nil
}

func derive(p, salt []byte) (cipher.AEAD, error) {
	// scrypt uses approximately 128 MiB; callers serialize backup creation.
	key, err := scrypt.Key(p, salt, 1<<17, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// sealWriter is a bounded record stream using standard AES-256-GCM. Each
// nonce is a random 32-bit prefix followed by a monotonic 64-bit record index;
// the key is independently derived with a fresh 256-bit salt for every file.
// The header, index and ciphertext length are authenticated as associated
// data. A final authenticated empty record is mandatory. Removing, reordering,
// appending or truncating records therefore fails verification.
type sealWriter struct {
	w      io.Writer
	aead   cipher.AEAD
	header [headerSize]byte
	index  uint64
	buf    []byte
	total  int64
	err    error
}

func newSealWriter(w io.Writer, passphrase []byte) (*sealWriter, error) {
	if err := ValidatePassphrase(passphrase); err != nil {
		return nil, err
	}
	s := &sealWriter{w: w, buf: make([]byte, 0, chunkSize)}
	copy(s.header[:16], magic[:])
	if _, err := rand.Read(s.header[16:]); err != nil {
		return nil, err
	}
	aead, err := derive(passphrase, s.header[16:16+saltSize])
	if err != nil {
		return nil, err
	}
	s.aead = aead
	if err := writeAll(w, s.header[:]); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *sealWriter) Write(p []byte) (int, error) {
	if s.err != nil {
		return 0, s.err
	}
	if s.total+int64(len(p)) > MaxArchiveBytes {
		s.err = ErrLimit
		return 0, s.err
	}
	n := len(p)
	s.total += int64(n)
	for len(p) > 0 {
		count := min(chunkSize-len(s.buf), len(p))
		s.buf = append(s.buf, p[:count]...)
		p = p[count:]
		if len(s.buf) == chunkSize {
			if err := s.record(s.buf); err != nil {
				s.err = err
				return n - len(p), err
			}
			clear(s.buf)
			s.buf = s.buf[:0]
		}
	}
	return n, nil
}

func (s *sealWriter) record(p []byte) error {
	var nonce [12]byte
	copy(nonce[:4], s.header[16+saltSize:])
	binary.BigEndian.PutUint64(nonce[4:], s.index)
	size := uint32(len(p) + s.aead.Overhead())
	aad := recordAAD(s.header[:], s.index, size)
	sealed := s.aead.Seal(nil, nonce[:], p, aad)
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], size)
	if err := writeAll(s.w, prefix[:]); err != nil {
		return err
	}
	if err := writeAll(s.w, sealed); err != nil {
		return err
	}
	s.index++
	return nil
}

func (s *sealWriter) Close() error {
	defer clear(s.buf)
	if s.err != nil {
		return s.err
	}
	if len(s.buf) > 0 {
		if err := s.record(s.buf); err != nil {
			return err
		}
	}
	return s.record(nil)
}

func recordAAD(header []byte, index uint64, size uint32) []byte {
	aad := make([]byte, len(header)+12)
	copy(aad, header)
	binary.BigEndian.PutUint64(aad[len(header):], index)
	binary.BigEndian.PutUint32(aad[len(header)+8:], size)
	return aad
}

type openReader struct {
	r      io.Reader
	aead   cipher.AEAD
	header [headerSize]byte
	index  uint64
	buf    []byte
	total  int64
	done   bool
}

func newOpenReader(r io.Reader, p []byte) (*openReader, error) {
	if err := ValidatePassphrase(p); err != nil {
		return nil, err
	}
	d := &openReader{r: r}
	if _, err := io.ReadFull(r, d.header[:]); err != nil {
		return nil, ErrAuthentication
	}
	if string(d.header[:16]) != string(magic[:]) {
		return nil, fmt.Errorf("unsupported or invalid backup format")
	}
	aead, err := derive(p, d.header[16:16+saltSize])
	if err != nil {
		return nil, err
	}
	d.aead = aead
	return d, nil
}

func (d *openReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(d.buf) > 0 {
		n := copy(p, d.buf)
		clear(d.buf[:n])
		d.buf = d.buf[n:]
		return n, nil
	}
	if d.done {
		return 0, io.EOF
	}
	var prefix [4]byte
	if _, err := io.ReadFull(d.r, prefix[:]); err != nil {
		return 0, ErrAuthentication
	}
	size := binary.BigEndian.Uint32(prefix[:])
	if size < uint32(d.aead.Overhead()) || size > chunkSize+uint32(d.aead.Overhead()) {
		return 0, ErrAuthentication
	}
	sealed := make([]byte, int(size))
	if _, err := io.ReadFull(d.r, sealed); err != nil {
		return 0, ErrAuthentication
	}
	var nonce [12]byte
	copy(nonce[:4], d.header[16+saltSize:])
	binary.BigEndian.PutUint64(nonce[4:], d.index)
	plain, err := d.aead.Open(nil, nonce[:], sealed, recordAAD(d.header[:], d.index, size))
	if err != nil {
		return 0, ErrAuthentication
	}
	d.index++
	if len(plain) == 0 {
		// There is exactly one terminal record. Even an otherwise valid second
		// encrypted stream concatenated to this one is refused.
		var extra [1]byte
		if n, err := d.r.Read(extra[:]); n != 0 || err != io.EOF {
			return 0, ErrAuthentication
		}
		d.done = true
		return 0, io.EOF
	}
	d.total += int64(len(plain))
	if d.total > MaxArchiveBytes {
		clear(plain)
		return 0, ErrLimit
	}
	d.buf = plain
	return d.Read(p)
}

func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}
