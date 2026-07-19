package managedbackup

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

const (
	streamMagic       = "PLBK1\x00\r\n"
	streamSaltBytes   = 16
	streamPrefixBytes = 4
	streamChunkBytes  = 1 << 20
	streamMemoryKiB   = 64 * 1024
	streamIterations  = 3
	streamParallelism = 1
	streamHeaderBytes = len(streamMagic) + 4 + 4 + 1 + streamSaltBytes + streamPrefixBytes + 4
)

var ErrAuthentication = errors.New("backup authentication failed")

type encryptedWriter struct {
	destination io.Writer
	aead        cipher.AEAD
	prefix      [streamPrefixBytes]byte
	buffer      []byte
	counter     uint64
	closed      bool
}

func newEncryptedWriter(destination io.Writer, passphrase []byte, random io.Reader) (*encryptedWriter, error) {
	if destination == nil || len(passphrase) < 12 {
		return nil, fmt.Errorf("backup destination and a passphrase of at least 12 bytes are required")
	}
	if random == nil {
		random = rand.Reader
	}
	salt := make([]byte, streamSaltBytes)
	var prefix [streamPrefixBytes]byte
	if _, err := io.ReadFull(random, salt); err != nil {
		return nil, fmt.Errorf("generate backup salt: %w", err)
	}
	if _, err := io.ReadFull(random, prefix[:]); err != nil {
		return nil, fmt.Errorf("generate backup nonce prefix: %w", err)
	}
	key := argon2.IDKey(passphrase, salt, streamIterations, streamMemoryKiB, streamParallelism, 32)
	defer wipe(key)
	aead, err := newStreamAEAD(key)
	if err != nil {
		return nil, err
	}
	header := make([]byte, streamHeaderBytes)
	position := copy(header, streamMagic)
	binary.BigEndian.PutUint32(header[position:], streamMemoryKiB)
	position += 4
	binary.BigEndian.PutUint32(header[position:], streamIterations)
	position += 4
	header[position] = streamParallelism
	position++
	position += copy(header[position:], salt)
	position += copy(header[position:], prefix[:])
	binary.BigEndian.PutUint32(header[position:], streamChunkBytes)
	if _, err := destination.Write(header); err != nil {
		return nil, fmt.Errorf("write backup header: %w", err)
	}
	return &encryptedWriter{
		destination: destination, aead: aead, prefix: prefix,
		buffer: make([]byte, 0, streamChunkBytes),
	}, nil
}

func (w *encryptedWriter) Write(input []byte) (int, error) {
	if w == nil || w.closed {
		return 0, fmt.Errorf("backup encryption stream is closed")
	}
	written := 0
	for len(input) > 0 {
		space := streamChunkBytes - len(w.buffer)
		count := len(input)
		if count > space {
			count = space
		}
		w.buffer = append(w.buffer, input[:count]...)
		input = input[count:]
		written += count
		if len(w.buffer) == streamChunkBytes {
			if err := w.flush(false); err != nil {
				return written, err
			}
		}
	}
	return written, nil
}

func (w *encryptedWriter) Close() error {
	if w == nil || w.closed {
		return nil
	}
	if len(w.buffer) > 0 {
		if err := w.flush(false); err != nil {
			return err
		}
	}
	if err := w.flush(true); err != nil {
		return err
	}
	w.closed = true
	return nil
}

func (w *encryptedWriter) flush(final bool) error {
	nonce := streamNonce(w.prefix, w.counter)
	plaintext := w.buffer
	if final {
		plaintext = nil
	}
	ciphertext := w.aead.Seal(nil, nonce[:], plaintext, streamAAD(w.counter, final))
	if len(ciphertext) > streamChunkBytes+w.aead.Overhead() {
		return fmt.Errorf("backup encrypted chunk exceeds limit")
	}
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(ciphertext)))
	if _, err := w.destination.Write(size[:]); err != nil {
		return fmt.Errorf("write backup chunk size: %w", err)
	}
	if _, err := w.destination.Write(ciphertext); err != nil {
		return fmt.Errorf("write backup encrypted chunk: %w", err)
	}
	wipe(w.buffer)
	w.buffer = w.buffer[:0]
	w.counter++
	return nil
}

type encryptedReader struct {
	source  io.Reader
	aead    cipher.AEAD
	prefix  [streamPrefixBytes]byte
	plain   []byte
	counter uint64
	final   bool
}

func newEncryptedReader(source io.Reader, passphrase []byte) (*encryptedReader, error) {
	if source == nil || len(passphrase) < 12 {
		return nil, ErrAuthentication
	}
	header := make([]byte, streamHeaderBytes)
	if _, err := io.ReadFull(source, header); err != nil {
		return nil, ErrAuthentication
	}
	if string(header[:len(streamMagic)]) != streamMagic {
		return nil, ErrAuthentication
	}
	position := len(streamMagic)
	memory := binary.BigEndian.Uint32(header[position:])
	position += 4
	iterations := binary.BigEndian.Uint32(header[position:])
	position += 4
	parallelism := header[position]
	position++
	salt := header[position : position+streamSaltBytes]
	position += streamSaltBytes
	var prefix [streamPrefixBytes]byte
	copy(prefix[:], header[position:position+streamPrefixBytes])
	position += streamPrefixBytes
	chunkSize := binary.BigEndian.Uint32(header[position:])
	if memory != streamMemoryKiB || iterations != streamIterations || parallelism != streamParallelism || chunkSize != streamChunkBytes {
		return nil, ErrAuthentication
	}
	key := argon2.IDKey(passphrase, salt, iterations, memory, parallelism, 32)
	defer wipe(key)
	aead, err := newStreamAEAD(key)
	if err != nil {
		return nil, ErrAuthentication
	}
	return &encryptedReader{source: source, aead: aead, prefix: prefix}, nil
}

func (r *encryptedReader) Read(destination []byte) (int, error) {
	if len(destination) == 0 {
		return 0, nil
	}
	for len(r.plain) == 0 {
		if r.final {
			return 0, io.EOF
		}
		if err := r.load(); err != nil {
			return 0, err
		}
	}
	count := copy(destination, r.plain)
	wipe(r.plain[:count])
	r.plain = r.plain[count:]
	return count, nil
}

func (r *encryptedReader) load() error {
	var encodedSize [4]byte
	if _, err := io.ReadFull(r.source, encodedSize[:]); err != nil {
		return ErrAuthentication
	}
	size := binary.BigEndian.Uint32(encodedSize[:])
	if size < uint32(r.aead.Overhead()) || size > streamChunkBytes+uint32(r.aead.Overhead()) {
		return ErrAuthentication
	}
	ciphertext := make([]byte, size)
	if _, err := io.ReadFull(r.source, ciphertext); err != nil {
		return ErrAuthentication
	}
	final := size == uint32(r.aead.Overhead())
	nonce := streamNonce(r.prefix, r.counter)
	plaintext, err := r.aead.Open(nil, nonce[:], ciphertext, streamAAD(r.counter, final))
	wipe(ciphertext)
	if err != nil {
		return ErrAuthentication
	}
	r.counter++
	if final {
		var extra [1]byte
		if count, err := r.source.Read(extra[:]); count != 0 || !errors.Is(err, io.EOF) {
			wipe(plaintext)
			return ErrAuthentication
		}
		r.final = true
		return nil
	}
	if len(plaintext) == 0 {
		return ErrAuthentication
	}
	r.plain = plaintext
	return nil
}

func newStreamAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create backup cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create backup AEAD: %w", err)
	}
	return aead, nil
}

func streamNonce(prefix [streamPrefixBytes]byte, counter uint64) [12]byte {
	var nonce [12]byte
	copy(nonce[:streamPrefixBytes], prefix[:])
	binary.BigEndian.PutUint64(nonce[streamPrefixBytes:], counter)
	return nonce
}

func streamAAD(counter uint64, final bool) []byte {
	var aad [17]byte
	copy(aad[:8], streamMagic)
	binary.BigEndian.PutUint64(aad[8:16], counter)
	if final {
		aad[16] = 1
	}
	return aad[:]
}

func wipe(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
