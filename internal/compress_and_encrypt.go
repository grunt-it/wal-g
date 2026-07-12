package internal

import (
	"fmt"
	"io"

	"github.com/pkg/errors"
	"github.com/wal-g/tracelog"
	"github.com/wal-g/wal-g/internal/compression"
	"github.com/wal-g/wal-g/internal/crypto"
	"github.com/wal-g/wal-g/utility"
)

// CompressAndEncryptError is used to catch specific errors from CompressAndEncrypt
// when uploading to Storage. Will not retry upload if this error occurs.
type CompressAndEncryptError struct {
	error
}

func newCompressingPipeWriterError(reason string, cause error) CompressAndEncryptError {
	err := errors.Wrap(cause, reason)
	if err == nil {
		err = errors.New(reason)
	}
	return CompressAndEncryptError{err}
}

func (err CompressAndEncryptError) Error() string {
	return fmt.Sprintf(tracelog.GetErrorFormatter(), err.error)
}

// CompressAndEncrypt streams compressed and encrypted input through a pipe.
// Writer construction runs in the producer goroutine because some crypters, including age,
// synchronously emit a header from Encrypt. Constructing them before returning the pipe reader
// deadlocks: the header fills an unconsumed io.Pipe before the caller can start reading.
func CompressAndEncrypt(source io.Reader, compressor compression.Compressor, crypter crypto.Crypter) io.Reader {
	compressedReader, dstWriter := io.Pipe()

	go func() {
		var encryptedWriter io.WriteCloser = dstWriter
		if crypter != nil {
			var err error
			encryptedWriter, err = crypter.Encrypt(dstWriter)
			if err != nil {
				e := newCompressingPipeWriterError("CompressAndEncrypt: encryption setup failed", err)
				_ = dstWriter.CloseWithError(e)
				return
			}
		}

		outputWriter := io.Writer(encryptedWriter)
		var compressedWriter io.WriteCloser
		if compressor != nil {
			writeIgnorer := &utility.EmptyWriteIgnorer{Writer: encryptedWriter}
			compressedWriter = compressor.NewWriter(writeIgnorer)
			outputWriter = compressedWriter
		}

		if _, err := utility.FastCopy(outputWriter, source); err != nil {
			e := newCompressingPipeWriterError("CompressAndEncrypt: compression failed", err)
			_ = dstWriter.CloseWithError(e)
			return
		}

		if compressedWriter != nil {
			if err := compressedWriter.Close(); err != nil {
				e := newCompressingPipeWriterError("CompressAndEncrypt: writer close failed", err)
				_ = dstWriter.CloseWithError(e)
				return
			}
		}
		if crypter != nil {
			if err := encryptedWriter.Close(); err != nil {
				e := newCompressingPipeWriterError("CompressAndEncrypt: encryption failed", err)
				_ = dstWriter.CloseWithError(e)
				return
			}
		}
		_ = dstWriter.Close()
	}()
	return compressedReader
}
