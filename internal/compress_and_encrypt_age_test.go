package internal_test

import (
	"io"
	"strings"
	"testing"
	"time"

	filippoage "filippo.io/age"
	"github.com/stretchr/testify/require"
	"github.com/wal-g/wal-g/internal"
	agecrypter "github.com/wal-g/wal-g/internal/crypto/age"
)

func TestCompressAndEncryptReturnsBeforeAgeOutputIsConsumed(t *testing.T) {
	identity, err := filippoage.GenerateX25519Identity()
	require.NoError(t, err)

	const payload = "wal-g age pipeline"
	result := make(chan io.Reader, 1)
	go func() {
		result <- internal.CompressAndEncrypt(
			strings.NewReader(payload),
			nil,
			agecrypter.CrypterFromRecipient(identity.Recipient().String()),
		)
	}()

	var encrypted io.Reader
	select {
	case encrypted = <-result:
	case <-time.After(time.Second):
		t.Fatal("CompressAndEncrypt deadlocked while age wrote its header to an unread pipe")
	}

	decrypted, err := filippoage.Decrypt(encrypted, identity)
	require.NoError(t, err)
	plaintext, err := io.ReadAll(decrypted)
	require.NoError(t, err)
	require.Equal(t, payload, string(plaintext))
}
