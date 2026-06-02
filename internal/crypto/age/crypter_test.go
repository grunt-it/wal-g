package age

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// genKey returns a fresh (identity, recipient) age X25519 keypair for tests.
// Keys are ephemeral — NEVER commit a real key to this PUBLIC repo.
func genKey(t *testing.T) (identity string, recipient string) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	return id.String(), id.Recipient().String()
}

func encryptTo(t *testing.T, c *Crypter, plaintext []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := c.Encrypt(&buf)
	require.NoError(t, err)
	_, err = w.Write(plaintext)
	require.NoError(t, err)
	// age writes its footer on Close — without this the stream is truncated.
	require.NoError(t, w.Close())
	return buf.Bytes()
}

func decryptWith(t *testing.T, c *Crypter, ciphertext []byte) ([]byte, error) {
	t.Helper()
	r, err := c.Decrypt(bytes.NewReader(ciphertext))
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

func TestName(t *testing.T) {
	assert.Equal(t, "age", (&Crypter{}).Name())
}

func TestRoundTripSingleRecipient(t *testing.T) {
	id, rcpt := genKey(t)
	plaintext := []byte("the quick brown fox jumps over the lazy dog")

	ct := encryptTo(t, CrypterFromRecipient(rcpt).(*Crypter), plaintext)
	assert.NotEqual(t, plaintext, ct, "ciphertext must differ from plaintext")

	got, err := decryptWith(t, CrypterFromIdentity(id).(*Crypter), ct)
	require.NoError(t, err)
	assert.Equal(t, plaintext, got)
}

// TestMultiRecipientEitherIdentityDecrypts is THE guarantee the grunt-it fork
// exists for: a blob encrypted to TWO recipients (e.g. the human-escrow key AND a
// drill-scoped key) must decrypt with EITHER identity independently. This is what
// lets an unattended restore-drill decrypt without the human-escrow key.
func TestMultiRecipientEitherIdentityDecrypts(t *testing.T) {
	humanID, humanRcpt := genKey(t)
	drillID, drillRcpt := genKey(t)
	plaintext := []byte("base backup bytes that must be drill-decryptable")

	// Encrypt to both recipients via a multi-line recipient string.
	enc := CrypterFromRecipient(humanRcpt + "\n" + drillRcpt).(*Crypter)
	ct := encryptTo(t, enc, plaintext)

	// Human identity decrypts.
	gotHuman, err := decryptWith(t, CrypterFromIdentity(humanID).(*Crypter), ct)
	require.NoError(t, err)
	assert.Equal(t, plaintext, gotHuman)

	// Drill identity decrypts the SAME blob, independently.
	gotDrill, err := decryptWith(t, CrypterFromIdentity(drillID).(*Crypter), ct)
	require.NoError(t, err)
	assert.Equal(t, plaintext, gotDrill)
}

// TestRecipientFileMultiLine verifies the file path used in production
// (/etc/walg/age-recipient.pub, one age1… per line) parses every recipient and
// skips blank/comment lines.
func TestRecipientFileMultiLine(t *testing.T) {
	humanID, humanRcpt := genKey(t)
	drillID, drillRcpt := genKey(t)

	dir := t.TempDir()
	recipientFile := dir + "/age-recipient.pub"
	contents := "# grunt-it tier0 recipients\n" + humanRcpt + "\n\n" + drillRcpt + "\n"
	require.NoError(t, os.WriteFile(recipientFile, []byte(contents), 0o644))

	plaintext := []byte("multi-line recipient file round trip")
	ct := encryptTo(t, CrypterFromRecipientPath(recipientFile).(*Crypter), plaintext)

	for name, id := range map[string]string{"human": humanID, "drill": drillID} {
		got, err := decryptWith(t, CrypterFromIdentity(id).(*Crypter), ct)
		require.NoError(t, err, "identity %s should decrypt", name)
		assert.Equal(t, plaintext, got, "identity %s plaintext mismatch", name)
	}
}

func TestEncryptNoRecipientsErrors(t *testing.T) {
	_, err := (&Crypter{}).Encrypt(io.Discard)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no recipients")
}

func TestDecryptNoIdentityErrors(t *testing.T) {
	_, err := (&Crypter{}).Decrypt(strings.NewReader("whatever"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no identity")
}

func TestInvalidRecipientErrors(t *testing.T) {
	_, err := CrypterFromRecipient("not-a-valid-age-recipient").(*Crypter).Encrypt(io.Discard)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid recipient")
}

func TestWrongIdentityFailsToDecrypt(t *testing.T) {
	_, rcpt := genKey(t)
	wrongID, _ := genKey(t)
	ct := encryptTo(t, CrypterFromRecipient(rcpt).(*Crypter), []byte("secret"))

	_, err := decryptWith(t, CrypterFromIdentity(wrongID).(*Crypter), ct)
	require.Error(t, err, "an unrelated identity must NOT decrypt")
}
