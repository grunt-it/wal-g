// Package age implements a WAL-G Crypter backed by age (https://age-encryption.org),
// the modern, audited file-encryption tool by Filippo Valsorda.
//
// WHY THIS EXISTS (grunt-it fork — see README)
//
//	Upstream WAL-G ships PGP, libsodium and KMS crypters but NOT age
//	(feature request: https://github.com/wal-g/wal-g/issues/1983). grunt-it's
//	backup/DR design standardizes on ONE asymmetric key — age — across the whole
//	backup surface (control-plane tarballs + WAL segments + base backups), so the
//	host holds only the PUBLIC recipient and cannot decrypt what it uploads. age
//	is the natural primitive for that, and crucially supports MULTIPLE recipients,
//	which lets an unattended restore-drill decrypt with its own scoped identity
//	without ever exposing the human-escrow key.
//
// MODEL
//
//	Encrypt (upload): recipients come from WALG_AGE_RECIPIENT_FILE (one age1… per
//	  line — MULTI-RECIPIENT) or WALG_AGE_RECIPIENT (inline, newline-separated).
//	  Every recipient can later decrypt independently.
//	Decrypt (download): the identity comes from WALG_AGE_IDENTITY_FILE (an
//	  AGE-SECRET-KEY-1… / SSH key) or WALG_AGE_IDENTITY (inline). Only ONE identity
//	  is needed — any of the encryption recipients works.
//
// This crypter is PURE Go (no cgo) and is always compiled in, unlike the
// libsodium crypter which is cgo + build-tag gated.
package age

import (
	"fmt"
	"io"
	"os"
	"strings"

	"filippo.io/age"
	"github.com/pkg/errors"
	"github.com/wal-g/wal-g/internal/crypto"
)

// Crypter is the age implementation of crypto.Crypter.
//
// It is constructed lazily: recipients are only parsed on Encrypt, identities
// only on Decrypt, so an upload-only configuration never needs a private key and
// a download-only configuration never needs recipients.
type Crypter struct {
	// Encryption inputs (at least one required for Encrypt).
	RecipientInline string // newline-separated age1… recipients
	RecipientPath   string // file containing one age1… recipient per line

	// Decryption inputs (at least one required for Decrypt).
	IdentityInline string // an age secret key / SSH identity
	IdentityPath   string // file containing the identity
}

// CrypterFromRecipient builds an encrypt-capable Crypter from inline recipients.
func CrypterFromRecipient(recipients string) crypto.Crypter {
	return &Crypter{RecipientInline: recipients}
}

// CrypterFromRecipientPath builds an encrypt-capable Crypter from a recipient file.
func CrypterFromRecipientPath(path string) crypto.Crypter {
	return &Crypter{RecipientPath: path}
}

// CrypterFromIdentity builds a decrypt-capable Crypter from an inline identity.
func CrypterFromIdentity(identity string) crypto.Crypter {
	return &Crypter{IdentityInline: identity}
}

// CrypterFromIdentityPath builds a decrypt-capable Crypter from an identity file.
func CrypterFromIdentityPath(path string) crypto.Crypter {
	return &Crypter{IdentityPath: path}
}

// CrypterFromConfig builds a Crypter that may be capable of both directions,
// depending on which of the four inputs are populated.
func CrypterFromConfig(recipientInline, recipientPath, identityInline, identityPath string) crypto.Crypter {
	return &Crypter{
		RecipientInline: recipientInline,
		RecipientPath:   recipientPath,
		IdentityInline:  identityInline,
		IdentityPath:    identityPath,
	}
}

func (crypter *Crypter) Name() string {
	return "age"
}

// Encrypt wraps writer so everything written to the returned WriteCloser is
// age-encrypted to ALL configured recipients. The caller MUST Close the returned
// writer to flush age's footer — an unclosed writer yields a truncated,
// undecryptable stream.
func (crypter *Crypter) Encrypt(writer io.Writer) (io.WriteCloser, error) {
	recipients, err := crypter.recipients()
	if err != nil {
		return nil, err
	}
	if len(recipients) == 0 {
		return nil, errors.New("age Crypter: no recipients configured (set WALG_AGE_RECIPIENT_FILE or WALG_AGE_RECIPIENT)")
	}

	w, err := age.Encrypt(writer, recipients...)
	if err != nil {
		return nil, errors.Wrap(err, "age Crypter: failed to create encryption writer")
	}
	return w, nil
}

// Decrypt wraps reader so the returned reader yields the age-decrypted plaintext.
// Any single configured identity that matches one of the stream's recipients works.
func (crypter *Crypter) Decrypt(reader io.Reader) (io.Reader, error) {
	identities, err := crypter.identities()
	if err != nil {
		return nil, err
	}
	if len(identities) == 0 {
		return nil, errors.New("age Crypter: no identity configured (set WALG_AGE_IDENTITY_FILE or WALG_AGE_IDENTITY)")
	}

	r, err := age.Decrypt(reader, identities...)
	if err != nil {
		return nil, errors.Wrap(err, "age Crypter: failed to create decryption reader")
	}
	return r, nil
}

// recipients parses every configured recipient. Inline and file sources are both
// honored (inline first, then file) so a deployment can layer them; each non-empty,
// non-comment line is parsed as an age recipient (X25519 or SSH).
func (crypter *Crypter) recipients() ([]age.Recipient, error) {
	var raw strings.Builder
	if crypter.RecipientInline != "" {
		raw.WriteString(crypter.RecipientInline)
		raw.WriteString("\n")
	}
	if crypter.RecipientPath != "" {
		contents, err := os.ReadFile(crypter.RecipientPath)
		if err != nil {
			return nil, fmt.Errorf("age Crypter: unable to read recipient file %q: %w", crypter.RecipientPath, err)
		}
		raw.Write(contents)
	}

	var recipients []age.Recipient
	for _, line := range strings.Split(raw.String(), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// age.ParseRecipients handles both native age (age1…) and SSH recipients,
		// and is lenient about a multi-line reader; we parse line-by-line so a single
		// malformed entry is reported with its content rather than aborting opaquely.
		parsed, err := age.ParseRecipients(strings.NewReader(line))
		if err != nil {
			return nil, fmt.Errorf("age Crypter: invalid recipient %q: %w", line, err)
		}
		recipients = append(recipients, parsed...)
	}
	return recipients, nil
}

// identities parses the configured identity (inline preferred, then file).
func (crypter *Crypter) identities() ([]age.Identity, error) {
	var raw string
	switch {
	case crypter.IdentityInline != "":
		raw = crypter.IdentityInline
	case crypter.IdentityPath != "":
		contents, err := os.ReadFile(crypter.IdentityPath)
		if err != nil {
			return nil, fmt.Errorf("age Crypter: unable to read identity file %q: %w", crypter.IdentityPath, err)
		}
		raw = string(contents)
	default:
		return nil, nil
	}

	identities, err := age.ParseIdentities(strings.NewReader(raw))
	if err != nil {
		return nil, errors.Wrap(err, "age Crypter: failed to parse identity")
	}
	return identities, nil
}
