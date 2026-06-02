# WAL-G — grunt-it fork (adds native `age` encryption)

> This is a fork of [`wal-g/wal-g`](https://github.com/wal-g/wal-g) maintained by
> [grunt-it](https://github.com/grunt-it). **The only addition is a native
> [`age`](https://age-encryption.org) crypter.** Everything else tracks upstream.
> See the upstream docs at <https://wal-g.readthedocs.io> for all other usage.

## Why this fork exists

Upstream WAL-G can encrypt backups with PGP, libsodium, or a cloud KMS — but **not
with `age`** (it's an open feature request: [wal-g#1983](https://github.com/wal-g/wal-g/issues/1983)).

grunt-it's backup/DR architecture standardises on **one asymmetric key — `age` — for
the entire backup surface** (control-plane tarballs, WAL segments, and Postgres base
backups). `age` is the right primitive for us because:

- **The host can't decrypt what it uploads.** A database host holds only the *public*
  recipient. A compromised host or leaked bucket credential exposes only ciphertext —
  the private identity is escrowed in a human-only vault and never touches a server.
  (libsodium is symmetric → the host *could* decrypt; PGP would be a *second* key model
  to mint/rotate/escrow alongside the `age` key we already use elsewhere.)
- **Multiple recipients, natively.** A backup can be encrypted to several recipients at
  once, and **any single identity decrypts it independently**. We use this so an
  unattended restore-*drill* can decrypt with its own scoped key — proving backups are
  restorable on a schedule — **without ever exposing the human-escrow key**.

Rather than bolt `age` on with a brittle `age -r … | wal-g wal-push -` shell pipe
(which only covers the WAL stream, not base backups, and is awkward to make
multi-recipient), we added `age` as a first-class WAL-G `Crypter` so it covers
**WAL and base backups uniformly**.

## What's added here

- **`internal/crypto/age/`** — an `age` implementation of WAL-G's `crypto.Crypter`
  (`Encrypt`/`Decrypt` over `io.Writer`/`io.Reader`, backed by
  [`filippo.io/age`](https://pkg.go.dev/filippo.io/age)). Pure Go, no cgo, always
  compiled in (unlike the libsodium crypter, which is cgo + build-tag gated).
- **Wiring** in `internal/configure.go` (`ConfigureCrypterForSpecificConfig`) and four
  new settings in `internal/config/config.go`.

### Configuration

| Setting | Direction | Notes |
| --- | --- | --- |
| `WALG_AGE_RECIPIENT_FILE` | encrypt (upload) | Path to a file with **one `age` recipient per line** (multi-recipient). |
| `WALG_AGE_RECIPIENT` | encrypt (upload) | Inline recipient(s), newline-separated. |
| `WALG_AGE_IDENTITY_FILE` | decrypt (download) | Path to an `age` identity (`AGE-SECRET-KEY-1…` or SSH key). |
| `WALG_AGE_IDENTITY` | decrypt (download) | Inline identity. |

An upload-only host sets only a recipient; a restore sets only an identity. Recipients
and identities are independent — any one of the encryption recipients can decrypt.

```bash
# Upload, encrypting to two recipients (e.g. human-escrow + a drill key):
printf '%s\n%s\n' "$HUMAN_RECIPIENT" "$DRILL_RECIPIENT" > /etc/walg/age-recipient.pub
export WALG_AGE_RECIPIENT_FILE=/etc/walg/age-recipient.pub
wal-g backup-push "$PGDATA"

# Restore, decrypting with either identity:
export WALG_AGE_IDENTITY_FILE=/etc/walg/age-identity.txt
wal-g backup-fetch /restore/path LATEST
```

## Security notes

- The age **recipient** (public key) is safe to ship to any host. The **identity**
  (private key) is secret — keep it out of hosts/repos; `WALG_AGE_IDENTITY` is
  redacted in logs.
- **No keys live in this repository.** Tests generate ephemeral keys at runtime.

## Relationship to upstream

- Tracks `wal-g/wal-g` (forked at `v3.0.8`). The age crypter is offered upstream as a
  PR against [wal-g#1983](https://github.com/wal-g/wal-g/issues/1983); if it merges,
  this fork can be retired.
- Apache-2.0, same as upstream (see `LICENSE.md`). Not affiliated with or endorsed by
  the WAL-G maintainers.

## Building

Same as upstream — the `age` crypter needs no extra system libraries:

```bash
make deps
make pg_build   # produces main/pg/wal-g
```

Tagged releases (`v*`) build `wal-g-pg` for Ubuntu 20.04/22.04/24.04 × amd64/aarch64
and publish SHA256-checksummed binaries (see `.github/workflows/release.yml`).
