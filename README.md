# Simplus

A cross-platform (Windows-first) desktop toolbox written in Rust with a Slint UI, extensible through community plugins.

Official modules (in build order):

- **Password manager**: Argon2id + XChaCha20-Poly1305 vault, a second password for secure notes, TOTP, recovery kit, optional self-hostable zero-knowledge sync
- **S3 manager**: any S3-compatible provider, one-way sync local↔S3 and S3→S3, schedules
- **FTP/FTPS/SFTP manager**: site manager protected by a master password, diff-based sync, schedules
- **Folder → Markdown combiner**: local folders or GitHub repos into one LLM-friendly Markdown file

Status: early development; see [docs/ROADMAP.md](docs/ROADMAP.md) and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Building

Requires Rust 1.92+.

```sh
cargo test --workspace
cargo run -p simplus-app
```

On Linux, Slint needs the usual X11/Wayland development headers (`libxkbcommon-dev`, `libfontconfig-dev`).
