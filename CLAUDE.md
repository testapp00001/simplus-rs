# Simplus — notes for Claude Code sessions

Simplus is a Rust + Slint desktop toolbox (Windows first, also Linux/macOS) for the owner, friends and
colleagues. It is meant to be extensible by community plugins (like VS Code extensions / Windhawk mods)
and to ship official modules: **password manager** (done), **S3 manager**, **FTP/SFTP manager**,
**folder → single Markdown combiner** (for LLMs). The full design lives in `docs/ARCHITECTURE.md`; the
phase plan in `docs/ROADMAP.md`.

## Working rules (from the owner)

- The owner is on the **Pro plan**: do **not** spawn subagents; work inline and keep tool output small.
- Commit and push after each finished step; keep CI green (fmt, clippy `-D warnings`, tests on 3 OSes).
- No license chosen yet; don't add one without asking.
- Never put model names in commits, PRs or code.

## Decisions already made

- Plugins: native dynamic libraries behind a versioned C ABI (MessagePack payloads), UI as `.slint`
  files loaded with `slint-interpreter`; local install + GitHub-hosted registry; trust prompt, safe mode.
  `ComponentContainer` is experimental in Slint 1.18, so v1 plugin pages open in their own window.
- S3/FTP sync is one-way (copy or mirror), any source → any target; schedules run from the system tray.
- Separate **app** master password (S3/FTP/GitHub credentials) and **vault** passwords.
- Vault: MP1 unlocks records/passwords/TOTP, MP2 decrypts secure notes; recovery kit; auto-lock,
  generator, import/export; optional sync to a self-hostable zero-knowledge server (offline first).
- Sync server: SQLite only, sign-up `open|invite|closed` (default open), email = account id (unverified),
  no official default URL yet. Personal multi-device sync of the vault only (no sharing).
- Combiner: local folders + public/private GitHub repos (PAT), include/exclude filters.

## Crate map

| Path | What |
|---|---|
| `crates/simplus-crypto` | Argon2id `KdfParams`/`derive_key`, XChaCha20-Poly1305 `seal`/`open` (version byte in AAD), HKDF, `KeySlot` key wrapping |
| `crates/simplus-core` | `AppPaths` (portable marker `simplus.portable`), TOML `AppConfig`, `db::{open, migrate}`, logging, `JobManager`, `Scheduler` |
| `crates/simplus-vault-core` | `Vault` (create/open/unlock/unlock_notes/recover, records + notes CRUD, password changes), TOTP, generator, import/export, `sync.rs` (sync state + conflict rules) |
| `crates/simplus-vault-proto` | Serde DTOs shared by sync client and server |
| `crates/simplus-vault-sync` | Blocking `ureq` client + `create_account`/`sign_in`/`sync`/`recover_account`/devices; `VaultAccess` trait |
| `crates/simplus-app` | Slint UI binary `simplus` (`ui/*.slint`, `src/vault_ui.rs` controller, clipboard auto-clear, Windows session-lock) |
| `server/simplus-sync-server` | axum + rusqlite server + admin CLI (`serve`, `invite create`, `user list/disable/enable`, `stats`, `backup`, `config`), `Dockerfile` |
| `deploy/` | docker-compose + Caddy, example config, systemd unit |

Key hierarchy, sync protocol and conflict rules: `docs/SYNC_PROTOCOL.md`. Self-hosting: `docs/SELF_HOSTING.md`.

## Commands

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace                       # unit + server API + e2e sync tests
cargo run -p simplus-app                     # the desktop app (binary `simplus`)
cargo run -p simplus-sync-server -- --config deploy/simplus-sync.toml serve
```

Linux build deps: `libxkbcommon-dev libfontconfig-dev`; runtime in a headless container also needs
`libxkbcommon-x11-0`.

### Manual UI testing in the container (no display)

```sh
Xvfb :99 -screen 0 1280x800x24 & export DISPLAY=:99
./target/debug/simplus &   # a `simplus.portable` file next to the exe keeps data beside it
xdotool search --name Simplus windowfocus --sync type 'text'; xdotool key Return
import -window root shot.png                   # ImageMagick screenshot, then Read the png
```

## Gotchas

- `pkill -f simplus` matches the invoking shell and kills it (exit 144). Use `pkill -x simplus` or an
  anchored pattern like `pkill -f '^./target/debug/simplus-sync-server'`.
- Slint: wrapped `Text` inside conditional nested layouts is measured before wrapping → cards come out
  too short. Put such captions directly in the card's layout. Slint has no generic "monospace" family;
  `MONO_FONT` in `main.rs` picks one per OS. Define components before use; avoid property
  names like `row` that clash with built-ins.
- `xdotool type` needs `windowfocus` first or keystrokes are lost.
- Docker builds in this sandbox can't reach crates.io directly: use a throwaway Dockerfile that adds
  `/root/.ccr/ca-bundle.crt` and build with `--network host --build-arg HTTPS_PROXY=$HTTPS_PROXY`.
  Keep the repo `Dockerfile` clean.
- Types with `Drop` (e.g. `Record`, `Totp`) can't use struct-update syntax; construct then mutate.
- Workspace lints deny `unsafe_code`; only `simplus-app/src/session.rs` (Windows FFI) opts in locally.

## Status / next

- Done: phase 0 (foundations), phase 1 (local vault + UI), phase 2 (sync server, client, app UI,
  docs, Docker, CI).
- **Next: phase 3 — plugin system** (`simplus-plugin-abi`, `simplus-plugin-sdk` with `export_plugin!`,
  `simplus-plugin-host` loader/manifest/UI bridge, trust dialog, safe mode, dev mode, zip install,
  `sdk/examples/hello-plugin`, `docs/PLUGIN_GUIDE.md`). Then S3 → FTP → Combiner → distribution.
- Known v1 limits (documented): a malicious sync server can withhold/replay items; emails unverified;
  recovery needs a device or backup that holds the vault.
