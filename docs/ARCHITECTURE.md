# Simplus architecture

Simplus is a cross-platform (Windows-first) desktop toolbox written in Rust with a [Slint](https://slint.dev) UI. It ships official modules (password manager, S3 manager, FTP/SFTP manager, folder→Markdown combiner) and can be extended by community plugins, much like VS Code extensions or Windhawk mods.

See [ROADMAP.md](ROADMAP.md) for build order and status.

## Key decisions

| Topic | Decision |
|---|---|
| Plugin runtime | Native dynamic libraries (`.dll/.so/.dylib`) behind a small versioned C ABI; no sandbox |
| Plugin UI | Plugins ship `.slint` files loaded at runtime with `slint-interpreter` |
| S3/FTP sync | One-way only (copy or mirror): local→remote, remote→local, remote→remote |
| Scheduling | Runs from the system tray; optional start with the OS |
| Passwords | Separate **App master password** (S3/FTP/GitHub credentials) and **Vault master password**; a second vault password protects secure notes |
| Plugin distribution | Local install (.zip/folder) plus a GitHub-hosted registry with trust warnings and SHA-256 checks |
| Vault sync | Optional, offline-first, end-to-end encrypted; open-source self-hostable server with an official default instance; personal multi-device only (no sharing in v1) |
| Vault recovery | Random recovery key generated at vault creation (printable recovery kit) |

## 1. Repository layout (Cargo workspace)

```
simplus-rs/
  Cargo.toml                    # [workspace], shared deps/lints, MSRV
  crates/
    simplus-app/                # bin: Slint shell, tray, navigation, settings, wires modules + plugin host
    simplus-core/               # paths, config, SQLite, logging, job manager, scheduler, notifications, event bus
    simplus-crypto/             # Argon2id, XChaCha20-Poly1305, HKDF, key wrapping, zeroize helpers
    simplus-secrets/            # App credential store (App master password; optional OS-keychain "remember")
    simplus-sync-engine/        # generic one-way sync over a RemoteFs trait (local, S3, FTP, SFTP)
    simplus-plugin-abi/         # #[repr(C)] versioned C ABI types (tiny, stable, no deps)
    simplus-plugin-sdk/         # safe Rust SDK for plugin authors: export_plugin! macro, host API wrappers
    simplus-plugin-host/        # loader, manifest, trust/safe-mode, Slint interpreter bridge, registry client
    simplus-ui-kit/             # shared .slint theme/widgets (compiled in + exposed to plugins as a library)
    modules/
      mod-s3/  mod-ftp/  mod-combiner/  mod-vault/     # official modules (logic + .slint UI)
    simplus-vault-core/         # vault model, crypto envelope, local store, import/export (UI-free, testable)
    simplus-vault-proto/        # sync API DTOs shared by client + server
  server/simplus-sync-server/   # axum + sqlx server, Dockerfile, docker-compose example
  sdk/plugin-template/          # cargo-generate template;  sdk/examples/hello-plugin/
  docs/                         # ARCHITECTURE.md, PLUGIN_GUIDE.md, SECURITY.md, SELF_HOSTING.md
  .github/workflows/            # CI matrix (windows/linux/macos), release packaging
```

Official modules are statically compiled into the app. They are written against the **same Rust `ModuleContext` API** that the plugin host exposes to DLLs through the C ABI, so community plugins get the same services (secrets, jobs, scheduler, notifications, settings, dialogs) as official ones.

## 2. Core app (`simplus-app`, `simplus-core`)

- **UI**: Slint, `fluent` style (native look on Windows 11), light/dark theme follows the system, `@tr()` strings from day 1 so the app can be translated later. The layout is a left sidebar (official modules + installed plugins), a content area, a bottom **Tasks/Transfers** panel, toasts, and Settings.
- **Threading**: Slint runs on the main thread and a tokio multi-thread runtime does the background work. Results go back to the UI with `slint::invoke_from_event_loop`, and long work never runs on the UI thread.
- **Tray**: `tray-icon` + `muda` menu. Events are polled with a `slint::Timer`. Close-to-tray is done with `on_close_requested → HideWindow` + `slint::run_event_loop_until_quit()`. Autostart uses the `auto-launch` crate (Run registry key on Windows). `single-instance` is used so a second launch focuses the existing window.
- **Storage**: `directories` crate paths (`%APPDATA%\Simplus` for config, `%LOCALAPPDATA%\Simplus` for data/logs/plugins). TOML config via serde. `rusqlite` (bundled) holds profiles, jobs, schedules, run history and sync state.
- **Job manager**: tasks with progress, cancel (`CancellationToken`), retry, history, and OS notifications (`notify-rust`, which uses WinRT toasts on Windows).
- **Scheduler**: cron + interval schedules (`croner`) stored in SQLite, with a missed-run policy (run once on startup if a run was missed). Jobs run only while the App credential store is unlocked.
- **Logging**: `tracing` + rolling file appender, plus an in-app log viewer.

## 3. Crypto & App credential store (`simplus-crypto`, `simplus-secrets`)

- Primitives (RustCrypto): `argon2` (Argon2id), `chacha20poly1305` (XChaCha20-Poly1305, random 24-byte nonce), `hkdf` (SHA-256), `zeroize`/`secrecy`, `rand::rngs::OsRng`.
- Argon2id params are calibrated to about 0.5–1 s on the device, with a floor of m=64 MiB, t=3, p=4, and are stored in each file header so they can be upgraded later.
- Envelope pattern: password → Argon2id → KEK, which **wraps** a random data key (DEK). Changing a password only re-wraps the DEK. Each item is sealed with AAD = `item_id ‖ version ‖ type` so ciphertexts can't be swapped.
- **App credential store**: holds S3 keys, FTP passwords and SSH key passphrases, the GitHub PAT, and plugin-namespaced secrets. It is unlocked with the **App master password** and stays unlocked while the app sits in the tray, so schedules keep running.
  - An optional setting, **"Remember on this device"** (off by default), stores the DEK in the Windows Credential Manager/DPAPI (`keyring` crate) so scheduled syncs can run after a reboot without the password being typed.

## 4. Plugin system (native DLL + runtime .slint)

**ABI**: the plugin boundary is a small, versioned **C ABI** (`simplus-plugin-abi`) with **serialized messages** (MessagePack via `rmp-serde`). This is preferred over `abi_stable`/raw Rust traits because it is resilient to Rust compiler version differences and lets C/C++/Zig/Go authors write plugins too. Rust authors never see it: `simplus-plugin-sdk` provides `export_plugin!(MyPlugin)` and typed host wrappers.

```c
// exported by plugin
const SimplusPluginV1* simplus_plugin_v1(void);
struct SimplusPluginV1 { u32 abi_version;
  i32  (*init)(const SimplusHostV1*, void** state);
  void (*shutdown)(void* state);
  Buf  (*handle)(void* state, Str method, Buf payload);   // UI callbacks, commands, scheduled jobs
  void (*free_buf)(Buf); };
struct SimplusHostV1 { u32 abi_version; Buf (*call)(HostCtx*, Str method, Buf payload); void (*free_buf)(Buf); ... };
```

- **Host API methods** (plain Rust traits for official modules): `ui.set/get/invoke`, `notify`, `settings.*`, `secrets.*` (namespaced per plugin), `jobs.start/progress/finish`, `scheduler.register`, `dialog.pick_file/folder`, `clipboard.*`, `events.subscribe`, `log`.
- **Safety at the boundary**: the SDK wraps every entry in `catch_unwind`. Plugin calls run on worker threads, never the UI thread. A crash sentinel file records "inside plugin X". If the previous session crashed there, the app offers **Safe Mode**, which starts with community plugins disabled, similar to Windhawk.
- **Loading**: `libloading`. Load/unload requires a restart, because unloading DLLs is unsafe once threads or TLS exist. **Developer mode** loads a plugin from an unpacked folder.
- **Manifest `plugin.toml`**: id, name, version, authors, license, `min_host_abi`, per-target entry (`windows-x86_64 = "x.dll"`, …), UI pages (`slint` file + root component + icon), declared capabilities (network, filesystem, secrets, clipboard, startup), and a settings schema that the host turns into a settings page automatically.
- **Package**: a `.simplus-plugin` file (a zip containing the manifest, per-platform binaries, `ui/` and assets).
- **UI bridge**: the host compiles the plugin's `.slint` with `slint_interpreter::Compiler`, using `simplus-ui-kit` as an importable library so plugins match the app theme. The page is embedded in the shell through `ComponentContainer` + `ComponentFactory` (`ComponentDefinition::create_embedded`). The host enumerates the component's callbacks/properties and forwards callbacks to the plugin's `handle("ui.callback", …)`. The plugin pushes state back with `ui.set` (JSON ↔ `slint_interpreter::Value`, arrays → `VecModel`). In v1, callbacks are fire-and-forget events.
- **Trust**: a trust dialog lists the declared capabilities and clearly states that native plugins run with full access. SHA-256 is verified on install, and each plugin can be enabled or disabled.
- **Registry (later phase)**: a GitHub repo `simplus-plugins` with `index.json` signed with minisign (`minisign-verify`). Entries point to a source repo and commit, the registry's CI builds the per-platform binaries from source, and it publishes the hashes. An in-app browser installs and updates plugins from it.

## 5. Sync engine (shared by S3 & FTP)

- `trait RemoteFs`: `list(prefix, recursive)` stream, `stat`, `read` (AsyncRead), `write`, `delete`, `mkdir`, `rename`. Implementations: LocalFs, S3Fs, FtpFs, SftpFs, so **any source to any target** works (S3→S3, FTP→S3, …).
- **Modes**: `Copy` (add/update only) and `Mirror` (also deletes extras on the target). Mirror has a safety threshold (abort if more than N% or N files would be deleted) and an optional move-to-trash.
- **Diff**: compares by size+mtime, size only, or checksum (SHA-256 local, ETag/MD5 for S3 single-part objects). A per-job **sync-state table** remembers what was transferred last time, which handles unreliable remote mtimes on FTP/S3. This is what makes "sync only changed files" reliable.
- **Filters**: include/exclude globs (`globset`), optional `.gitignore`, size limits, hidden files.
- **Flow**: **Plan → dry-run preview** (uploads/updates/deletes/bytes) → execute with a concurrency limit, retry/backoff, progress and cancel. Run history and a notification follow. Schedules are attached per job.

## 6. S3 module (`mod-s3`)

- `aws-sdk-s3` with a custom endpoint, `force_path_style`, and region. `request_checksum_calculation`/`response_checksum_validation = WhenRequired` is set for compatibility with R2/MinIO/B2/Wasabi.
- Profiles come with provider presets (AWS, Cloudflare R2, MinIO, Backblaze B2, Wasabi, DO Spaces, Hetzner, custom). Secrets are kept in the App credential store.
- The browser covers buckets, prefix navigation with breadcrumb, a virtualized list with continuation-token paging, multi-select, upload files/folders (`rfd` dialogs, plus OS drag-drop if the Slint version supports it), download, delete, create folder, rename (copy+delete), metadata view, **presigned share link** with expiry, and multipart upload for large files.
- Sync jobs: local→S3, S3→local, S3→S3 (server-side `CopyObject` when both are on the same endpoint and credentials, otherwise streamed).

## 7. FTP module (`mod-ftp`)

- FTP/FTPS: `suppaftp` (async, rustls), using MLSD for accurate listings, with a LIST fallback and MDTM/MFMT. SFTP: `russh` + `russh-sftp` (pure Rust), with password or private-key auth and **known-hosts TOFU** (the fingerprint prompt appears on first connect).
- Site manager: passwords and key passphrases are encrypted in the App credential store. Import from FileZilla `sitemanager.xml` is a nice-to-have.
- Two-pane UI (local | remote), transfer queue, rename/delete/mkdir/chmod (SFTP), and sync jobs + schedules through the sync engine.

## 8. Markdown combiner (`mod-combiner`)

- **Sources**: local files/folders, and GitHub repos (public, or private via PAT) at any branch/tag/commit and subpath. The repo is fetched as **one tarball request** (`/repos/{o}/{r}/tarball/{ref}`, `flate2` + `tar`) to avoid rate limits.
- **Filters**: include/exclude globs, `.gitignore` support (`ignore` crate), default excludes (`.git`, `node_modules`, `target`, lockfiles), max file size, and binary detection (`content_inspector`). A file-tree checklist lets the user tick/untick individual files.
- **Output**: a header with source info, a directory tree, then one `## path` section per file with a fenced block that has the language tag and a fence length adapted if the file itself contains ```` ``` ````. It shows a **token estimate** per file and in total (`tiktoken-rs`), can split the output into N-token chunks, and supports copy to clipboard or save. Presets are saved.
- Optional headless CLI: `simplus combine <src> --include … --out file.md`.

## 9. Password manager (`simplus-vault-core`, `mod-vault`)

**Key hierarchy**
- Vault master password **MP1** → Argon2id → MK1 → HKDF → `KEK1` (wraps **Vault Key VK**) and `AuthKey` (server login only).
- Second password **MP2** → Argon2id → `KEK2` (wraps **Notes Key NK**).
- **Recovery key**: 256-bit random, shown as grouped base32 in a printable "Emergency Kit". It wraps VK and NK separately, so it can reset either password.
- Records are sealed with VK, and each secure note is sealed individually with NK. Unlocking with MP1 allows listing records, view/copy passwords, and see TOTP codes. Opening a secure note requires MP2, and NK re-locks sooner than VK.

**Record model**: id (UUIDv7), title, username, password (+ history), URLs, tags/folder, favorite, custom fields, **TOTP** (otpauth URI, `totp-rs`, countdown ring, and QR import from an image via `rqrr`), and `notes: Vec<SecureNote>`. Timestamps and a revision number are kept for sync.

**Storage**: a local SQLite `vault.db` with one encrypted row per record or note, plus a header table (KDF params, wrapped keys). Row-level encryption keeps sync per record.

**Features**
- Auto-lock on idle, Windows session lock (`WTSRegisterSessionNotification`), or sleep.
- Clipboard copy auto-clears after N seconds, only if the clipboard still holds the copied value, and is excluded from Win+V history/cloud clipboard (`arboard` Windows extension).
- Generator: random passwords and EFF-wordlist passphrases, with a `zxcvbn` strength meter.
- **Import**: Bitwarden JSON, KeePass `.kdbx` (`keepass` crate) / KeePassXC CSV, Chrome/Edge/Firefox CSV, and generic CSV with column mapping. **Export**: an encrypted `.simplusvault` backup; plain CSV only after an explicit warning.
- Memory hygiene: `secrecy`/`zeroize`, and passwords are masked in the UI until revealed.

## 10. Sync server (`simplus-sync-server`) + vault sync client

> Implemented. The authoritative description is [SYNC_PROTOCOL.md](SYNC_PROTOCOL.md); the notes below are the original design.

- **Offline-first**: the local vault is the source of truth and sync is opt-in. In Settings the user picks the server URL (the official server by default, or a self-hosted one) and an account.
- **Zero-knowledge**: the server stores only the account id, an auth verifier, KDF params/salts, the wrapped VK/NK (including the recovery-wrapped copies) and encrypted record blobs. It never sees MP1, MP2, VK or NK.
- **Auth**: the client sends `AuthKey` (derived from MK1 via HKDF, separate from the encryption keys). The server stores Argon2id(AuthKey) and issues short-lived access tokens and per-device refresh tokens. The prelogin endpoint returns KDF params, including fake deterministic params for unknown users so accounts can't be enumerated. The device list supports revocation. A password change re-wraps VK and revokes the other devices' sessions.
- **Protocol** (`/v1`, OpenAPI via `utoipa`): a per-account monotonic `seq`. The client pulls with `GET /v1/vault/changes?since=seq` and pushes with `POST /v1/vault/items` (with `base_revision` for optimistic concurrency). Deletes are tombstones.
  - Conflicts are resolved on the client, since only it has the plaintext: the newest version wins, the losing version is kept in the record's history, and a conflict notice is shown.
  - An offline `pending_changes` queue syncs on unlock, after an edit (debounced), periodically, and on reconnect.
- **Stack**: axum, tokio, sqlx (**SQLite by default** for easy self-hosting, Postgres optional), rate limiting (`tower_governor`), and TOML/env config.
  - Registration modes: open, invite-only, or disabled. Admin CLI: invites, disable user, stats.
  - Distributed as a single binary plus a Docker image, with `docker-compose` + Caddy TLS examples. `SELF_HOSTING.md` documents the setup.
- Suggested licenses (not yet decided): app + SDK MIT/Apache-2.0 so plugin authors aren't restricted; server AGPL-3.0.

## 11. Key risks

- **Native plugins and the vault share one process**: a malicious plugin could read decrypted memory. This is mitigated, not solved, by trust prompts, registry builds from source, safe mode, keeping vault plaintext short-lived and zeroized, and clear documentation in `SECURITY.md`.
- **Slint `ComponentContainer` may still be experimental** in the Slint version we pin. Confirmed during Phase 0: in Slint 1.18 `ComponentContainer` still requires `SLINT_ENABLE_EXPERIMENTAL_FEATURES` and the interpreter's semver-exempt `internal` feature. v1 therefore opens plugin pages in their own interpreter-created window and will switch to embedding once Slint stabilises it.
- **Slint strings aren't zeroizable**, so revealed secrets are kept in the UI only while they're shown.
