# Roadmap

Order revised to put the password manager first.

| Phase | Deliverable | Status |
|---|---|---|
| **0 Foundations** | Cargo workspace, `simplus-crypto` (Argon2id, XChaCha20-Poly1305, HKDF, key slots), `simplus-core` (paths, config, SQLite migrations, logging, jobs, scheduler), minimal Slint shell, CI | crypto ✅ core ✅ shell/CI in progress |
| **1 Vault (local)** | `simplus-vault-core` + vault UI: two master passwords, secure notes, recovery kit, TOTP, generator, auto-lock, clipboard clear, import/export | in progress |
| **2 Vault sync server** | `simplus-sync-server` (axum + sqlx, SQLite default/Postgres optional), zero-knowledge auth, change feed, client sync, device management, Docker + self-hosting guide | planned |
| **3 Plugin system** | C ABI, Rust SDK + `export_plugin!`, manifest, loader, `.slint` UI bridge, trust dialog, safe mode, developer mode, zip install, example plugin + template, plugin guide | planned |
| **4 S3** | `simplus-secrets` credential store, tray/close-to-tray/autostart, sync engine, S3 browser, profiles, transfers, scheduled sync jobs | planned |
| **5 FTP/SFTP** | FTP/FTPS/SFTP backends, site manager, two-pane browser, sync + schedules | planned |
| **6 Combiner** | Local + GitHub sources, filters, file-tree picker, token counts, split output, presets | planned |
| **7 Distribution** | Plugin registry + in-app browser, installer (MSI/Velopack + portable zip), auto-update, code signing | planned |

## Verification policy

- Every change: `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` on Windows, Linux and macOS (GitHub Actions).
- Crypto and vault: published test vectors (Argon2id cross-implementation, draft-XChaCha20-Poly1305, RFC 5869, RFC 6238), wrong-password/tamper/swap tests, password change and recovery flows.
- Sync engine: in-memory backend unit tests plus MinIO / pure-ftpd / atmoz-sftp containers in CI.
- Server: axum integration tests with in-memory SQLite and simulated multi-device conflicts.
- Manual Windows checks: tray, autostart, auto-lock on Win+L, clipboard clear and Win+V exclusion, plugin install and safe mode.
