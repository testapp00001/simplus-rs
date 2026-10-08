# Vault sync protocol (v1)

Simplus sync is **optional, offline-first and zero-knowledge**. The local vault is always the source of truth. The server only relays encrypted items and wrapped keys between devices of the same account, and never sees a password or a decryption key.

## Keys and credentials

```
master password ── Argon2id(salt, params) ──► MK ──┬─ HKDF "simplus/slot-kek/v1" ──► KEK ─ wraps ─► vault key (VK)
                                                    └─ HKDF "simplus/vault/auth/v1" ─► AuthKey ──► server login
notes password  ── Argon2id ──► … ──► KEK ─ wraps ─► notes key (NK)
recovery key (random 256 bit) ──► wraps VK and NK (two more slots)
VK ── HKDF "simplus/vault/key-proof/v1" ──► KeyProof ──► authorises a recovery reset on the server
```

- **Items.** Every record and secure note is sealed on its own with XChaCha20-Poly1305 under VK or NK. Its associated data binds the item id, its kind and its parent record, so ciphertexts cannot be swapped between items.
- **Key bundle.** The four wrapped key slots plus the vault id. The server stores the bundle and returns it only after login, with a `keys_version` that increases on every change.
- **Server-side verifiers.** The server keeps only `Argon2id(AuthKey)` and `Argon2id(KeyProof)` (19 MiB, t=2, random salt). Both inputs are 256-bit keys derived on the client with the full master-password cost.
- **Key fingerprints.** Each device stores `HKDF(VK, "simplus/vault/key-check/v1")` (and the same for NK) and checks it on every unlock. If a bundle received from a server wraps a *different* key, it is rejected and the previous slots are restored. A malicious server therefore cannot plant a key it knows.

## Sign-in flow

1. `POST /v1/prelogin {email}` → `{kdf}` (Argon2id parameters and salt). Unknown emails get stable fake parameters derived from a server secret, so accounts cannot be enumerated.
2. The client derives `AuthKey` from the master password and that KDF info.
3. `POST /v1/sessions {email, auth_key, device}` → `{token, keys, keys_version, kdf}`. Unknown accounts are checked against a dummy verifier so that timing reveals nothing. After 10 failures (configurable) the account is locked for 15 minutes.
4. A new device builds its local vault from `keys` (it fails early if the password does not open the master slot) and then pulls every item.

`Authorization: Bearer <token>` authenticates every later call. Each device has one session token, which the server stores only as a SHA-256 hash and expires after 90 days of inactivity. On the device, the token is sealed under VK.

## Items

| Call | Purpose |
|---|---|
| `GET /v1/items?since=SEQ&limit=N` | Changes after `SEQ`, in sequence order, with `has_more`, `latest_seq` and the current `keys_version` |
| `POST /v1/items {items: [PushItem]}` | Conditional writes. Each item carries `base_seq`, the server seq the client last saw (0 = new). The server accepts it with a new seq only if the item is still at `base_seq`, otherwise it returns `conflict` |

Each account has one monotonic `seq`. Deletes are tombstones (`deleted: true`, no blob).

### Client sync loop

1. **Pull** pages from the cursor. If `keys_version` changed, fetch `GET /v1/keys` and adopt the bundle. Merge every item.
2. **Push** every locally changed (dirty) item. Accepted items are marked clean. If the item was edited again while the push was in flight, it stays dirty.
3. If any push came back as a conflict, pull and push again (at most 3 rounds).

### Conflict rules (never lose data)

| Local | Remote | Result |
|---|---|---|
| edited | edited | The remote version stays. The local version becomes a new item titled "… (conflict copy)" (skipped when both are identical). Note conflicts found while the notes are locked are stashed and become copies at the next notes unlock |
| edited | deleted | The local edit wins and is pushed again |
| deleted | edited | The remote version comes back |
| deleted | deleted | Nothing to do |

Remote items that fail to decrypt, or whose kind or parent does not match, are rejected and never stored.

## Key changes

`PUT /v1/keys {expected_version, keys, …}` publishes a new bundle with optimistic concurrency (`409 version_conflict` if another device changed the keys first).

- **Master password change:** the request also carries `current_auth_key` (proof of the old password), `new_auth_key` and `new_kdf`, and signs out every other device. Those devices then sign in again with the new password and adopt the new bundle.
- **Notes password change / recovery-key rotation:** the bundle alone changes. Other devices adopt it on their next sync.
- If publishing fails, the app rolls the local change back, so devices never disagree about keys.

**Recovery** (forgotten password, on a device that still has the vault): the recovery key resets both passwords locally. Then `POST /v1/recover {email, key_proof, new_auth_key, kdf, keys, device}` resets the server login and signs out every session. If the server cannot be reached, the vault remembers to finish the reset later.

## Other endpoints

`GET /health`, `GET /v1/info` (version, API version, registration mode), `POST /v1/accounts` (register), `DELETE /v1/sessions/current` (sign out), `GET /v1/devices`, `DELETE /v1/devices/{id}`, `DELETE /v1/account {auth_key}`.

Errors are JSON: `{"code": "invalid_credentials", "message": "…"}`.

## What the server can and cannot learn

**Can see:**
- the account email and device names;
- item counts and sizes;
- update times and sequence numbers;
- which notes belong to which record (parent ids);
- client IP addresses.

**Cannot see:** any title, username, password, URL, note, TOTP secret, or any key able to decrypt them.

**Known limitations of v1:**
- A malicious server can withhold items, or serve an older ciphertext of an item again (rollback). It cannot forge or read items.
- Accounts are identified by email without verification.
- Recovering a forgotten password needs a device that still holds the vault file (or a `.simplusvault` backup).
