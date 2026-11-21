# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Shield 3.1.0: a Rust file/folder encryption tool for Windows and Linux. Files are compressed, encrypted with XChaCha20-Poly1305 (Argon2id KDF) and stored in a `.shd` container. Ships as a GUI (`shield-gui`, egui) and a CLI (`shield`). Both OSes share one byte-identical container format (v2; 2.x containers open, 1.x do not). Docs and user-facing strings are bilingual (Korean/English); Korean is the primary docs language (`docs/*.txt`, English in `docs/en/`).

## Commands

```text
cargo build --release                      # workspace; bins: shield, shield-gui
cargo test --workspace --release           # what build.ps1/build.sh run first
cargo test -p shield-core <name>           # single test / filter (e.g. cargo test -p shield-core fuzz)
cargo build --release -p shield-cli --no-default-features   # console-only build, no GUI deps
SHIELD_BLESS=1 cargo test --release -p shield-cli help_snapshots   # rewrite CLI help snapshots after a deliberate change
cargo audit --deny warnings                # ignores with reasons live in .cargo/audit.toml (same IDs in deny.toml)
cargo deny --locked check advisories bans sources licenses   # deny.toml, written for cargo-deny 0.20.2
.\build.ps1 -RepoUrl https://github.com/<owner>/<repo> -NoSign [-Variants msi,portable,console] [-SkipTests]   # Windows packaging
./build.sh --repo https://github.com/<owner>/<repo> --no-sign [--variants deb,appimage,console,rpm,zip]        # Linux packaging
```

- Every cargo call in build.ps1/build.sh/release.yml uses `--locked` (release_tests checks). Both scripts take a stage (`-Stage`/`--stage all|build|package|manifest`, `-BinDir`/`--bin-dir`); CI builds unsigned, signs in separate `release-signing` environment jobs (docs/02 section 7).
- Rust >= 1.89 (workspace `rust-version`). Release profile is LTO + `codegen-units=1` + strip.
- Tests run Argon2id (256 MiB) many times, so `[profile.dev.package."*"]` uses `opt-level = 3`; prefer `--release` or accept slow debug tests.
- Packaging needs extra tools (WiX 5 via `.config/dotnet-tools.json`, MSVC on Windows; gtk/dpkg/appimagetool/musl on Linux). Details: `docs/02_빌드_방법.txt`. Releases are tag-driven via `.github/workflows/release.yml`.
- Build-time inputs: `SHIELD_REPO_URL` (must be `https://github.com/<owner>/<repo>`, else `shield-core/build.rs` aborts; empty = no updates/dev-info link) and `SHIELD_PUBKEY_PATH` (default `keys/release_key.asc`, embedded for update/integrity checks; build aborts if it contains a private key). Never put signing private keys in the repo.

## Architecture

Four crates, strict layering: `shield-platform` ← `shield-core` ← `shield-gui` ← `shield-cli`.

- **shield-platform**: the *only* place with OS-specific code. `Platform` trait (via `platform()`) plus low-level `fs`/`mem`/`sys` primitives, with `windows/` and `linux/` modules chosen by `cfg`. Unsupported services return `PlatformError::Unsupported`, never silently skipped.
- **shield-core**: all engine logic, **no `cfg(windows)`/`cfg(unix)` product code** (keep it that way; route OS needs through shield-platform). Key pieces: `format`/`container`/`crypto`/`engine`/`rekey` (container format and operations), `archive`/`compress`/`manifest`/`staging`/`sectemp` (content pipeline and secure temp files), `wipe` (3/7-pass overwrite + TRIM + snapshot warnings), `entropy/` (OS CSPRNG always base; extra sources only mixed in), `settings` + `settings_auth` (settings-password-locked, HMAC-SHA3-512-protected config), `sigverify` (OpenPGP) + `update` + `buildinfo` (self-integrity, GitHub release updates, off by default), `spool` (merges multi-item Explorer launches into one window), `lock`, `harden`.
- **All user-visible strings** live in `shield-core/src/lang/` as ko/en × core/ui/v3/cli tables (plus `help_ko`/`help_en`), accessed through `i18n`. Add both languages when adding strings.
- **shield-gui**: lib `run(Start)` + bin `shield-gui`. Encryption window (`enc_*`), container file-manager window (`mgr_*`), settings, update UI. Launch args used by shell verbs: `--encrypt-multi`, `--decrypt`, `--open`, `--manager`, `--settings`.
- **shield-cli**: table-driven arg parsing (`args`), no-echo secret input (`secret`), credential rules (`cred`; password-on-argv is off by default), command impls (`cmds`, `tools`), exit codes/progress (`out`). Feature `gui` (default) adds `shield gui ...`; disabling it gives a console build with no eframe/rfd deps.

3.0.0 release-patch structure (details in `docs/06` section 12):
- One password check: `password::check_new` returns `blocks` (refuse) and `warnings` (confirm); GUI, settings password and CLI all use it via `engine::check_new_password`.
- Window geometry only in `shield-gui/src/window.rs` (size constants, position restore/tracking); OS scale/monitor queries in `shield_platform::display` (`prepare_scale` must run first in `run()`).
- Remembered UI state is `ui_prefs::UiPrefs` inside `Settings` (`ui_*` keys). Never store passwords, key files, paths, PIM or acknowledgements. The GUI saves through `Settings::save_merged` (lock + merge, debounced in `shell.rs`).
- Environment-unavailable options use `Settings::suppress(EnvKey, reason)`: shown off with a reason, the file keeps the user's value. Failed hardening goes through `harden::degraded` → `Shell::gate` / CLI confirmation.
- CLI help is generated in `shield-cli/src/cli_help.rs` from the `args` tables plus `cli.h_*/o_*/v_*/s_*` strings; every command/option must have an entry (tested).
- `shield-core/src/release_tests.rs` guards the installer identity (UpgradeCode, IgnoreLanguage, pinned GUIDs), version consistency and the absence of beta labels.

Invariants worth preserving (see `docs/01_프로젝트_설명.txt`): keys are wiped after each task and the password is asked per task; the container has no magic bytes and metadata (including format version/algorithm IDs) is encrypted; crypto parameters must not be weakened (Argon2id 256 MiB, p=4, t=3+PIM). Cross-OS compatibility is tested against fixtures in `crates/shield-core/tests/fixtures` (`cross_os_tests`); fuzz-style tests live in `fuzz_tests.rs`. Unit tests are mostly sibling `*_tests.rs` files.

## Repo notes

- `target/`, `dist/`, `dist_old_v2.1.0/`, `Shield.msi`, `.wix/`, `.claude-flow/` are build/tool output; `_unused/` is dead code. Not a git repository at the moment.
- Docs to update alongside behavior changes: `docs/01`–`07` (+ `docs/en/`); `docs/05` is the test/security review log, `docs/06_3.1.0_*` the current change log (`docs/06_3.0.0_*` is the 3.0 design record cited as "docs/06 section 12"), `docs/07` the signing key rotation procedure (optional backup key `keys/release_key_backup.asc` / `SHIELD_PUBKEY_BACKUP_PATH`).
- `shield-core/src/compat_tests.rs` pins what 3.0.0 clients read (manifest parser, settings MAC input) against copies in `tests/fixtures/compat_3_0_0`; changing those functions breaks 3.0.0 -> 3.x updates.
