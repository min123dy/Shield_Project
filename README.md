# Shield 3.0.0

[한국어](#한국어) · [English](#english)

---

## 한국어

Shield는 Windows와 Linux용 파일·폴더 암호화 프로그램입니다. 파일을 압축한 뒤 XChaCha20-Poly1305로 암호화해 `.shd`
컨테이너에 저장하고, 파일 관리자 창에서 컨테이너 안을 보거나 일부만 꺼내고 파일을 더하거나 뺄 수 있습니다.
창 프로그램(`shield-gui`)과 명령줄 프로그램(`shield`)이 있으며, 두 OS가 같은 파일 형식을 씁니다.

### 3.0의 새 기능

- **여러 항목 암호화**: 탐색기·파일 관리자에서 여러 개를 골라 하나로 묶거나 항목마다 따로 만듭니다. 목록을 고칠 수 있습니다.
- **명령줄 프로그램** `shield`: encrypt, decrypt, list, add, remove, change-password, rekey, keyfile, verify, update,
  entropy, version. 비밀번호는 에코 없이 입력받고, 인자 비밀번호는 기본으로 꺼져 있습니다. GUI 의존성 없는 콘솔 전용 빌드도 있습니다.
- **Linux 판**: deb, AppImage, musl 정적 콘솔. Nautilus·Nemo·Dolphin·Thunar 메뉴, FITRIM, LUKS·스냅숏 확인, XDG 경로.
- **덮어쓰기 삭제**: 3회 또는 7회(매번 선택), 키 영역은 항상 7회, 스냅숏(VSS·btrfs·ZFS·LVM·Timeshift·Snapper) 경고,
  끝나면 TRIM. 키 교체·추가·삭제 뒤의 이전 컨테이너도 덮어씁니다.
- **엔트로피**: OS 난수가 항상 기본이고, 보조 소스는 섞기만 합니다. 소스별로 켜고 끌 수 있고 상태는 정상/약함만 표시합니다.
- **업데이트**(기본 꺼짐): GitHub 릴리스를 HTTPS로 확인하고, 내장 공개키로 OpenPGP 서명·SHA-256을 확인한 뒤 물어보고 설치합니다.
  다운그레이드와 서명 실패는 거부합니다.
- **무결성 검사**: 프로그램 자신의 서명 확인, `shield verify <파일> <서명>`, 키 지문 표시.
- **설정 비밀번호**: 보안 설정은 설정 비밀번호(Argon2id)로 잠기고, 설정 파일 변조는 HMAC-SHA3-512로 감지합니다.

### 암호 구성 (2.1과 같음)

| 항목 | 값 |
|---|---|
| 암호화 | XChaCha20-Poly1305 (256비트 키, 192비트 nonce) |
| 키 유도 | Argon2id v1.3, 256 MiB, 병렬도 4, 반복 3 + PIM (기본 12) |
| 해시·복원 검증 | SHA3-512 |
| 메타데이터 | 암호화 + 헤더 인증 (형식 버전·알고리즘 ID도 안에만) |
| 압축 | LZMA2, Zstandard, 무압축 (자동 선택) |
| 서명 검증 | OpenPGP (rPGP; brainpool은 RustCrypto) |

키는 작업이 끝나면 지우고, 작업마다 비밀번호를 다시 묻습니다. 3.0은 2.x 컨테이너를 그대로 엽니다(1.x 형식은 열지 않음).

### 설치

- Windows: `Shield_v3.0.0_x64.msi` (창 프로그램 + PATH에 `shield`), 또는 `Shield_v3.0.0_x64_portable.exe`,
  `shield-console_v3.0.0_windows_x64.exe`
- Linux: `sudo apt install ./shield_v3.0.0_amd64.deb`, 또는 `Shield_v3.0.0_x86_64.AppImage`, `shield-console_v3.0.0_linux_x64`
- 받은 파일은 `.sig`로 검증하세요: `gpg --verify <파일>.sig <파일>` 또는 `shield verify <파일> <파일>.sig --key <공개키.asc>`

### 빠른 사용

```text
shield encrypt 보고서.pdf 사진/ -o 묶음.shd     여러 항목을 하나로 (--separate: 항목마다)
shield decrypt 묶음.shd -o 풀_폴더
shield list 묶음.shd --json
shield verify 파일 파일.sig
shield help                                    전체 도움말과 종료 코드
```

### 빌드

```text
Windows: .\build.ps1 -RepoUrl https://github.com/<owner>/<repo> -NoSign
Linux:   ./build.sh --repo https://github.com/<owner>/<repo> --no-sign
```

입력: 저장소 URL, 내장할 공개키 `.asc`(기본 `keys/release_key.asc`), 서명 여부, 변형. 서명 개인키는 저장소에 넣지 않고,
CI에서는 GitHub 시크릿(서명 부키)으로만 씁니다. 자세한 내용은 `docs/02_빌드_방법.txt`.

### 문서

| 파일 | 내용 |
|---|---|
| `docs/01_프로젝트_설명.txt` | 구조, 암호 구성, 형식, 한계 |
| `docs/02_빌드_방법.txt` | 빌드 입력, 스크립트, CI, OS별 확인 목록 |
| `docs/03_사용_방법.txt` | 사용 설명서 (창과 명령줄) |
| `docs/04_설치_안내.txt` | 설치 첫 화면의 주의사항 |
| `docs/05_테스트_및_점검_기록.txt` | 테스트 결과, 발견·수정한 문제, 보안 재점검 |
| `docs/06_3.0.0_수정_기록.txt` | 3.0 변경, 의존성, 엔트로피 소스, OS 지원 표, 라이선스 검토 |
| `docs/en/` | 영어판 |
| `docs/history/` | 2.x 기록 |

### 한계 (요약)

같은 사용자 권한의 악성 프로그램, 관리자/root, 커널, 물리적 접근은 막지 못합니다. SSD·COW 파일 시스템·스냅숏·클라우드
폴더에서는 덮어쓰기와 TRIM이 물리적 삭제를 보장하지 않습니다. Linux에서는 설정 MAC 키가 봉인되지 않고 화면 캡처 방지가
없습니다. 독립적인 외부 보안 감사를 받지 않았습니다. 전체 목록은 `docs/01_프로젝트_설명.txt` 7절.

---

## English

Shield encrypts files and folders on Windows and Linux. Items are compressed, encrypted with XChaCha20-Poly1305 and
stored in a `.shd` container; the file manager window browses containers, extracts some items and adds or removes
files. There is a windowed program (`shield-gui`) and a command-line program (`shield`); both OSes share one file format.

### New in 3.0

- **Several items at once**: select several in Explorer or a Linux file manager and make one container or one per item;
  the list can be edited.
- **Command-line program** `shield`: encrypt, decrypt, list, add, remove, change-password, rekey, keyfile, verify,
  update, entropy, version. Passwords are read without echo; argument passwords are off by default. A console-only build
  without GUI dependencies exists too.
- **Linux version**: deb, AppImage, static musl console. Nautilus, Nemo, Dolphin and Thunar entries, FITRIM, LUKS and
  snapshot checks, XDG paths.
- **Overwrite deletion**: 3 or 7 passes (chosen each time), key areas always 7, snapshot warnings (VSS, btrfs, ZFS, LVM,
  Timeshift, Snapper), TRIM at the end. The old container after rekey, add and delete is overwritten too.
- **Entropy**: the OS RNG is always the base; extra sources are only mixed in, can be switched per source and show
  Normal / Weak only.
- **Updates** (off by default): GitHub releases over HTTPS; the OpenPGP signature and SHA-256 are checked with the
  built-in key, then you are asked before installing. Downgrades and bad signatures are refused.
- **Integrity**: the program's own signature check, `shield verify <file> <signature>`, the key fingerprint shown.
- **Settings password**: security settings are locked by a settings password (Argon2id); edits of the settings file are
  detected with HMAC-SHA3-512.

### Cryptography (same as 2.1)

| Item | Value |
|---|---|
| Encryption | XChaCha20-Poly1305 (256-bit key, 192-bit nonce) |
| Key derivation | Argon2id v1.3, 256 MiB, parallelism 4, iterations 3 + PIM (default 12) |
| Hash, restore check | SHA3-512 |
| Metadata | encrypted + header authentication (format version and algorithm IDs only inside) |
| Compression | LZMA2, Zstandard, stored (automatic) |
| Signature verification | OpenPGP (rPGP; brainpool via RustCrypto) |

Keys are wiped after each task and the password is asked for every task. 3.0 opens 2.x containers unchanged (not 1.x).

### Install

- Windows: `Shield_v3.0.0_x64.msi` (windows + `shield` on PATH), or `Shield_v3.0.0_x64_portable.exe`,
  `shield-console_v3.0.0_windows_x64.exe`
- Linux: `sudo apt install ./shield_v3.0.0_amd64.deb`, or `Shield_v3.0.0_x86_64.AppImage`, `shield-console_v3.0.0_linux_x64`
- Verify downloads with the `.sig`: `gpg --verify <file>.sig <file>` or `shield verify <file> <file>.sig --key <key.asc>`

### Quick use

```text
shield encrypt report.pdf photos/ -o all.shd    several items into one (--separate: one per item)
shield decrypt all.shd -o out_dir
shield list all.shd --json
shield verify file file.sig
shield help                                     full help and exit codes
```

### Build

```text
Windows: .\build.ps1 -RepoUrl https://github.com/<owner>/<repo> -NoSign
Linux:   ./build.sh --repo https://github.com/<owner>/<repo> --no-sign
```

Inputs: repository URL, the public key `.asc` to embed (default `keys/release_key.asc`), signing yes/no, variants. The
signing private key never goes into the repository; CI uses it only through GitHub secrets (signing subkey). Details in
`docs/en/02_build.txt`.

### Documents

| File | Content |
|---|---|
| `docs/en/01_overview.txt` | layout, cryptography, format, limits |
| `docs/en/02_build.txt` | build inputs, scripts, CI, per-OS checklists |
| `docs/en/03_usage.txt` | user guide (windows and command line) |
| `docs/en/04_install_notes.txt` | notes on the first installer page |
| `docs/en/05_test_and_audit.txt` | test results, bugs found and fixed, security re-audit |
| `docs/en/06_changes_3.0.0.txt` | 3.0 changes, dependencies, entropy sources, OS support table, license review |
| `docs/` | Korean versions |
| `docs/history/` | 2.x records (Korean) |

### Limits (summary)

Malware running as the same user, administrators/root, the kernel and physical access are out of reach. On SSDs, COW
file systems, snapshots and cloud folders, overwriting and TRIM don't guarantee physical erasure. On Linux the settings
MAC key is not sealed and there is no screen capture protection. No independent external audit. Full list:
`docs/en/01_overview.txt` section 7.
