# SHIELD 1.1

SHIELD는 Windows 환경을 위한 파일 및 폴더 암호화 프로그램입니다. 파일별 독립 암호화 키와 스트리밍 암호화 구조를 사용하며, 자동 압축, 키 파일 결합, 임시 암호화 저장소 등의 기능을 제공합니다.

기존 파일 관리 흐름을 최대한 유지하면서 암호화와 복호화 작업을 간편하게 수행할 수 있도록 설계되었습니다.

## 주요 기능

### 파일 및 폴더 암호화

- 개별 파일 및 폴더 암호화
- 폴더 암호화 시 자동으로 7z 압축 수행
- LZMA2 압축 지원
- 스트리밍 방식의 암호화 및 복호화
- 파일별 독립적인 DEK(Data Encryption Key) 사용
- 암호화 작업 진행률 표시
- 작업 취소 지원

### 암호화 알고리즘

- ChaCha20-Poly1305 인증 암호화
- Argon2id 기반 키 파생
- 운영체제 난수 생성기 사용
- 파일별 무작위 DEK 생성
- 암호화 키와 비밀번호를 이용한 키 보호
- 선택적인 키 파일 결합
- PIM 설정을 통한 Argon2id 반복 횟수 조정

### 키 및 비밀번호 관리

- 비밀번호 기반 암호화
- 외부 키 파일 추가 및 결합
- 여러 키 파일 사용 지원
- 비밀번호 변경
- 키 파일을 이용한 추가 인증 요소 제공
- 민감한 메모리 데이터의 초기화 및 보호 기능

### SecTemp 임시 암호화 저장소

암호화 과정에서 생성되는 임시 데이터를 보호하기 위해 SecTemp를 사용합니다.

- 임시 데이터 암호화
- 64 KiB 단위 블록 처리
- 스트리밍 입출력
- 임의 접근 지원
- 임시 암호화 키 관리
- 작업 완료 후 임시 데이터 정리

### 파일 관리 및 시스템 연동

- 파일 탐색기 기반 파일 관리
- Windows 탐색기 컨텍스트 메뉴 연동
- 암호화 및 복호화 작업 진행 상태 표시
- 출력 파일 이름 충돌 처리
- 선택적인 원본 파쇄 기능
- SSD 환경을 고려한 여유 공간 정리 기능

## 보안 설계

SHIELD는 다음과 같은 암호학적 구성 요소를 사용합니다.

| 구성 요소 | 사용 기술 |
|---|---|
| 대칭키 암호화 | ChaCha20-Poly1305 |
| 키 파생 함수 | Argon2id |
| 파일 암호화 키 | 파일별 독립 DEK |
| 키 보호 | KEK 기반 DEK 래핑 |
| 난수 생성 | 운영체제 CSPRNG |
| 압축 | 7z / LZMA2 |
| 임시 저장소 | SecTemp |

Argon2id는 비밀번호로부터 암호화 키를 파생하는 데 사용됩니다. 파일별 독립 DEK는 각 파일의 데이터 암호화에 사용되며, 비밀번호와 키 파일은 키 보호 과정에 활용됩니다.

암호화 알고리즘 자체뿐 아니라 임시 데이터, 파일 처리, 키 관리 및 복호화 과정도 보안 설계의 중요한 부분으로 취급합니다.

## 다운로드 및 설치

설치 프로그램은 GitHub 저장소의 **Releases** 페이지에서 다운로드할 수 있습니다.

- 소스 코드를 직접 빌드할 필요 없이 릴리즈에 게시된 설치 파일을 사용할 수 있습니다.
- 최신 버전의 설치 파일과 변경 사항은 Releases 페이지에서 확인할 수 있습니다.
- 설치 파일은 Windows 환경을 대상으로 합니다.

**다운로드:** [GitHub Releases](../../releases)

## 빌드 환경

SHIELD는 Rust 기반 프로젝트입니다.

빌드에 필요한 환경은 다음과 같습니다.

- Windows 10 또는 Windows 11
- Rust 안정화 버전(Stable)
- Cargo
- Visual Studio Build Tools
- MSVC C++ 빌드 도구
- Windows SDK

Rust 설치는 공식 홈페이지에서 진행할 수 있습니다.

- Rust: https://www.rust-lang.org/tools/install
- Visual Studio Build Tools: https://visualstudio.microsoft.com/downloads/

## 소스 코드 빌드

### 1. 저장소 복제

```powershell
git clone <REPOSITORY_URL>
cd shield
```

### 2. Rust 빌드 환경 확인

```powershell
rustc --version
cargo --version
```

### 3. 의존성 확인 및 다운로드

```powershell
cargo fetch
```

### 4. 디버그 빌드

```powershell
cargo build
```

### 5. 릴리즈 빌드

최적화된 실행 파일을 생성하려면 다음 명령을 사용합니다.

```powershell
cargo build --release
```

빌드가 성공하면 실행 파일은 다음 위치에 생성됩니다.

```text
target\release\shield.exe
```

### 6. 프로그램 실행

```powershell
cargo run --release
```

또는 빌드된 실행 파일을 직접 실행할 수 있습니다.

```powershell
.\target\release\shield.exe
```

### 7. 테스트

프로젝트에 포함된 테스트를 실행하려면 다음 명령을 사용합니다.

```powershell
cargo test
```

### 8. 의존성 보안 검사

Cargo Audit을 설치한 뒤 다음 명령으로 Rust 의존성의 공개 보안 권고를 확인할 수 있습니다.

```powershell
cargo install cargo-audit
cargo audit
```

## 프로젝트 구조

주요 소스 파일은 다음과 같은 역할을 담당합니다.

| 파일 | 역할 |
|---|---|
| `main.rs` | 프로그램 진입점 및 메인 UI |
| `engine.rs` | 파일 암호화 및 복호화 엔진 |
| `sectemp.rs` | SecTemp 임시 암호화 저장소 |
| `archive.rs` | 압축 및 압축 해제 처리 |
| `harden.rs` | 메모리 및 민감 데이터 보호 |
| `keyfile.rs` | 키 파일 처리 |
| `Cargo.toml` | Rust 프로젝트 설정 및 의존성 |

실제 프로젝트 버전에 따라 파일 구성은 달라질 수 있습니다.

## 라이선스

SHIELD는 **Apache License 2.0**을 따릅니다.

Apache License 2.0에 따라 라이선스 조건을 준수하는 범위에서 소프트웨어의 사용, 복제, 수정 및 배포가 가능합니다.

자세한 내용은 저장소의 `LICENSE` 파일을 확인하십시오.

라이선스 전문: https://www.apache.org/licenses/LICENSE-2.0

## 주의사항

- 암호화 비밀번호와 키 파일은 안전한 장소에 별도로 보관해야 합니다.
- 비밀번호 또는 필요한 키 파일을 분실하면 암호화된 데이터에 접근하지 못할 수 있습니다.
- 원본 파쇄 기능을 사용하기 전에 암호화된 결과물의 정상적인 복호화 여부를 확인하는 것이 좋습니다.
- SSD의 웨어 레벨링 및 컨트롤러 동작으로 인해 소프트웨어 덮어쓰기만으로 물리적인 데이터 삭제를 보장할 수는 없습니다.
- 중요한 파일은 암호화 작업 전후로 별도의 백업을 유지하는 것을 권장합니다.

---

**SHIELD 1.1**

Rust 기반 Windows 파일 암호화 프로그램

Licensed under the Apache License, Version 2.0.
