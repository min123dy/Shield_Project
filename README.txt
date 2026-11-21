SHIELD 3.1.0 - 프로젝트 파일 / project files

빌드 / Build
  Windows (PowerShell): .\build.ps1 [-RepoUrl https://github.com/<owner>/<repo>] [-Sign | -NoSign] [-Variants msi,portable,console]
  Linux (bash):         ./build.sh  [--repo https://github.com/<owner>/<repo>] [--sign | --no-sign] [--variants deb,appimage,console,zip]
  입력이 없으면 터미널에서 묻습니다 / missing inputs are asked in the terminal.
  결과 / output: dist\ (MSI, portable, console, deb, AppImage, Shield_Project_v3.1.0.zip, release manifests v1/v2, SHA256SUMS.txt,
                  서명 시 .sig·공개키·VERIFY.txt / when signed: .sig files, public key, VERIFY.txt)

프로그램 / Programs
  shield-gui                         암호화 창 / encryption window
  shield-gui --manager [경로|path]    파일 관리자 / file manager
  shield-gui --open <c.shd>          컨테이너 열기 / open a container
  shield-gui --encrypt-multi <...>   여러 항목 암호화 / encrypt several items
  shield-gui --decrypt <c.shd>       복호화 / decrypt
  shield-gui --wipe -- <...>         완전삭제 탭 열기(확인은 창에서) / open the Secure delete tab (confirmed in the window)
  shield wipe <...> [-r]             완전삭제 / secure delete (docs\10)
  shield help                        명령줄 도움말 / command-line help

문서 / Documents
  docs\01_프로젝트_설명.txt      docs\en\01_overview.txt        구조, 암호, 한계 / layout, crypto, limits
  docs\02_빌드_방법.txt          docs\en\02_build.txt           빌드·서명·CI / build, signing, CI
  docs\03_사용_방법.txt          docs\en\03_usage.txt           사용 설명서 / user guide
  docs\04_설치_안내.txt          docs\en\04_install_notes.txt   설치 첫 화면 / installer notes
  docs\05_테스트_및_점검_기록.txt docs\en\05_test_and_audit.txt  테스트·보안 점검 / tests, audit
  docs\06_3.1.0_수정_기록.txt    docs\en\06_changes_3.1.0.txt   이전 3.1.0 빌드 수정 / earlier 3.1.0 build fixes
  docs\06_3.0.0_수정_기록.txt    docs\en\06_changes_3.0.0.txt   3.0 변경 / 3.0 changes
  docs\07_서명키_교체.txt        docs\en\07_key_rotation.txt    서명 키 운영·교체 / signing key operation, rotation
  docs\08_3.1.0_최종_변경_내역.txt docs\en\08_changes_3.1.0_final.txt     3.1.0 최종 변경 / 3.1.0 final changes
  docs\09_보안_분석_보고서.txt   docs\en\09_security_report.txt       보안 분석 / security analysis
  docs\10_완전삭제_설계.txt      docs\en\10_secure_delete_design.txt  완전삭제 설계 / secure delete design
  docs\history\                  2.x 기록 / 2.x records

주의 / Note: 공개키는 유효해야 하지만 서명 부키·만료일·프로젝트 사용자 ID·백업 키는 빌드 필수 조건이 아닙니다.
서명된 릴리스에는 내장 공개키와 일치하는 서명 가능한 비밀키가 필요합니다. 라이선스: Apache License 2.0.
A valid public key is required, but a signing subkey, expiry, project ID and backup key are not build prerequisites.
Signed releases need a signing-capable secret key matching the embedded public key. License: Apache License 2.0.
