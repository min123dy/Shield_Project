SHIELD 3.0.0 - 프로젝트 파일 / project files

빌드 / Build
  Windows (PowerShell): .\build.ps1 [-RepoUrl https://github.com/<owner>/<repo>] [-Sign | -NoSign] [-Variants msi,portable,console]
  Linux (bash):         ./build.sh  [--repo https://github.com/<owner>/<repo>] [--sign | --no-sign] [--variants deb,appimage,console,zip]
  입력이 없으면 터미널에서 묻습니다 / missing inputs are asked in the terminal.
  결과 / output: dist\ (MSI, portable, console, deb, AppImage, Shield_Project_v3_0_0.zip, release manifest, SHA256SUMS.txt,
                  서명 시 .sig·공개키·VERIFY.txt / when signed: .sig files, public key, VERIFY.txt)

프로그램 / Programs
  shield-gui                         암호화 창 / encryption window
  shield-gui --manager [경로|path]    파일 관리자 / file manager
  shield-gui --open <c.shd>          컨테이너 열기 / open a container
  shield-gui --encrypt-multi <...>   여러 항목 암호화 / encrypt several items
  shield-gui --decrypt <c.shd>       복호화 / decrypt
  shield help                        명령줄 도움말 / command-line help

문서 / Documents
  docs\01_프로젝트_설명.txt      docs\en\01_overview.txt        구조, 암호, 한계 / layout, crypto, limits
  docs\02_빌드_방법.txt          docs\en\02_build.txt           빌드·서명·CI / build, signing, CI
  docs\03_사용_방법.txt          docs\en\03_usage.txt           사용 설명서 / user guide
  docs\04_설치_안내.txt          docs\en\04_install_notes.txt   설치 첫 화면 / installer notes
  docs\05_테스트_및_점검_기록.txt docs\en\05_test_and_audit.txt  테스트·보안 점검 / tests, audit
  docs\06_3.0.0_수정_기록.txt    docs\en\06_changes_3.0.0.txt   3.0 변경 / 3.0 changes
  docs\history\                  2.x 기록 / 2.x records
