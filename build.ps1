#requires -Version 5.1
# Shield 3.0 Windows build: tests, shield-gui.exe + shield.exe, MSI, portable builds, source zip,
# signed release manifest, optional OpenPGP signatures (.sig) and SHA256SUMS in dist\.
#
# Inputs (parameter, environment variable, or asked when missing on a terminal):
#   -RepoUrl https://github.com/<owner>/<repo>   SHIELD_REPO_URL  (Enter = no link, no updates)
#   -PublicKeyPath key.asc                       SHIELD_PUBKEY_PATH (default keys\release_key.asc)
#                                                embedded for update / integrity checks
#   -Sign | -NoSign                              SHIELD_SIGN=y|n  (asks when neither)
#   -Variants msi,portable,console               SHIELD_VARIANTS  (default: all three)
#   -Culture ko-KR|en-US                         MSI language (default ko-KR)
#   -MergeManifest <file>                        add the lines of another release manifest
#                                                (e.g. the Linux packages) before signing
#   -GpgHome <dir>  -UpxPath <upx>  -NoUpx  -SkipTests
# Secrets: the signing passphrase is never an argument, variable or log line; gpg-agent/pinentry
# asks for it. The private key never leaves the local keyring (CI: see docs 02).
# Saved as UTF-8 with BOM for Windows PowerShell 5.1.
[CmdletBinding()]
param(
    [string]$RepoUrl,
    [string]$PublicKeyPath,
    [switch]$Sign,
    [switch]$NoSign,
    [string]$Variants,
    [ValidateSet('ko-KR', 'en-US')][string]$Culture = 'ko-KR',
    [string]$MergeManifest,
    [string]$GpgHome,
    [string]$UpxPath,
    [switch]$NoUpx,
    [switch]$SkipTests
)
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding
Set-Location -LiteralPath $PSScriptRoot
$root = (Resolve-Path -LiteralPath $PSScriptRoot).Path.TrimEnd('\')
$manifestPath = Join-Path $root "Cargo.toml"
$wixVersion = "5.0.2"
$utf8Bom = New-Object System.Text.UTF8Encoding($true)
$utf8 = New-Object System.Text.UTF8Encoding($false)
$canAsk = [Environment]::UserInteractive -and -not [Console]::IsInputRedirected

function Assert-ExitCode([string]$what) {
    if ($LASTEXITCODE -ne 0) { throw "$what 실패 (종료 코드: $LASTEXITCODE). 위의 오류를 확인하세요." }
}
function Ask-YesNo([string]$q) { return ((Read-Host "$q (y/N)") -match '^\s*(y|yes|예|네|ㅇ)\s*$') }
function Step([string]$m) { Write-Host "== $m" -ForegroundColor Cyan }

function Find-Gpg {
    $native = @((Join-Path ${env:ProgramFiles(x86)} "GnuPG\bin\gpg.exe"), (Join-Path $env:ProgramFiles "GnuPG\bin\gpg.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "Gpg4win\bin\gpg.exe"), (Join-Path $env:ProgramFiles "Gpg4win\bin\gpg.exe")) |
        Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) } | Select-Object -First 1
    $cmd = Get-Command gpg.exe -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cmd -and -not ($native -and $cmd.Source -match '\\usr\\bin\\gpg\.exe$')) { return $cmd.Source }
    if ($native) { return $native }
    if ($cmd) { return $cmd.Source }
    throw "gpg.exe를 찾을 수 없습니다. Gpg4win을 설치하거나 -NoSign으로 실행하세요."
}
function ConvertTo-GpgPath([string]$p) {
    if ($script:msysGpg -and $p -match '^([A-Za-z]):[\\/](.*)$') { return '/' + $Matches[1].ToLowerInvariant() + '/' + ($Matches[2] -replace '\\', '/') }
    return $p
}
function Invoke-Gpg([string[]]$a, [switch]$AllowFail) {
    $ErrorActionPreference = 'Continue'
    $out = & $script:gpg @a 2>&1 | ForEach-Object { "$_" }
    if (-not $AllowFail -and $LASTEXITCODE -ne 0) { throw "gpg 실패 (종료 코드 $LASTEXITCODE): $($out -join ' | ')" }
    return $out
}
function Invoke-Upx([string[]]$a) {
    $ErrorActionPreference = 'Continue'
    $out = @(& $script:upxExe @a 2>&1 | ForEach-Object { "$_" })
    if ($LASTEXITCODE -ne 0) { throw "UPX 실패 (종료 코드 $LASTEXITCODE): $($out -join ' | ')" }
    return $out
}
function Get-PeFlags([string]$p) {
    $b = [System.IO.File]::ReadAllBytes($p); $pe = [BitConverter]::ToInt32($b, 0x3C)
    if ($pe -le 0 -or $pe + 24 + 0x48 -gt $b.Length -or [BitConverter]::ToUInt32($b, $pe) -ne 0x4550) { throw "PE 헤더 오류: $p" }
    return [BitConverter]::ToUInt16($b, $pe + 24 + 0x46)
}
# Detached signature, then verification with a keyring that holds ONLY the given public key.
function Sign-File([string]$t) {
    $sig = "$t.sig"
    if (Test-Path -LiteralPath $sig) { Remove-Item -LiteralPath $sig -Force }
    $a = @('--local-user', $script:fpr, '--digest-algo', 'SHA512', '--detach-sign', '--output', (ConvertTo-GpgPath $sig), (ConvertTo-GpgPath $t))
    if ($GpgHome) { $a = @('--homedir', (ConvertTo-GpgPath $GpgHome)) + $a }
    $null = Invoke-Gpg $a
    $v = Invoke-Gpg @('--homedir', (ConvertTo-GpgPath $script:tmpHome), '--batch', '--status-fd', '1', '--verify', (ConvertTo-GpgPath $sig), (ConvertTo-GpgPath $t)) -AllowFail
    if ($LASTEXITCODE -ne 0 -or -not ($v | Where-Object { $_ -match "^\[GNUPG:\] VALIDSIG .*\b$($script:fpr)\b" })) {
        Remove-Item -LiteralPath $sig -Force -ErrorAction SilentlyContinue
        throw "서명 검증 실패: $(Split-Path -Leaf $sig)"
    }
    Write-Host "  서명 확인: $(Split-Path -Leaf $sig)"
}

# ------------------------------------------------------------------ 0. inputs
if ($Sign -and $NoSign) { throw "-Sign과 -NoSign은 함께 쓸 수 없습니다." }
if (-not $RepoUrl) { $RepoUrl = $env:SHIELD_REPO_URL }
if (-not $RepoUrl -and $canAsk) { $RepoUrl = (Read-Host "GitHub 저장소 URL (https://github.com/<owner>/<repo>, 없으면 Enter)").Trim() }
$RepoUrl = "$RepoUrl".Trim()
if ($RepoUrl -and $RepoUrl -notmatch '^https://github\.com/[A-Za-z0-9._-]{1,100}/[A-Za-z0-9._-]{1,100}/?$') {
    throw "저장소 URL은 https://github.com/<owner>/<repo> 형식이어야 합니다: $RepoUrl"
}
if (-not $PublicKeyPath) { $PublicKeyPath = $env:SHIELD_PUBKEY_PATH }
if (-not $PublicKeyPath) { $PublicKeyPath = Join-Path $root "keys\release_key.asc" }
$doSign = $false
if ($Sign) { $doSign = $true }
elseif (-not $NoSign) {
    if ($env:SHIELD_SIGN) { $doSign = $env:SHIELD_SIGN -match '^(y|yes|1|true)$' }
    elseif ($canAsk) { $doSign = Ask-YesNo "GPG 서명을 하시겠습니까? / Sign with GPG?" }
}
if (-not $Variants) { $Variants = $env:SHIELD_VARIANTS }
if (-not $Variants) { $Variants = "msi,portable,console" }
$want = @($Variants -split '[,\s]+' | Where-Object { $_ })
foreach ($v in $want) { if ($v -notin @('msi', 'portable', 'console')) { throw "알 수 없는 변형: $v (msi, portable, console)" } }

# public key: embedded in the programs; with -Sign also the signing key
$keyItem = Get-Item -LiteralPath $PublicKeyPath -ErrorAction SilentlyContinue
if (-not $keyItem) { throw "공개키 파일이 없습니다: $PublicKeyPath (업데이트·무결성 검사에 필요)" }
if ($keyItem.Length -le 0 -or $keyItem.Length -gt 1MB) { throw "공개키 파일 크기가 올바르지 않습니다." }
$keyText = [System.IO.File]::ReadAllText($keyItem.FullName)
if ($keyText -match 'PRIVATE KEY BLOCK|SECRET KEY') { throw "이 파일에는 비밀키가 들어 있습니다. 공개키(.asc)만 지정하세요." }
if ($keyText -notmatch '-----BEGIN PGP PUBLIC KEY BLOCK-----') { throw "ASCII 형식 공개키 파일이 아닙니다." }

$script:tmpHome = $null
$script:fpr = $null
try {
    if ($doSign) {
        $script:gpg = Find-Gpg
        $script:msysGpg = $script:gpg -match '\\usr\\bin\\gpg\.exe$'
        $script:tmpHome = Join-Path ([System.IO.Path]::GetTempPath()) ("shield_gpg_" + [guid]::NewGuid().ToString("N"))
        New-Item -ItemType Directory -Path $script:tmpHome | Out-Null
        $null = Invoke-Gpg @('--homedir', (ConvertTo-GpgPath $script:tmpHome), '--batch', '--import', (ConvertTo-GpgPath $keyItem.FullName))
        $cols = Invoke-Gpg @('--homedir', (ConvertTo-GpgPath $script:tmpHome), '--batch', '--with-colons', '--fingerprint', '--list-keys')
        if (@($cols | Where-Object { $_ -match '^pub:' }).Count -ne 1) { throw "공개키 파일에는 키가 정확히 하나 있어야 합니다." }
        $script:fpr = (@($cols | Where-Object { $_ -match '^fpr:' })[0] -split ':')[9]
        if ($script:fpr -notmatch '^[0-9A-F]{40}([0-9A-F]{24})?$') { throw "지문을 읽을 수 없습니다." }
        Write-Host "서명 키 지문 : $($script:fpr)" -ForegroundColor Cyan
        if ($canAsk -and -not $Sign -and -not (Ask-YesNo "이 키로 서명하시겠습니까?")) { throw "서명 키를 확인하지 않아 중단했습니다." }
        $secArgs = @('--batch', '--with-colons', '--list-secret-keys', $script:fpr)
        if ($GpgHome) { $secArgs = @('--homedir', (ConvertTo-GpgPath $GpgHome)) + $secArgs }
        $sec = Invoke-Gpg $secArgs -AllowFail
        if ($LASTEXITCODE -ne 0 -or -not ($sec | Where-Object { $_ -match '^sec:' })) { throw "이 지문의 비밀키가 로컬 키링에 없습니다: $($script:fpr)" }
    }

    $cargoBin = Join-Path $env:USERPROFILE ".cargo\bin"
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue) -and (Test-Path (Join-Path $cargoBin "cargo.exe"))) { $env:PATH = "$cargoBin;$env:PATH" }
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) { throw "Cargo를 찾을 수 없습니다." }
    if (('msi' -in $want) -and -not (Get-Command dotnet -ErrorAction SilentlyContinue)) { throw ".NET SDK가 필요합니다 (WiX)." }
    $versionLine = Select-String -LiteralPath $manifestPath -Pattern '^\s*version\s*=\s*"(\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?)"' | Select-Object -First 1
    if (-not $versionLine) { throw "Cargo.toml의 version을 읽을 수 없습니다." }
    $version = $versionLine.Matches[0].Groups[1].Value
    # MSI 버전 (3.0.0 §5): Windows Installer는 세 자리만 비교하고 "-beta"를 모릅니다.
    # 정식 X.Y.Z는 그대로, 사전 배포 X.0.0-<태그>.N 은 (X-1).99.N 으로 만들어 정식판이 이를 교체합니다.
    $msiVersion = $version
    if ($version -match '^(\d+)\.(\d+)\.(\d+)-[0-9A-Za-z]+\.(\d+)$') {
        if ([int]$Matches[1] -lt 1 -or [int]$Matches[2] -ne 0 -or [int]$Matches[3] -ne 0) { throw "사전 배포 버전은 X.0.0-<태그>.N 형식만 MSI로 만들 수 있습니다: $version" }
        $msiVersion = "$([int]$Matches[1] - 1).99.$([int]$Matches[4])"
    } elseif ($version -match '-') {
        throw "사전 배포 버전에는 번호가 있어야 합니다 (예: 3.0.0-beta.2): $version"
    }
    $vu = $version -replace '\.', '_'
    if ($UpxPath -and $NoUpx) { throw "-UpxPath와 -NoUpx는 함께 쓸 수 없습니다." }
    if (('portable' -in $want) -and -not $UpxPath -and -not $NoUpx -and $canAsk) { $UpxPath = Read-Host "포터블 exe를 UPX로 압축하려면 upx.exe 경로 (아니면 Enter)" }
    $script:upxExe = $null
    if ($UpxPath) {
        $UpxPath = ($UpxPath.Trim() -replace '^&\s*', '').Trim().Trim('"').Trim("'")
        if (Test-Path -LiteralPath $UpxPath -PathType Container) { $UpxPath = Join-Path $UpxPath "upx.exe" }
        $r = Get-Command $UpxPath -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $r) { throw "UPX를 찾을 수 없습니다: $UpxPath" }
        $script:upxExe = $r.Source
    }
    Write-Host "Shield v$version · 저장소: $(if ($RepoUrl) { $RepoUrl } else { '(없음)' }) · 서명: $doSign · 변형: $($want -join ',') · MSI: $Culture"

    # ------------------------------------------------------------------ 1. tests and builds
    $env:SHIELD_REPO_URL = $RepoUrl
    $env:SHIELD_PUBKEY_PATH = $keyItem.FullName
    if (-not $SkipTests) {
        Step "테스트 (cargo test --workspace --release)"
        & cargo test --workspace --release --manifest-path $manifestPath
        Assert-ExitCode "테스트"
    }
    Step "릴리스 빌드: shield-gui.exe, shield.exe"
    & cargo build --release --manifest-path $manifestPath -p shield-gui -p shield-cli
    Assert-ExitCode "빌드"
    $bin = Join-Path $root "target\release"
    $gui = Join-Path $bin "shield-gui.exe"
    $cli = Join-Path $bin "shield.exe"
    foreach ($f in @($gui, $cli)) { if (-not (Test-Path -LiteralPath $f -PathType Leaf)) { throw "빌드 결과가 없습니다: $f" } }
    $consoleExe = $null
    if ('console' -in $want) {
        Step "콘솔 전용 빌드 (GUI 의존성 없음)"
        & cargo build --release --manifest-path $manifestPath -p shield-cli --no-default-features --target-dir (Join-Path $root "target\console")
        Assert-ExitCode "콘솔 빌드"
        $consoleExe = Join-Path $root "target\console\release\shield.exe"
    }
    # programs are signed before packaging, so the installed copies can check themselves
    if ($doSign) {
        Step "프로그램 서명 (비밀번호는 pinentry 창에 입력)"
        Sign-File $gui
        Sign-File $cli
    } else {
        foreach ($s in @("$gui.sig", "$cli.sig")) { if (Test-Path -LiteralPath $s) { Remove-Item -LiteralPath $s -Force } }
    }

    $distDir = Join-Path $root "dist"
    # earlier release files are kept: moved aside, never deleted
    if ((Test-Path -LiteralPath $distDir) -and (Get-ChildItem -LiteralPath $distDir -Force | Select-Object -First 1)) {
        $old = Join-Path $root ("dist_old_" + (Get-Date -Format 'yyyyMMdd_HHmmss'))
        Move-Item -LiteralPath $distDir -Destination $old
        Write-Host "previous dist moved to $(Split-Path -Leaf $old)"
    }
    if (-not (Test-Path -LiteralPath $distDir)) { New-Item -ItemType Directory -Path $distDir | Out-Null }
    $packages = @()

    # ------------------------------------------------------------------ 2. MSI
    if ('msi' -in $want) {
        Step "MSI ($Culture)"
        $noticePath = if ($Culture -eq 'en-US') { Join-Path $root "docs\en\04_install_notes.txt" } else { Join-Path $root "docs\04_설치_안내.txt" }
        $cp = if ($Culture -eq 'en-US') { 1252 } else { 949 }
        $charset = if ($Culture -eq 'en-US') { 0 } else { 129 }
        $sb = New-Object System.Text.StringBuilder
        # every non-ASCII character is a \uN escape: code page bytes (\'xx) are decoded with the PC's
        # non-Unicode code page by RichEdit and turned into garbage on systems not set to 949
        [void]$sb.Append("{\rtf1\ansi\ansicpg$cp\deff0{\fonttbl{\f0\fnil\fcharset$charset Malgun Gothic;}}\viewkind4\uc1\pard\sa60\f0\fs18 ")
        foreach ($line in ([System.IO.File]::ReadAllText($noticePath, $utf8) -split "`r?`n")) {
            $bold = $line.StartsWith([string][char]0x25A0)
            if ($bold) { [void]$sb.Append('\b\fs20 ') }
            foreach ($ch in $line.ToCharArray()) {
                if ($ch -eq '\' -or $ch -eq '{' -or $ch -eq '}') { [void]$sb.Append('\' + $ch) }
                elseif ([int]$ch -lt 128) { [void]$sb.Append($ch) }
                else {
                    # RTF Unicode escape (signed 16-bit UTF-16 unit) with '?' as fallback
                    $u = [int]$ch; if ($u -gt 32767) { $u -= 65536 }
                    [void]$sb.Append('\u' + $u + '?')
                }
            }
            if ($bold) { [void]$sb.Append('\b0\fs18') }
            [void]$sb.Append("\par`r`n")
        }
        [void]$sb.Append('}')
        $rtfDir = Join-Path $root "target\installer"
        New-Item -ItemType Directory -Force -Path $rtfDir | Out-Null
        $rtf = Join-Path $rtfDir "notice.rtf"
        [System.IO.File]::WriteAllText($rtf, $sb.ToString(), [System.Text.Encoding]::ASCII)
        & dotnet tool restore
        Assert-ExitCode "WiX 복원"
        $prevRf = $env:DOTNET_ROLL_FORWARD
        $env:DOTNET_ROLL_FORWARD = "Major"
        try {
            foreach ($ext in @("WixToolset.UI.wixext", "WixToolset.Util.wixext")) { & dotnet tool run wix -- extension add "$ext/$wixVersion"; Assert-ExitCode "WiX 확장 $ext" }
            $msi = Join-Path $distDir "Shield_v${version}_x64.msi"
            $wxs = Join-Path $root "installer\windows\installer.wxs"
            $wxl = Join-Path $root "installer\windows\installer.$Culture.wxl"
            & dotnet tool run wix -- build -arch x64 -culture $Culture -ext "WixToolset.UI.wixext/$wixVersion" -ext "WixToolset.Util.wixext/$wixVersion" `
                -d "Version=$msiVersion" -d "NoticeRtf=$rtf" -d "Bin=$bin" -d "Signed=$(if ($doSign) { 'yes' } else { 'no' })" -loc $wxl $wxs -o $msi
            Assert-ExitCode "WiX MSI 빌드"
        } finally {
            if ($null -eq $prevRf) { Remove-Item Env:\DOTNET_ROLL_FORWARD -ErrorAction SilentlyContinue } else { $env:DOTNET_ROLL_FORWARD = $prevRf }
        }
        $wixpdb = [System.IO.Path]::ChangeExtension($msi, ".wixpdb")
        if (Test-Path -LiteralPath $wixpdb) { Remove-Item -LiteralPath $wixpdb -Force }
        $packages += $msi
    }

    # ------------------------------------------------------------------ 3. portable builds
    if ('portable' -in $want) {
        # the name ending in "_portable" keeps settings in Shield_data next to the program
        $p = Join-Path $distDir "Shield_v${version}_x64_portable.exe"
        Copy-Item -LiteralPath $gui -Destination $p
        if ($script:upxExe) {
            $before = (Get-PeFlags $p) -band 0x160
            Invoke-Upx @('--best', '--lzma', '--strip-relocs=0', '--no-progress', $p) | Out-Null
            $null = Invoke-Upx @('-t', $p)
            if (((Get-PeFlags $p) -band 0x160) -ne $before) { Remove-Item -LiteralPath $p -Force; throw "UPX 후 ASLR/DEP 플래그가 사라졌습니다." }
        }
        $packages += $p
    }
    if ($consoleExe) {
        $c = Join-Path $distDir "shield-console_v${version}_windows_x64.exe"
        Copy-Item -LiteralPath $consoleExe -Destination $c
        $packages += $c
    }

    # ------------------------------------------------------------------ 4. source zip
    Step "소스 zip"
    Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
    $zipPath = Join-Path $distDir "Shield_Project_v$vu.zip"
    $excludeDirs = @('target', 'dist', '.git', '.vs', '.idea', '.wix', '.claude', '.claude-flow', '.swarm', '.hive-mind', 'node_modules', '_unused')
    $excludeExt = @('.msi', '.wixpdb', '.sig', '.gpg', '.kbx', '.key', '.pem', '.pfx', '.p12', '.zip', '.shd', '.tmp', '.part')
    $files = Get-ChildItem -LiteralPath $root -Recurse -File -Force | Where-Object {
        $rel = $_.FullName.Substring($root.Length + 1)
        $top = ($rel -split '[\\/]')[0]
        # test fixtures (.asc / .sig / .shd) are part of the source; other keys and outputs are not
        $fixture = $rel -match '^crates[\\/]shield-core[\\/]tests[\\/]fixtures[\\/]'
        $pubkey = $rel -match '^keys[\\/][^\\/]+\.asc$'
        -not ($excludeDirs -contains $top) -and -not $top.StartsWith('dist_old_') -and ($fixture -or $pubkey -or -not ($excludeExt -contains $_.Extension.ToLowerInvariant())) -and
        -not ($_.Extension -eq '.asc' -and -not $fixture -and -not $pubkey) -and -not ($_.Name -like '.env*') -and -not ($_.Name -like '.shd_*')
    }
    foreach ($f in $files) { if ([System.IO.File]::ReadAllText($f.FullName) -match '(?m)^-----BEGIN [A-Z0-9 ]*(PRIVATE|SECRET) KEY( BLOCK)?-----') { throw "비밀키가 들어 있는 파일은 zip에 넣지 않습니다: $($f.FullName)" } }
    $zip = [System.IO.Compression.ZipFile]::Open($zipPath, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($f in $files) {
            [void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $f.FullName, $f.FullName.Substring($root.Length + 1).Replace('\', '/'), [System.IO.Compression.CompressionLevel]::Optimal)
        }
    } finally { $zip.Dispose() }
    Write-Host "  $(Split-Path -Leaf $zipPath) ($($files.Count)개 파일)"
    $packages += $zipPath

    # ------------------------------------------------------------------ 5. release manifest (the updater checks it)
    $lines = @{}
    if ($MergeManifest) {
        $m = [System.IO.File]::ReadAllLines($MergeManifest)
        if ($m[0] -ne 'Shield release manifest 1' -or $m[1] -ne "version $version") { throw "합칠 매니페스트의 형식이나 버전이 다릅니다: $MergeManifest" }
        foreach ($l in $m[2..($m.Count - 1)]) { if ($l -match '^sha256 ([0-9a-f]{64}) (\S+)$') { $lines[$Matches[2]] = $l } elseif ($l) { throw "매니페스트 줄 오류: $l" } }
    }
    foreach ($p in $packages) {
        $n = Split-Path -Leaf $p
        $lines[$n] = "sha256 $((Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()) $n"
    }
    $manifest = Join-Path $distDir "Shield_v${version}_release.txt"
    $body = @('Shield release manifest 1', "version $version") + @($lines.Keys | Sort-Object | ForEach-Object { $lines[$_] })
    [System.IO.File]::WriteAllText($manifest, (($body -join "`n") + "`n"), $utf8)

    # ------------------------------------------------------------------ 6. signatures, key, sums
    if ($doSign) {
        Step "배포 파일 서명"
        foreach ($p in $packages + @($manifest)) { Sign-File $p }
        Copy-Item -LiteralPath $keyItem.FullName -Destination (Join-Path $distDir $keyItem.Name)
        $verify = @"
Shield $version - verifying the release / 배포 파일 검증
=========================================================
Key fingerprint / 서명 키 지문: $($script:fpr)
Public key / 공개키 파일: $($keyItem.Name)

1) gpg --import $($keyItem.Name)
2) gpg --fingerprint $($script:fpr)
   Compare with the fingerprint the developer published elsewhere.
   개발자가 다른 경로로 알려 준 지문과 같은지 확인하세요.
3) gpg --verify <file>.sig <file>      (or: shield verify <file> <file>.sig --key $($keyItem.Name))
   "Good signature" + the fingerprint above. "BAD signature": do not install / 설치하지 마세요.
4) SHA256SUMS.txt: Get-FileHash <file> -Algorithm SHA256   /   sha256sum -c SHA256SUMS.txt
"@
        [System.IO.File]::WriteAllText((Join-Path $distDir "VERIFY.txt"), $verify, $utf8Bom)
    }
    $sum = Get-ChildItem -LiteralPath $distDir -File | Where-Object { $_.Name -ne 'SHA256SUMS.txt' } | Sort-Object Name | ForEach-Object {
        "{0}  {1}" -f (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant(), $_.Name
    }
    [System.IO.File]::WriteAllText((Join-Path $distDir "SHA256SUMS.txt"), (($sum -join "`n") + "`n"), $utf8)
    Write-Host "완료 / done: dist\" -ForegroundColor Green
    Get-ChildItem -LiteralPath $distDir -File | Sort-Object Name | ForEach-Object { Write-Host ("  {0,-46} {1,12:N0} bytes" -f $_.Name, $_.Length) }
    if (-not $doSign) { Write-Host "서명 없이 빌드했습니다 (.sig 없음). 업데이트로 배포하려면 서명이 필요합니다." -ForegroundColor Yellow }
}
finally {
    Remove-Item Env:\SHIELD_REPO_URL -ErrorAction SilentlyContinue
    Remove-Item Env:\SHIELD_PUBKEY_PATH -ErrorAction SilentlyContinue
    if ($script:tmpHome -and (Test-Path -LiteralPath $script:tmpHome)) {
        $gpgconf = Join-Path (Split-Path -Parent $script:gpg) "gpgconf.exe"
        if (Test-Path -LiteralPath $gpgconf) { $ErrorActionPreference = 'Continue'; & $gpgconf --homedir (ConvertTo-GpgPath $script:tmpHome) --kill gpg-agent 2>&1 | Out-Null }
        Remove-Item -LiteralPath $script:tmpHome -Recurse -Force -ErrorAction SilentlyContinue
    }
}
