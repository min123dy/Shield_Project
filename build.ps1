#requires -Version 5.1
# Build shield.exe, run the tests, package Shield.msi and collect the release files in dist\.
# Optional GPG detached signatures (.sig) for the source zip and the MSI.
#   .\build.ps1                                  asks "GPG 서명을 하시겠습니까?"
#   .\build.ps1 -NoSign                          no signing (everything else identical)
#   .\build.ps1 -Sign -PublicKeyPath key.asc     sign with the key whose public part is key.asc
#   -GpgHome <dir>                               keyring holding the secret key (default: gpg's own)
# The passphrase is never passed as an argument or logged: gpg-agent / pinentry asks for it.
# Saved as UTF-8 with BOM for Windows PowerShell 5.1 compatibility.
[CmdletBinding()]
param(
    [switch]$Sign,
    [switch]$NoSign,
    [string]$PublicKeyPath,
    [string]$GpgHome
)
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding
Set-Location -LiteralPath $PSScriptRoot

$manifestPath = Join-Path $PSScriptRoot "Cargo.toml"
$toolManifestPath = Join-Path $PSScriptRoot ".config\dotnet-tools.json"
$guidePath = Join-Path $PSScriptRoot "docs\03_사용_방법.txt"
$noticePath = Join-Path $PSScriptRoot "docs\04_설치_안내.txt"
$installerPath = Join-Path $PSScriptRoot "installer.wxs"
$locPath = Join-Path $PSScriptRoot "installer.ko-KR.wxl"
$exePath = Join-Path $PSScriptRoot "target\release\shield.exe"
$rtfDir = Join-Path $PSScriptRoot "target\installer"
$rtfPath = Join-Path $rtfDir "notice.rtf"
$msiPath = Join-Path $PSScriptRoot "Shield.msi"
$distDir = Join-Path $PSScriptRoot "dist"
$wixVersion = "5.0.2"
$utf8Bom = New-Object System.Text.UTF8Encoding($true)

function Assert-ExitCode([string]$what) {
    if ($LASTEXITCODE -ne 0) {
        throw "$what 실패 (종료 코드: $LASTEXITCODE). 위의 오류를 확인하세요."
    }
}

function Ask-YesNo([string]$question) {
    $a = Read-Host "$question (y/N)"
    return ($a -match '^\s*(y|yes|예|네|ㅇ)\s*$')
}

function Find-Gpg {
    $native = @(
        (Join-Path ${env:ProgramFiles(x86)} "GnuPG\bin\gpg.exe"),
        (Join-Path $env:ProgramFiles "GnuPG\bin\gpg.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "Gpg4win\bin\gpg.exe"),
        (Join-Path $env:ProgramFiles "Gpg4win\bin\gpg.exe")
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) } | Select-Object -First 1
    $cmd = Get-Command gpg.exe -ErrorAction SilentlyContinue | Select-Object -First 1
    # Git for Windows ships an MSYS gpg (usr\bin); prefer a native Gpg4win build when both exist.
    if ($cmd -and -not ($native -and $cmd.Source -match '\\usr\\bin\\gpg\.exe$')) { return $cmd.Source }
    if ($native) { return $native }
    if ($cmd) { return $cmd.Source }
    throw "gpg.exe를 찾을 수 없습니다. Gpg4win(https://gpg4win.org)을 설치한 뒤 다시 실행하거나 -NoSign으로 실행하세요."
}

# MSYS gpg (Git for Windows) only understands /c/... paths; native gpg takes Windows paths.
function ConvertTo-GpgPath([string]$path) {
    if ($script:msysGpg -and $path -match '^([A-Za-z]):[\\/](.*)$') {
        return '/' + $Matches[1].ToLowerInvariant() + '/' + ($Matches[2] -replace '\\', '/')
    }
    return $path
}

# Runs gpg with the given arguments; returns stdout lines. Never receives a passphrase.
function Invoke-Gpg([string[]]$gpgArgs, [switch]$AllowFail) {
    # gpg prints normal progress on stderr; in PowerShell 5.1 that must not count as an error.
    $ErrorActionPreference = 'Continue'
    $out = & $script:gpg @gpgArgs 2>&1 | ForEach-Object { "$_" }
    if (-not $AllowFail -and $LASTEXITCODE -ne 0) {
        throw "gpg 실행 실패 (종료 코드 $LASTEXITCODE): $($out -join ' | ')"
    }
    return $out
}

# ------------------------------------------------------------------ 0. signing decision + key checks
if ($Sign -and $NoSign) { throw "-Sign과 -NoSign은 함께 쓸 수 없습니다." }
$doSign = $false
$interactive = $false
if ($Sign) { $doSign = $true }
elseif (-not $NoSign) {
    $interactive = $true
    $doSign = Ask-YesNo "GPG 서명을 하시겠습니까?"
}
if ($NoSign -and $PublicKeyPath) { Write-Warning "-NoSign이 지정되어 -PublicKeyPath는 무시합니다." }

$tmpHome = $null
$fpr = $null
$keyCopyName = $null
try {
    if ($doSign) {
        $script:gpg = Find-Gpg
        $script:msysGpg = $script:gpg -match '\\usr\\bin\\gpg\.exe$'
        Write-Host "gpg: $script:gpg"
        if (-not $PublicKeyPath) {
            $interactive = $true
            $PublicKeyPath = (Read-Host "공개키 .asc 파일 경로").Trim().Trim('"')
        }
        if (-not $PublicKeyPath -or -not (Test-Path -LiteralPath $PublicKeyPath -PathType Leaf)) {
            throw "공개키 파일이 없습니다: $PublicKeyPath"
        }
        $keyItem = Get-Item -LiteralPath $PublicKeyPath
        if ($keyItem.Length -le 0 -or $keyItem.Length -gt 1MB) { throw "공개키 파일 크기가 올바르지 않습니다 ($($keyItem.Length) bytes)." }
        $keyText = [System.IO.File]::ReadAllText($keyItem.FullName)
        if ($keyText -match 'PRIVATE KEY BLOCK|SECRET KEY') {
            throw "이 파일에는 비밀키가 들어 있습니다. 비밀키는 절대 배포하거나 빌드에 넘기지 마세요. 공개키만 내보낸 .asc를 지정하세요 (gpg --armor --export <지문>)."
        }
        if ($keyText -notmatch '-----BEGIN PGP PUBLIC KEY BLOCK-----') {
            throw "ASCII 형식(-----BEGIN PGP PUBLIC KEY BLOCK-----) 공개키 파일이 아닙니다."
        }

        # temporary keyring with only this public key
        $tmpHome = Join-Path ([System.IO.Path]::GetTempPath()) ("shield_gpg_" + [guid]::NewGuid().ToString("N"))
        New-Item -ItemType Directory -Path $tmpHome | Out-Null
        $shown = Invoke-Gpg @('--homedir', (ConvertTo-GpgPath $tmpHome), '--batch', '--with-colons', '--show-keys', (ConvertTo-GpgPath $keyItem.FullName))
        if ($shown | Where-Object { $_ -match '^(sec|ssb):' }) { throw "이 파일에는 비밀키가 들어 있습니다. 공개키만 지정하세요." }
        $null = Invoke-Gpg @('--homedir', (ConvertTo-GpgPath $tmpHome), '--batch', '--import', (ConvertTo-GpgPath $keyItem.FullName))
        $cols = Invoke-Gpg @('--homedir', (ConvertTo-GpgPath $tmpHome), '--batch', '--with-colons', '--fingerprint', '--list-keys')
        $pubs = @($cols | Where-Object { $_ -match '^pub:' })
        if ($pubs.Count -ne 1) { throw "공개키 파일에는 키가 정확히 하나 있어야 합니다 (발견: $($pubs.Count)개)." }
        $fpr = (@($cols | Where-Object { $_ -match '^fpr:' })[0] -split ':')[9]
        $uids = @($cols | Where-Object { $_ -match '^uid:' } | ForEach-Object { ($_ -split ':')[9] })
        if (-not $fpr -or $fpr -notmatch '^[0-9A-F]{40}([0-9A-F]{24})?$') { throw "지문을 읽을 수 없습니다." }
        Write-Host ""
        Write-Host "서명 키 지문 : $fpr" -ForegroundColor Cyan
        foreach ($u in $uids) { Write-Host "사용자 ID    : $u" -ForegroundColor Cyan }
        if ($interactive -and -not (Ask-YesNo "이 키로 서명하시겠습니까?")) { throw "사용자가 서명 키를 확인하지 않아 중단했습니다." }

        # the matching secret key must be in the local keyring
        $secArgs = @('--batch', '--with-colons', '--list-secret-keys', $fpr)
        if ($GpgHome) { $secArgs = @('--homedir', (ConvertTo-GpgPath $GpgHome)) + $secArgs }
        $sec = Invoke-Gpg $secArgs -AllowFail
        if ($LASTEXITCODE -ne 0 -or -not ($sec | Where-Object { $_ -match '^sec:' })) {
            throw "이 지문의 비밀키가 로컬 키링에 없습니다: $fpr"
        }
        $keyCopyName = $keyItem.Name
    }

    # ------------------------------------------------------------------ 1-5. build, test, MSI
    foreach ($required in @($manifestPath, $toolManifestPath, $guidePath, $noticePath, $installerPath, $locPath)) {
        if (-not (Test-Path -LiteralPath $required -PathType Leaf)) { throw "필수 파일이 없습니다: $required" }
    }
    # Rust is often installed by rustup without touching PATH of the current session.
    $cargoBin = Join-Path $env:USERPROFILE ".cargo\bin"
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath (Join-Path $cargoBin "cargo.exe"))) {
        $env:PATH = "$cargoBin;$env:PATH"
    }
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) { throw "Cargo를 찾을 수 없습니다. Rust stable toolchain을 설치하고 PATH를 확인하세요." }
    if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) { throw ".NET SDK를 찾을 수 없습니다. .NET SDK 6 이상을 설치하고 PATH를 확인하세요." }

    # The MSI version always follows Cargo.toml, so every new build upgrades the installed one.
    $versionLine = Select-String -LiteralPath $manifestPath -Pattern '^\s*version\s*=\s*"(\d+\.\d+\.\d+)"' | Select-Object -First 1
    if (-not $versionLine) { throw "Cargo.toml에서 version을 찾을 수 없습니다." }
    $version = $versionLine.Matches[0].Groups[1].Value

    # Prevent an old MSI from being mistaken for the result of this build.
    if (Test-Path -LiteralPath $msiPath) { Remove-Item -LiteralPath $msiPath -Force }

    Write-Host "[1/5] Rust release 빌드 중 (v$version)..."
    & cargo build --release --manifest-path $manifestPath
    Assert-ExitCode "Cargo 빌드"
    if (-not (Test-Path -LiteralPath $exePath -PathType Leaf)) { throw "빌드 후 실행 파일을 찾을 수 없습니다: $exePath" }

    Write-Host "[2/5] 테스트 실행 중..."
    & cargo test --release --manifest-path $manifestPath
    Assert-ExitCode "Cargo 테스트"

    Write-Host "[3/5] 프로젝트에 고정된 WiX $wixVersion 도구와 확장 복원 중..."
    & dotnet tool restore
    Assert-ExitCode ".NET local tool 복원"
    # WiX 5.0.2 targets .NET 6; allow it to run on a newer installed .NET runtime if needed.
    $previousRollForward = $env:DOTNET_ROLL_FORWARD
    $env:DOTNET_ROLL_FORWARD = "Major"
    try {
        foreach ($ext in @("WixToolset.UI.wixext", "WixToolset.Util.wixext")) {
            & dotnet tool run wix -- extension add "$ext/$wixVersion"
            Assert-ExitCode "WiX 확장 $ext 설치"
        }

        Write-Host "[4/5] 설치 안내(주의사항/사용법) 화면 생성 중..."
        # RTF for the installer's notice page. The MSI dialog's RichEdit ignores \uN escapes, so
        # non-ASCII text is written WordPad-style as code page 949 bytes (\'hh), matching the MSI.
        $text = [System.IO.File]::ReadAllText($noticePath, [System.Text.Encoding]::UTF8)
        $cp949 = [System.Text.Encoding]::GetEncoding(949)
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.Append('{\rtf1\ansi\ansicpg949\deff0{\fonttbl{\f0\fnil\fcharset129 Malgun Gothic;}}\viewkind4\uc1\pard\sa60\f0\fs18 ')
        foreach ($line in ($text -split "`r?`n")) {
            $bold = $line.StartsWith([string][char]0x25A0)
            if ($bold) { [void]$sb.Append('\b\fs20 ') }
            foreach ($ch in $line.ToCharArray()) {
                $c = [int]$ch
                if ($ch -eq '\' -or $ch -eq '{' -or $ch -eq '}') { [void]$sb.Append('\' + $ch) }
                elseif ($c -lt 128) { [void]$sb.Append($ch) }
                else { foreach ($b in $cp949.GetBytes([string]$ch)) { [void]$sb.Append(("\'{0:x2}" -f $b)) } }
            }
            if ($bold) { [void]$sb.Append('\b0\fs18') }
            [void]$sb.Append("\par`r`n")
        }
        [void]$sb.Append('}')
        New-Item -ItemType Directory -Force -Path $rtfDir | Out-Null
        [System.IO.File]::WriteAllText($rtfPath, $sb.ToString(), [System.Text.Encoding]::ASCII)

        Write-Host "[5/5] x64 MSI 생성 중..."
        & dotnet tool run wix -- build -arch x64 -culture ko-KR `
            -ext "WixToolset.UI.wixext/$wixVersion" -ext "WixToolset.Util.wixext/$wixVersion" `
            -d "Version=$version" -d "NoticeRtf=$rtfPath" `
            -loc installer.ko-KR.wxl installer.wxs -o Shield.msi
        Assert-ExitCode "WiX MSI 빌드"
    }
    finally {
        if ($null -eq $previousRollForward) { Remove-Item Env:\DOTNET_ROLL_FORWARD -ErrorAction SilentlyContinue }
        else { $env:DOTNET_ROLL_FORWARD = $previousRollForward }
    }
    if (-not (Test-Path -LiteralPath $msiPath -PathType Leaf)) { throw "WiX가 성공 코드를 반환했지만 MSI 파일이 없습니다: $msiPath" }
    if ((Get-Item -LiteralPath $msiPath).Length -le 0) { throw "생성된 MSI 파일 크기가 0바이트입니다." }

    # ------------------------------------------------------------------ dist\
    Write-Host "[배포] dist 폴더 구성 중..."
    if (Test-Path -LiteralPath $distDir) { Remove-Item -LiteralPath $distDir -Recurse -Force }
    New-Item -ItemType Directory -Path $distDir | Out-Null

    # Source zip with '/' separators (System.IO.Compression; not Compress-Archive).
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zipName = "Shield_Project_v$version.zip"
    $zipPath = Join-Path $distDir $zipName
    $excludeDirs = @('target', 'dist', '.git', '.vs', '.idea', '.wix', '.claude', '.claude-flow', '.swarm', '.hive-mind', 'node_modules')
    $excludeExt = @('.msi', '.wixpdb', '.sig', '.asc', '.gpg', '.kbx', '.key', '.pem', '.pfx', '.p12', '.zip', '.shd', '.tmp', '.part')
    $root = (Resolve-Path -LiteralPath $PSScriptRoot).Path.TrimEnd('\')
    $files = Get-ChildItem -LiteralPath $root -Recurse -File -Force | Where-Object {
        $rel = $_.FullName.Substring($root.Length + 1)
        $top = ($rel -split '[\\/]')[0]
        -not ($excludeDirs -contains $top) -and
        -not ($excludeExt -contains $_.Extension.ToLowerInvariant()) -and
        -not ($_.Name -like '.env*') -and
        -not ($_.Name -like '.shd_*')
    }
    $zip = [System.IO.Compression.ZipFile]::Open($zipPath, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($f in $files) {
            $entry = $f.FullName.Substring($root.Length + 1).Replace('\', '/')
            [void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $f.FullName, $entry, [System.IO.Compression.CompressionLevel]::Optimal)
        }
    }
    finally { $zip.Dispose() }
    Write-Host "  소스 zip: $zipName ($($files.Count)개 파일)"
    Copy-Item -LiteralPath $msiPath -Destination (Join-Path $distDir "Shield.msi")

    if ($doSign) {
        Write-Host "[서명] GPG 분리 서명 생성 중 (비밀번호는 gpg-agent/pinentry 창에 입력)..."
        $targets = @($zipPath, (Join-Path $distDir "Shield.msi"))
        $sigs = @()
        try {
            foreach ($t in $targets) {
                $sig = "$t.sig"
                $signArgs = @('--local-user', $fpr, '--digest-algo', 'SHA512', '--detach-sign', '--output', (ConvertTo-GpgPath $sig), (ConvertTo-GpgPath $t))
                if ($GpgHome) { $signArgs = @('--homedir', (ConvertTo-GpgPath $GpgHome)) + $signArgs }
                $sigs += $sig
                $null = Invoke-Gpg $signArgs
                # verify with the temporary keyring that holds ONLY the given public key
                $v = Invoke-Gpg @('--homedir', (ConvertTo-GpgPath $tmpHome), '--batch', '--status-fd', '1', '--verify', (ConvertTo-GpgPath $sig), (ConvertTo-GpgPath $t)) -AllowFail
                $good = $LASTEXITCODE -eq 0 -and ($v | Where-Object { $_ -match "^\[GNUPG:\] VALIDSIG .*\b$fpr\b" })
                if (-not $good) { throw "서명 검증 실패: $(Split-Path -Leaf $sig) — $($v -join ' | ')" }
                Write-Host "  서명 확인: $(Split-Path -Leaf $sig)"
            }
        }
        catch {
            foreach ($s in $sigs) { if (Test-Path -LiteralPath $s) { Remove-Item -LiteralPath $s -Force } }
            throw
        }
        Copy-Item -LiteralPath $PublicKeyPath -Destination (Join-Path $distDir $keyCopyName)
        $verify = @"
Shield $version 배포 파일 검증 방법
==================================

서명 키 지문: $fpr
공개키 파일 : $keyCopyName

1) Gpg4win(https://gpg4win.org) 또는 GnuPG를 설치합니다.
2) 공개키를 가져옵니다.
     gpg --import $keyCopyName
3) 지문이 위 값과 같은지, 개발자가 다른 경로(웹사이트, 직접 전달 등)로 알려 준 지문과도 같은지 확인합니다.
     gpg --fingerprint $fpr
4) 서명을 검증합니다. "Good signature(올바른 서명)"와 위 지문이 나와야 합니다.
     gpg --verify Shield.msi.sig Shield.msi
     gpg --verify $zipName.sig $zipName
   "이 키는 신뢰할 수 있는 서명으로 인증되지 않았습니다" 경고는 키를 직접 인증하지 않았다는 뜻이며,
   3)에서 지문을 확인했다면 무시해도 됩니다. "BAD signature"가 나오면 절대 설치하지 마세요.
5) SHA256SUMS.txt의 해시와도 비교할 수 있습니다 (PowerShell):
     Get-FileHash Shield.msi -Algorithm SHA256

참고: Shield.msi에는 Authenticode 코드 서명이 없어 Windows SmartScreen 경고가 뜰 수 있습니다.
무결성 확인은 위의 GPG 서명으로 합니다.
"@
        [System.IO.File]::WriteAllText((Join-Path $distDir "VERIFY.txt"), $verify, $utf8Bom)
    }

    # SHA-256 list of everything in dist\ (always)
    $sumLines = Get-ChildItem -LiteralPath $distDir -File | Sort-Object Name | ForEach-Object {
        "{0}  {1}" -f (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant(), $_.Name
    }
    # LF, no BOM: the format `sha256sum -c` expects
    [System.IO.File]::WriteAllText((Join-Path $distDir "SHA256SUMS.txt"), (($sumLines -join "`n") + "`n"), (New-Object System.Text.UTF8Encoding($false)))

    $msi = Get-Item -LiteralPath $msiPath
    Write-Host "완료: $msiPath (v$version, $($msi.Length) bytes)" -ForegroundColor Green
    Write-Host "SHA-256: $((Get-FileHash -LiteralPath $msiPath -Algorithm SHA256).Hash)"
    Write-Host "dist 산출물:" -ForegroundColor Green
    Get-ChildItem -LiteralPath $distDir -File | Sort-Object Name | ForEach-Object { Write-Host ("  {0,-40} {1,12:N0} bytes" -f $_.Name, $_.Length) }
    if (-not $doSign) { Write-Host "GPG 서명 없이 빌드했습니다 (.sig 없음)." -ForegroundColor Yellow }
}
finally {
    if ($tmpHome -and (Test-Path -LiteralPath $tmpHome)) {
        $gpgconf = Join-Path (Split-Path -Parent $script:gpg) "gpgconf.exe"
        if (Test-Path -LiteralPath $gpgconf) {
            $ErrorActionPreference = 'Continue'
            & $gpgconf --homedir (ConvertTo-GpgPath $tmpHome) --kill gpg-agent 2>&1 | Out-Null
        }
        Remove-Item -LiteralPath $tmpHome -Recurse -Force -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $tmpHome) { Write-Warning "임시 키링을 지우지 못했습니다: $tmpHome (공개키만 들어 있음 — 직접 삭제하세요)" }
    }
}
