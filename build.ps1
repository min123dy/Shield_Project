#requires -Version 5.1
# Build shield.exe, run the tests and package Shield.msi (with installer UI).
# Saved as UTF-8 with BOM for Windows PowerShell 5.1 compatibility.
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
$wixVersion = "5.0.2"

foreach ($required in @($manifestPath, $toolManifestPath, $guidePath, $noticePath, $installerPath, $locPath)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "필수 파일이 없습니다: $required"
    }
}

# Rust is often installed by rustup without touching PATH of the current session.
$cargoBin = Join-Path $env:USERPROFILE ".cargo\bin"
if (-not (Get-Command cargo -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath (Join-Path $cargoBin "cargo.exe"))) {
    $env:PATH = "$cargoBin;$env:PATH"
}
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    throw "Cargo를 찾을 수 없습니다. Rust stable toolchain을 설치하고 PATH를 확인하세요."
}
if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    throw ".NET SDK를 찾을 수 없습니다. .NET SDK 6 이상을 설치하고 PATH를 확인하세요."
}

# The MSI version always follows Cargo.toml, so every new build upgrades the installed one.
$versionLine = Select-String -LiteralPath $manifestPath -Pattern '^\s*version\s*=\s*"(\d+\.\d+\.\d+)"' | Select-Object -First 1
if (-not $versionLine) {
    throw "Cargo.toml에서 version을 찾을 수 없습니다."
}
$version = $versionLine.Matches[0].Groups[1].Value

# Prevent an old MSI from being mistaken for the result of this build.
if (Test-Path -LiteralPath $msiPath) {
    Remove-Item -LiteralPath $msiPath -Force
}

function Assert-ExitCode([string]$what) {
    if ($LASTEXITCODE -ne 0) {
        throw "$what 실패 (종료 코드: $LASTEXITCODE). 위의 오류를 확인하세요."
    }
}

Write-Host "[1/5] Rust release 빌드 중 (v$version)..."
& cargo build --release --manifest-path $manifestPath
Assert-ExitCode "Cargo 빌드"
if (-not (Test-Path -LiteralPath $exePath -PathType Leaf)) {
    throw "빌드 후 실행 파일을 찾을 수 없습니다: $exePath"
}

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
    if ($null -eq $previousRollForward) {
        Remove-Item Env:\DOTNET_ROLL_FORWARD -ErrorAction SilentlyContinue
    } else {
        $env:DOTNET_ROLL_FORWARD = $previousRollForward
    }
}
if (-not (Test-Path -LiteralPath $msiPath -PathType Leaf)) {
    throw "WiX가 성공 코드를 반환했지만 MSI 파일이 없습니다: $msiPath"
}
$msi = Get-Item -LiteralPath $msiPath
if ($msi.Length -le 0) {
    throw "생성된 MSI 파일 크기가 0바이트입니다."
}
$hash = (Get-FileHash -LiteralPath $msiPath -Algorithm SHA256).Hash

Write-Host "완료: $msiPath (v$version, $($msi.Length) bytes)" -ForegroundColor Green
Write-Host "SHA-256: $hash"
