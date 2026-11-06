<#
.SYNOPSIS
    Build and verify the NetGuardian release.

.DESCRIPTION
    Runs the test suite, builds both distributions with PyInstaller
    (portable folder and single file), executes a --version smoke test on
    the portable build, creates ZIP archives and writes SHA256SUMS.txt.

.EXAMPLE
    .\build.ps1
    .\build.ps1 -Clean -SkipTests
#>
[CmdletBinding()]
param(
    [string]$Python = "python",
    [switch]$Clean,
    [switch]$SkipTests
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $root
try {
    if ($Clean) {
        Remove-Item -Recurse -Force build, dist -ErrorAction SilentlyContinue
    }

    # Версия читается из кода, а не дублируется в именах файлов: иначе архивы
    # 3.1.1 разъезжаются с названием "3.1" и получатель не понимает, что получил.
    $versionFile = Join-Path $root "netguardian\__init__.py"
    $versionMatch = Select-String -LiteralPath $versionFile -Pattern '__version__\s*=\s*"([^"]+)"'
    if (-not $versionMatch) { throw "cannot read __version__ from $versionFile" }
    $version = $versionMatch.Matches[0].Groups[1].Value
    Write-Host "      version: $version (netguardian\__init__.py)"

    # Свойства exe (FileVersion/ProductVersion) берутся из того же __version__,
    # иначе они расходятся с `--version`. Так и вышло в 3.1.3: внутри 3.1.3,
    # а в свойствах файла осталось 3.1.1, потому что version_info.txt правили руками.
    $viParts = @($version.Split('.') | ForEach-Object { [int]$_ })
    while ($viParts.Count -lt 4) { $viParts += 0 }
    $viTuple = ($viParts[0..3] -join ', ')
    $viText = @"
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=($viTuple),
    prodvers=($viTuple),
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo(
      [
        StringTable(
          u'040904B0',
          [
            StringStruct(u'CompanyName', u'Svetliak'),
            StringStruct(u'FileDescription', u'NetGuardian - adaptive route manager'),
            StringStruct(u'FileVersion', u'$version.0'),
            StringStruct(u'InternalName', u'NetGuardian'),
            StringStruct(u'LegalCopyright', u'Copyright (c) 2026 Svetliak. MIT License.'),
            StringStruct(u'OriginalFilename', u'NetGuardian.exe'),
            StringStruct(u'ProductName', u'NetGuardian'),
            StringStruct(u'ProductVersion', u'$version.0')
          ]
        )
      ]
    ),
    VarFileInfo([VarStruct(u'Translation', [1033, 1200])])
  ]
)
"@
    Set-Content -LiteralPath (Join-Path $root "packaging\version_info.txt") -Value $viText -Encoding utf8
    Write-Host "      version_info.txt: $viTuple"

    if (-not $SkipTests) {
        Write-Host "[1/5] Compiling sources..."
        & $Python -m compileall -q netguardian guardian.py
        if ($LASTEXITCODE -ne 0) { throw "compileall failed" }

        Write-Host "[2/5] Running the test suite..."
        & $Python -m unittest discover -s tests -t .
        if ($LASTEXITCODE -ne 0) { throw "tests failed" }
    } else {
        Write-Host "[1/5] Skipping compile and tests (-SkipTests)."
        Write-Host "[2/5] Skipping tests (-SkipTests)."
    }

    Write-Host "[3/5] Building the portable distribution..."
    & $Python -m PyInstaller --clean --noconfirm NetGuardian-portable.spec
    if ($LASTEXITCODE -ne 0) { throw "PyInstaller (portable) failed" }

    $portableDir = Join-Path $root "dist\NetGuardian"
    $portableExe = Join-Path $portableDir "NetGuardian.exe"
    if (-not (Test-Path $portableExe)) { throw "dist\NetGuardian\NetGuardian.exe was not produced" }
    Copy-Item "packaging\run.cmd" (Join-Path $portableDir "run.cmd") -Force
    Copy-Item "packaging\UNBLOCK.cmd" (Join-Path $portableDir "UNBLOCK.cmd") -Force
    Copy-Item "packaging\NetGuardian-Repair.cmd" (Join-Path $portableDir "NetGuardian-Repair.cmd") -Force
    Copy-Item "README.md", "README.en.md", "README.en.txt", "CHANGELOG.md", "LICENSE", "NOTICE.txt", "README.txt", "SIGNING.txt" $portableDir -Force
    $portableDocs = Join-Path $portableDir "docs"
    New-Item -ItemType Directory -Force $portableDocs | Out-Null
    Copy-Item "docs\PROJECT.txt", "docs\HOW-IT-WORKS.txt", "docs\RELEASE.txt", "docs\REVIEW.md" $portableDocs -Force

    Write-Host "[4/5] Building the single-file executable..."
    & $Python -m PyInstaller --clean --noconfirm NetGuardian.spec
    if ($LASTEXITCODE -ne 0) { throw "PyInstaller (single file) failed" }

    $exe = Join-Path $root "dist\NetGuardian.exe"
    if (-not (Test-Path $exe)) { throw "dist\NetGuardian.exe was not produced" }
    Copy-Item "README.md", "README.en.md", "README.en.txt", "CHANGELOG.md", "LICENSE", "NOTICE.txt", "README.txt", "SIGNING.txt" (Join-Path $root "dist") -Force
    $distDocs = Join-Path $root "dist\docs"
    New-Item -ItemType Directory -Force $distDocs | Out-Null
    Copy-Item "docs\PROJECT.txt", "docs\HOW-IT-WORKS.txt", "docs\RELEASE.txt", "docs\REVIEW.md" $distDocs -Force
    Copy-Item "packaging\run.cmd" (Join-Path $root "dist\run.cmd") -Force
    Copy-Item "packaging\UNBLOCK.cmd" (Join-Path $root "dist\UNBLOCK.cmd") -Force
    Copy-Item "packaging\NetGuardian-Repair.cmd" (Join-Path $root "dist\NetGuardian-Repair.cmd") -Force

    Write-Host "[5/5] Smoke test and packaging..."
    $banner = & $portableExe --version
    if ($LASTEXITCODE -ne 0) { throw "the portable executable failed --version" }
    Write-Host "      portable: $banner"

    # Защита от расхождения: свойства файла обязаны совпадать с --version.
    $fileVersion = (Get-Item $portableExe).VersionInfo.FileVersion
    $productVersion = (Get-Item $portableExe).VersionInfo.ProductVersion
    Write-Host "      FileVersion: $fileVersion, ProductVersion: $productVersion"
    if (-not $fileVersion.StartsWith($version) -or -not $productVersion.StartsWith($version)) {
        throw "exe version info ($fileVersion / $productVersion) does not match $version"
    }

    $portableZip = Join-Path $root "dist\NetGuardian-$version-portable-win64.zip"
    $singleZip = Join-Path $root "dist\NetGuardian-$version-singlefile-win64.zip"
    if (Test-Path $portableZip) { Remove-Item $portableZip -Force }
    if (Test-Path $singleZip) { Remove-Item $singleZip -Force }
    Compress-Archive -Path (Join-Path $portableDir "*") -DestinationPath $portableZip -CompressionLevel Optimal
    Compress-Archive -Path @(
        $exe,
        (Join-Path $root "dist\README.md"),
        (Join-Path $root "dist\README.en.md"),
        (Join-Path $root "dist\README.en.txt"),
        (Join-Path $root "dist\README.txt"),
        (Join-Path $root "dist\CHANGELOG.md"),
        (Join-Path $root "dist\LICENSE"),
        (Join-Path $root "dist\NOTICE.txt"),
        (Join-Path $root "dist\SIGNING.txt"),
        (Join-Path $root "dist\docs"),
        (Join-Path $root "dist\run.cmd"),
        (Join-Path $root "dist\UNBLOCK.cmd")
    ) -DestinationPath $singleZip -CompressionLevel Optimal

    # Source archive: everything needed to build, review and continue the project.
    $sourceZip = Join-Path $root "dist\NetGuardian-$version-source.zip"
    $sourceStage = Join-Path $root "dist\.source-stage"
    if (Test-Path $sourceZip) { Remove-Item $sourceZip -Force }
    if (Test-Path $sourceStage) { Remove-Item $sourceStage -Recurse -Force }
    New-Item -ItemType Directory $sourceStage | Out-Null
    $sourceItems = @(
        "guardian.py", "README.md", "README.en.md", "README.en.txt", "README.txt",
        "CHANGELOG.md", "LICENSE", "NOTICE.txt", "SIGNING.txt",
        ".gitignore", "pyproject.toml", "requirements-dev.txt", "build.ps1",
        "build-native.ps1", "NATIVE-BUILD.txt",
        "NetGuardian.spec", "NetGuardian-portable.spec",
        "netguardian", "tests", "docs", "packaging", "assets"
    )
    foreach ($item in $sourceItems) {
        Copy-Item (Join-Path $root $item) $sourceStage -Recurse -Force
    }
    Get-ChildItem $sourceStage -Recurse -Directory -Filter "__pycache__" -ErrorAction SilentlyContinue |
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::CreateFromDirectory(
        $sourceStage, $sourceZip,
        [System.IO.Compression.CompressionLevel]::Optimal, $false)
    Remove-Item $sourceStage -Recurse -Force

    $exeHash = (Get-FileHash $exe -Algorithm SHA256).Hash.ToLowerInvariant()
    $singleHash = (Get-FileHash $singleZip -Algorithm SHA256).Hash.ToLowerInvariant()
    $portableHash = (Get-FileHash $portableZip -Algorithm SHA256).Hash.ToLowerInvariant()
    $sourceHash = (Get-FileHash $sourceZip -Algorithm SHA256).Hash.ToLowerInvariant()
    @(
        "$exeHash  NetGuardian.exe",
        "$singleHash  NetGuardian-$version-singlefile-win64.zip",
        "$portableHash  NetGuardian-$version-portable-win64.zip",
        "$sourceHash  NetGuardian-$version-source.zip"
    ) | Set-Content "dist\SHA256SUMS.txt" -Encoding ASCII

    Write-Host ""
    Write-Host "Release ready:"
    Get-ChildItem dist | Select-Object Name, Length | Format-Table -AutoSize
    Write-Host "SHA256 exe      $exeHash"
    Write-Host "SHA256 single   $singleHash"
    Write-Host "SHA256 portable $portableHash"
    Write-Host "SHA256 source   $sourceHash"
} finally {
    Pop-Location
}
