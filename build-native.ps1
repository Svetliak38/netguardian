<#
.SYNOPSIS
    Build the native (Nuitka) NetGuardian distribution.

.DESCRIPTION
    Compiles the Python package to C with Nuitka and produces a standalone
    folder in dist-native\NetGuardian. Unlike the PyInstaller build, the result
    contains no PYZ archive and no Python bytecode that can be extracted with
    pyi-archive_viewer.

    This raises the cost of reverse engineering. It does NOT prevent copying
    the folder or the executable, and it is not a license/activation system.

    Prerequisites:
      python -m pip install nuitka
      a C toolchain:
        - MSVC (Visual Studio Build Tools with C++), or
        - MinGW64 (Nuitka can download it with -Compiler mingw64), or
        - Zig on PATH (use -Compiler zig).

.EXAMPLE
    .\build-native.ps1 -Compiler zig
    .\build-native.ps1 -Compiler mingw64
    .\build-native.ps1 -Compiler msvc
#>
[CmdletBinding()]
param(
    [string]$Python = "python",
    [ValidateSet("auto", "msvc", "mingw64", "zig")]
    [string]$Compiler = "auto",
    [switch]$Clean
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $root
try {
    if ($Clean) {
        Remove-Item -Recurse -Force "dist-native" -ErrorAction SilentlyContinue
    }

    $version = (& $Python -c "import netguardian; print(netguardian.__version__)").Trim()
    if ($LASTEXITCODE -ne 0) { throw "cannot read netguardian.__version__" }
    Write-Host "Building native NetGuardian $version with Nuitka..."

    & $Python -m nuitka --version *> $null
    if ($LASTEXITCODE -ne 0) {
        throw "Nuitka is not installed. Run: $Python -m pip install nuitka"
    }

    if (-not $env:NUITKA_CACHE_DIR) {
        $env:NUITKA_CACHE_DIR = Join-Path $root ".nuitka-cache"
    }

    $arguments = @(
        "--standalone",
        "--windows-console-mode=force",
        "--assume-yes-for-downloads",
        "--output-dir=dist-native",
        "--output-filename=NetGuardian.exe",
        "--windows-icon-from-ico=assets\netguardian.ico",
        "--company-name=Svetliak",
        "--product-name=NetGuardian",
        "--file-version=$version",
        "--product-version=$version",
        "--file-description=NetGuardian - adaptive route manager"
    )
    switch ($Compiler) {
        "msvc" { $arguments += "--msvc=latest" }
        "mingw64" { $arguments += "--mingw64" }
        "zig" { $arguments += "--zig" }
        default { }
    }
    $arguments += "guardian.py"

    & $Python -m nuitka @arguments
    if ($LASTEXITCODE -ne 0) { throw "Nuitka build failed" }

    $built = Get-ChildItem "dist-native" -Directory -Filter "*.dist" |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $built) { throw "Nuitka did not produce a .dist folder" }

    $target = Join-Path $root "dist-native\NetGuardian"
    if (Test-Path $target) { Remove-Item -Recurse -Force $target }
    Move-Item $built.FullName $target

    Copy-Item "packaging\run.cmd" (Join-Path $target "run.cmd") -Force
    Copy-Item "packaging\UNBLOCK.cmd" (Join-Path $target "UNBLOCK.cmd") -Force
    Copy-Item "README.md", "README.en.md", "README.en.txt", "README.txt",
              "CHANGELOG.md", "LICENSE", "NOTICE.txt", "NATIVE-BUILD.txt", "SIGNING.txt" $target -Force
    $docs = Join-Path $target "docs"
    New-Item -ItemType Directory -Force $docs | Out-Null
    Copy-Item "docs\PROJECT.txt", "docs\HOW-IT-WORKS.txt", "docs\RELEASE.txt",
              "docs\REVIEW.md" $docs -Force

    $nativeExe = Join-Path $target "NetGuardian.exe"
    $banner = & $nativeExe --version
    if ($LASTEXITCODE -ne 0) { throw "the native executable failed --version" }
    Write-Host "Native build OK: $banner"

    $zip = Join-Path $root "dist-native\NetGuardian-$version-native-win64.zip"
    if (Test-Path $zip) { Remove-Item $zip -Force }
    Compress-Archive -Path (Join-Path $target "*") -DestinationPath $zip -CompressionLevel Optimal
    $hash = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-Host "ZIP: $zip"
    Write-Host "SHA256: $hash"
} finally {
    Pop-Location
}
