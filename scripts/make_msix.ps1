# Builds r7z-shell.msix, the sparse package that puts r7z in Windows 11's main context
# menu, from package/ with the release version and the signing certificate's subject as
# publisher (Windows installs the package only when the two match).
#
#   pwsh scripts/make_msix.ps1 -Version 0.1.3 -Publisher "CN=..., O=..., C=US" -Out target/release/r7z-shell.msix
param(
    [Parameter(Mandatory)][string]$Version,
    [Parameter(Mandatory)][string]$Publisher,
    [Parameter(Mandatory)][string]$Out
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$stage = Join-Path ([IO.Path]::GetTempPath()) "r7z-msix-$PID"
Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue
Copy-Item -Recurse (Join-Path $root "package") $stage

$manifest = Join-Path $stage "AppxManifest.xml"
[xml]$xml = Get-Content -Raw $manifest
$identity = $xml.Package.Identity
$identity.Version = "$Version.0"
$identity.Publisher = $Publisher
$xml.Save($manifest)

# makeappx comes with the Windows SDK; take the newest one installed.
$makeappx = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\makeappx.exe" |
    Sort-Object FullName | Select-Object -Last 1
if (-not $makeappx) { throw "makeappx.exe not found; install the Windows SDK" }

# /nv: a sparse package's executables live in the install folder, not in the package.
New-Item -ItemType Directory -Force (Split-Path -Parent $Out) | Out-Null
& $makeappx.FullName pack /d $stage /p $Out /nv /o
if ($LASTEXITCODE -ne 0) { throw "makeappx failed" }
Remove-Item -Recurse -Force $stage
Write-Output "built $Out ($((Get-Item $Out).Length) bytes)"
