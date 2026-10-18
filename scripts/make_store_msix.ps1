# Builds the Microsoft Store package of r7z from package/store and a `store` build of the
# programs. The package is not signed: Partner Center signs it when it is published.
#
#   cargo build --release --target-dir target/store -p r7z -p r7z-gui -p r7z-shell --features r7z-gui/store,r7z-shell/store
#   pwsh scripts/make_store_msix.ps1 -Version 0.1.8 -BinDir target/store/release -Out target/store/r7z-0.1.8-store.msix
param(
    [Parameter(Mandatory)][string]$Version,
    [Parameter(Mandatory)][string]$BinDir,
    [Parameter(Mandatory)][string]$Out
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$work = Join-Path ([IO.Path]::GetTempPath()) "r7z-store-$PID"
$stage = Join-Path $work "package"
Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
New-Item -ItemType Directory $stage | Out-Null
Copy-Item (Join-Path $root "package/store/AppxManifest.xml") $stage
Copy-Item -Recurse (Join-Path $root "package/store/Assets") $stage
foreach ($f in "r7z.exe", "r7z-gui.exe", "r7z_shell.dll") {
    Copy-Item (Join-Path $BinDir $f) $stage
}
Copy-Item (Join-Path $root "LICENSE") $stage

# The Store wants the fourth version part to be 0.
$manifest = Join-Path $stage "AppxManifest.xml"
[xml]$xml = Get-Content -Raw $manifest
$xml.Package.Identity.Version = "$Version.0"
$xml.Save($manifest)

$sdk = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\makeappx.exe" |
    Sort-Object FullName | Select-Object -Last 1
if (-not $sdk) { throw "makeappx.exe not found; install the Windows SDK" }
$makepri = Join-Path $sdk.DirectoryName "makepri.exe"

# resources.pri maps the logos' scale and target-size variants to the names in the manifest.
$config = Join-Path $work "priconfig.xml"
& $makepri createconfig /cf $config /dq en-US /pv 10.0.0 /o | Out-Null
if ($LASTEXITCODE -ne 0) { throw "makepri createconfig failed" }
& $makepri new /pr $stage /cf $config /mn $manifest /of (Join-Path $stage "resources.pri") /o | Out-Null
if ($LASTEXITCODE -ne 0) { throw "makepri new failed" }

New-Item -ItemType Directory -Force (Split-Path -Parent $Out) | Out-Null
& $sdk.FullName pack /d $stage /p $Out /o
if ($LASTEXITCODE -ne 0) { throw "makeappx failed" }
Remove-Item -Recurse -Force $work
Write-Output "built $Out ($((Get-Item $Out).Length) bytes)"
