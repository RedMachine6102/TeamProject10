# Build the VaultMind C++ core into build\vaultcore.dll on Windows.
# Requires g++ (MSYS2 UCRT64) and OpenSSL. See README for the one-time setup.
#
# Run from an MSYS2 UCRT64 shell is preferred; this PowerShell wrapper assumes
# g++ and OpenSSL are on PATH (e.g. C:\msys64\ucrt64\bin).
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
New-Item -ItemType Directory -Force -Path "$root\build" | Out-Null

g++ -O2 -Wall -std=c++17 -shared `
    "$root\core\vault_core.cpp" `
    -lcrypto `
    -o "$root\build\vaultcore.dll"

# copy OpenSSL + runtime DLLs next to the core so ctypes can load it
$ucrt = "C:\msys64\ucrt64\bin"
foreach ($dll in @("libcrypto-3-x64.dll","libgcc_s_seh-1.dll","libstdc++-6.dll","libwinpthread-1.dll")) {
    if (Test-Path "$ucrt\$dll") { Copy-Item "$ucrt\$dll" "$root\build\" -Force }
}
Write-Host "Built build\vaultcore.dll"
