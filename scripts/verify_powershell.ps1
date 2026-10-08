param(
    [Parameter(Mandatory = $true)]
    [string] $PackageRoot
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath $PackageRoot).Path
$binary = Join-Path $root 'gs.exe'
$init = Join-Path $root 'shell/gs-init.ps1'
$completion = Join-Path $root 'gs.ps1'

if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) {
    throw "GS6 binary is missing: $binary"
}

. $init
. $completion

if ((Get-Command gs -ErrorAction Stop).CommandType -ne 'Function') {
    throw 'gs PowerShell shell-init did not create a function'
}

gs system proxy on --yes | Out-Null
if ($env:http_proxy -ne 'http://127.0.0.1:7890') {
    throw "proxy environment effect was not applied: $env:http_proxy"
}
gs system proxy off --yes | Out-Null
if (Test-Path Env:http_proxy) {
    throw 'proxy environment effect was not removed'
}

$nav = Join-Path $HOME 'code/github/global_scripts'
New-Item -ItemType Directory -Path $nav -Force | Out-Null
Push-Location $env:TEMP
try {
    gs navigator global-scripts | Out-Null
    if ((Get-Location).Path -ne (Resolve-Path -LiteralPath $nav).Path) {
        throw "navigator did not change PowerShell location: $(Get-Location)"
    }
} finally {
    Pop-Location
}

$candidates = @(& $binary __complete plugin info android app)
if (-not ($candidates | Where-Object { $_ -match '^list-3rd\t.+' })) {
    throw 'PowerShell multi-level completion descriptions are missing'
}

Write-Host 'GS6 PowerShell integration: PASS'
