#Requires -Version 7
<#
.SYNOPSIS
    Installs the SocialName local CLI from a published GitHub Release.

.DESCRIPTION
    Downloads one archive plus the release checksum file, verifies the archive
    against it, and unpacks the binary and its site-rule pack into a user-owned
    directory. It never needs administrator rights, never writes to system
    directories, and never contacts a SocialName service: the local CLI
    defaults to local execution with sync=never.

    irm https://raw.githubusercontent.com/yhay81/socialname/main/scripts/install-cli.ps1 | iex

.PARAMETER Version
    Release tag to install. Defaults to the latest release.

.PARAMETER Prefix
    Install root. Defaults to $env:LOCALAPPDATA\SocialName.
#>
[CmdletBinding()]
param(
    [string]$Version = $(if ($env:SOCIALNAME_VERSION) { $env:SOCIALNAME_VERSION } else { 'latest' }),
    [string]$Prefix = $(if ($env:SOCIALNAME_PREFIX) { $env:SOCIALNAME_PREFIX } else { Join-Path $env:LOCALAPPDATA 'SocialName' })
)

$ErrorActionPreference = 'Stop'
$repository = 'yhay81/socialname'

$architecture = switch ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture) {
    'X64' { 'x86_64' }
    'Arm64' { 'aarch64' }
    default { throw "Unsupported architecture $_; see docs/installation.md" }
}

$target = "$architecture-pc-windows-msvc"
$archive = "socialname-cli-$target.zip"
$base = if ($Version -eq 'latest') {
    "https://github.com/$repository/releases/latest/download"
} else {
    "https://github.com/$repository/releases/download/$Version"
}

$workspace = New-Item -ItemType Directory -Path (Join-Path ([System.IO.Path]::GetTempPath()) ("socialname-" + [guid]::NewGuid()))
try {
    Write-Host "socialname-install: downloading $archive"
    $archivePath = Join-Path $workspace $archive
    Invoke-WebRequest -Uri "$base/$archive" -OutFile $archivePath -UseBasicParsing
    $checksumPath = Join-Path $workspace 'SHA256SUMS.txt'
    Invoke-WebRequest -Uri "$base/SHA256SUMS.txt" -OutFile $checksumPath -UseBasicParsing

    $computed = (Get-FileHash -Path $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $expected = Get-Content $checksumPath |
        Where-Object { $_ -match "\s\*?$([regex]::Escape($archive))$" } |
        ForEach-Object { ($_ -split '\s+')[0].ToLowerInvariant() } |
        Select-Object -First 1
    if (-not $expected) {
        throw "The release checksum file does not list $archive"
    }
    if ($computed -ne $expected) {
        throw "Checksum mismatch for ${archive}; refusing to install"
    }
    Write-Host 'socialname-install: checksum verified'

    Expand-Archive -Path $archivePath -DestinationPath $workspace -Force
    $unpacked = Join-Path $workspace "socialname-$target"
    $binary = Join-Path $unpacked 'socialname.exe'
    if (-not (Test-Path $binary)) {
        throw 'The archive did not contain the expected binary'
    }

    $binDirectory = Join-Path $Prefix 'bin'
    New-Item -ItemType Directory -Path $binDirectory -Force | Out-Null
    Copy-Item -Path $binary -Destination (Join-Path $binDirectory 'socialname.exe') -Force
    $rulesDirectory = Join-Path $Prefix 'rules'
    if (Test-Path $rulesDirectory) {
        Remove-Item -Recurse -Force $rulesDirectory
    }
    Copy-Item -Recurse -Path (Join-Path $unpacked 'rules') -Destination $rulesDirectory

    Write-Host "socialname-install: installed $(Join-Path $binDirectory 'socialname.exe')"
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if ($userPath -notlike "*$binDirectory*") {
        Write-Host 'socialname-install: add it to PATH for this user with'
        Write-Host "  [Environment]::SetEnvironmentVariable('Path', `"$binDirectory;`$([Environment]::GetEnvironmentVariable('Path','User'))`", 'User')"
    }
    Write-Host 'socialname-install: try'
    Write-Host "  socialname rules list --rules-dir $rulesDirectory\sites"
    Write-Host "  socialname search octocat --site github --rules-dir $rulesDirectory\sites --allow-disabled"
} finally {
    Remove-Item -Recurse -Force $workspace -ErrorAction SilentlyContinue
}
