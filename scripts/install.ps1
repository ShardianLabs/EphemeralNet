param(
    [string]$InstallDir
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

if (-not $PSVersionTable.PSVersion) {
    Write-Error 'PowerShell 5+ is required.'
    exit 1
}

if (-not $InstallDir) {
    if ($env:ProgramFiles -and (Test-Path $env:ProgramFiles)) {
        $InstallDir = Join-Path $env:ProgramFiles 'EphemeralNet'
    } else {
        $InstallDir = Join-Path $env:LOCALAPPDATA 'Programs\EphemeralNet'
    }
}

$repoOwner = 'ShardianLabs'
$repoName  = 'EphemeralNet'
$apiUrl    = "https://api.github.com/repos/$repoOwner/$repoName/releases/latest"
$userAgent = 'EphemeralNetInstaller/1.0'

try {
    $release = Invoke-RestMethod -Uri $apiUrl -Headers @{ 'User-Agent' = $userAgent }
} catch {
    Write-Error 'Unable to query GitHub releases. Try again later.'
    exit 1
}

$tag = $release.tag_name
if (-not $tag) {
    Write-Error 'Latest release tag not found.'
    exit 1
}

$arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
switch ($arch) {
    'X64' { $assetName = "eph-$tag-windows-x64.zip" }
    default {
        Write-Error "Unsupported Windows architecture: $arch"
        exit 1
    }
}

$downloadUrl = "https://github.com/$repoOwner/$repoName/releases/download/$tag/$assetName"
$tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("ephemeralnet-" + [System.Guid]::NewGuid())
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
$archivePath = Join-Path $tempDir $assetName

try {
    Invoke-WebRequest -Uri $downloadUrl -OutFile $archivePath -UseBasicParsing
} catch {
    Write-Error "Failed to download $downloadUrl"
    Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    exit 1
}

try {
    Expand-Archive -Path $archivePath -DestinationPath $tempDir -Force
} catch {
    Write-Error 'Unable to extract the downloaded archive.'
    Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    exit 1
}

New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
$destination = Join-Path $InstallDir 'eph.exe'
Copy-Item -Path (Join-Path $tempDir 'eph.exe') -Destination $destination -Force

$pathEntries = ($env:Path -split ';')
if ($pathEntries -notcontains $InstallDir) {
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if ([string]::IsNullOrWhiteSpace($userPath)) {
        $newUserPath = $InstallDir
    } elseif ($userPath -like "*$InstallDir*") {
        $newUserPath = $userPath
    } else {
        $newUserPath = "$userPath;$InstallDir"
    }
    [Environment]::SetEnvironmentVariable('Path', $newUserPath, 'User')
    Write-Host "Added $InstallDir to your user PATH. Open a new PowerShell session to use 'eph' globally."
}

Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "EphemeralNet $tag installed at $destination"
Write-Host "Run 'eph --help' to explore the CLI."
