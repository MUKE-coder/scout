# Scout installer for Windows (PowerShell).
#   irm https://scout.codetotech.com/install.ps1 | iex
#
# Downloads the latest prebuilt binary from GitHub releases and installs it to
# %LOCALAPPDATA%\Scout\bin, adding that to your user PATH.
$ErrorActionPreference = "Stop"

$repo = "MUKE-coder/scout"

function Say($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Die($m) { Write-Host "error: $m" -ForegroundColor Red; exit 1 }

# --- detect architecture ----------------------------------------------------
$arch = switch ($env:PROCESSOR_ARCHITECTURE) {
  "AMD64" { "amd64" }
  "ARM64" { "arm64" }
  default { Die "unsupported architecture: $($env:PROCESSOR_ARCHITECTURE)" }
}
$asset = "scout_windows_$arch.zip"

if ($env:SCOUT_VERSION) {
  $url = "https://github.com/$repo/releases/download/$($env:SCOUT_VERSION)/$asset"
} else {
  $url = "https://github.com/$repo/releases/latest/download/$asset"
}

# --- download & extract -----------------------------------------------------
$tmp = Join-Path $env:TEMP ("scout-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
try {
  Say "Downloading $asset"
  $zip = Join-Path $tmp $asset
  Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
  Expand-Archive -Path $zip -DestinationPath $tmp -Force

  $dir = Join-Path $env:LOCALAPPDATA "Scout\bin"
  New-Item -ItemType Directory -Path $dir -Force | Out-Null
  Copy-Item -Path (Join-Path $tmp "scout.exe") -Destination (Join-Path $dir "scout.exe") -Force
  Say "Installed scout.exe to $dir"

  # --- add to user PATH -----------------------------------------------------
  $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
  if ($userPath -notlike "*$dir*") {
    [Environment]::SetEnvironmentVariable("Path", "$userPath;$dir", "User")
    Say "Added $dir to your user PATH (restart your terminal to pick it up)"
  }
  $env:Path = "$env:Path;$dir"

  & (Join-Path $dir "scout.exe") version
  Say "Done. Try:  scout scan --target http://localhost:3000"
}
finally {
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
