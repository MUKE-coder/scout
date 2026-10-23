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

  # --- add to the FRONT of user PATH ----------------------------------------
  # Prepend, so this install wins over any older scout (e.g. one from
  # `go install` in %USERPROFILE%\go\bin) that would otherwise shadow it.
  $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
  $clean = ($userPath -split ';' | Where-Object { $_ -and $_ -ne $dir }) -join ';'
  [Environment]::SetEnvironmentVariable("Path", "$dir;$clean", "User")
  Say "Added $dir to the front of your user PATH (restart your terminal to pick it up)"
  $env:Path = "$dir;$env:Path"

  & (Join-Path $dir "scout.exe") version

  # Warn about an older scout that may shadow this one in existing terminals.
  $gobin = Join-Path $env:USERPROFILE "go\bin\scout.exe"
  if (Test-Path $gobin) {
    Write-Host "note: another scout exists at $gobin" -ForegroundColor Yellow
    Write-Host "      open a NEW terminal so this install wins, or remove the old one, or run:" -ForegroundColor Yellow
    Write-Host "      go install github.com/$repo/cmd/scout@latest   (updates that copy too)" -ForegroundColor Yellow
  }
  Say "Done. Open a new terminal, then:  scout scan --target http://localhost:3000"
}
finally {
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
