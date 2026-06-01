#Requires -Version 5.1
<#
.SYNOPSIS
    Pre-commit secret scan for the BitNet project.

.DESCRIPTION
    Scans staged (pre-commit) or committed (CI) files for potential
    hardcoded secrets.  Allowed test-password literals from
    .cargo/security.yaml are explicitly whitelisted so that test
    fixtures do not trigger false positives.

    Exit code
      0  – no potential secrets found
      1  – one or more suspicious patterns matched

.PARAMETER CI
    When set, the script scans files in the *last commit*
    (git diff-tree) instead of staged files.
    Use this mode in GitHub Actions / CI pipelines.

.EXAMPLE
    .\scripts\pre-commit-secret-scan.ps1          # local pre-commit
    .\scripts\pre-commit-secret-scan.ps1 -CI     # CI mode
#>

param(
    [switch]$CI
)

$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Allowed test-password literals (keep in sync with .cargo/security.yaml)
# ---------------------------------------------------------------------------
$Allowed = @(
    # string literals used in tests
    '"master"'
    '"password"'
    '"master_password"'
    '"cli_test_password"'
    '"pass"'
    '"pass1"'
    '"pass2"'
    '"secret123"'
    '"p"'
    # raw byte-string literals used in tests
    'b"master"'
    'b"password"'
    'b"master_password"'
    'b"cli_test_password"'
    'b"pass"'
    'b"pass1"'
    'b"pass2"'
    'b"secret123"'
    'b"p"'
)

# ---------------------------------------------------------------------------
# Determine file scope
# ---------------------------------------------------------------------------
if ($CI) {
    $files = git diff-tree --no-commit-id --name-only -r HEAD
} else {
    $files = git diff --cached --name-only
}

if (-not $files) {
    Write-Host "[INFO] No files to scan."
    exit 0
}

# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------
$Patterns = @(
    # variable/property assignment with secret-looking value
    '(?i)(password|passwd|pwd|secret|api_key|apikey|token|auth)\s*=\s*["''`]([^"''`]{4,})["''`]'
    # YAML/JSON key-value
    '(?i)(password|passwd|pwd|secret|api_key|apikey|token|auth)\s*:\s*["''`]([^"''`]{4,})["''`]'
    # hard-coded base64 that could be a key
    '(?i)b64_decode\s*\(\s*["''`][A-Za-z0-9+/=]{20,}["''`]\s*\)'
    # PEM private key block
    '-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'
)

$Found = $false

foreach ($f in $files) {
    if (-not (Test-Path $f)) { continue }
    if ($f -notmatch '\.(rs|cs|js|json|yaml|yml|ps1|toml)$') { continue }

    $content = Get-Content $f -Raw

    foreach ($pat in $Patterns) {
        foreach ($m in [regex]::Matches($content, $pat)) {
            $value = $m.Value

            # Skip whitelisted literals
            $isAllowed = $false
            foreach ($a in $Allowed) {
                if ($value -like "*$a*") {
                    $isAllowed = $true
                    break
                }
            }

            if (-not $isAllowed) {
                Write-Host "POTENTIAL SECRET in $f`: $value" -ForegroundColor Yellow
                $Found = $true
            }
        }
    }
}

if ($Found) {
    Write-Host ""
    Write-Host "[FAIL] Potential secrets detected." -ForegroundColor Red
    Write-Host "       If these are legitimate test fixtures, add the literal to the Allowed list in:" -ForegroundColor Red
    Write-Host "       scripts/pre-commit-secret-scan.ps1" -ForegroundColor Red
    exit 1
} else {
    Write-Host "[OK] No potential secrets detected in scoped files." -ForegroundColor Green
    exit 0
}
