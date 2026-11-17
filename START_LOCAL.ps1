$ErrorActionPreference='Stop'
Set-Location -LiteralPath $PSScriptRoot
$venvPython=Join-Path $PSScriptRoot '.venv/Scripts/python.exe'
if (-not (Test-Path -LiteralPath $venvPython)) {
    if (Get-Command py -ErrorAction SilentlyContinue) { & py -3.12 -m venv .venv }
    elseif (Get-Command python -ErrorAction SilentlyContinue) { & python -m venv .venv }
    else { throw 'Install Python 3.12, then rerun START_LOCAL.ps1.' }
    if ($LASTEXITCODE -ne 0) { throw 'Python environment creation failed.' }
    & $venvPython -m pip install -r requirements-reproduction.txt
    if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed. Check network access and rerun pip install -r requirements-reproduction.txt.' }
}
& $venvPython reproduce_round3.py
if ($LASTEXITCODE -ne 0) { throw 'Reproduction failed; inspect the console output.' }
