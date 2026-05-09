$ErrorActionPreference = "Stop"

Write-Host "==> Running pytest"
& ".\.venv\Scripts\python.exe" -m pytest

Write-Host "==> Running ruff"
& ".\.venv\Scripts\python.exe" -m ruff check .

Write-Host "==> Running mypy"
& ".\.venv\Scripts\python.exe" -m mypy

Write-Host "All quality checks passed."
