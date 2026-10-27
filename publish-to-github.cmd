@echo off
setlocal
cd /d "%~dp0"
where gh >nul 2>&1 || (echo ERROR: GitHub CLI gh is not installed. Visit https://cli.github.com/ & exit /b 1)
where git >nul 2>&1 || (echo ERROR: git is not installed. Visit https://git-scm.com/ & exit /b 1)
gh auth status >nul 2>&1 || (echo ERROR: Please run "gh auth login" first. & exit /b 1)
if not exist ".git" (
  git init -b main || exit /b 1
)
git add -A || exit /b 1
git diff --cached --quiet
if errorlevel 1 (
  git commit -m "Initial release: DNS Observer LSPosed v0.1.0" || exit /b 1
)
gh repo view yuzhouoo/DNS-Observer-LSPosed >nul 2>&1
if errorlevel 1 (
  gh repo create yuzhouoo/DNS-Observer-LSPosed --private --source . --remote origin --push || exit /b 1
) else (
  git remote get-url origin >nul 2>&1 || git remote add origin https://github.com/yuzhouoo/DNS-Observer-LSPosed.git
  git push -u origin main || exit /b 1
)
echo Published: https://github.com/yuzhouoo/DNS-Observer-LSPosed
endlocal
