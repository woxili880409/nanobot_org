<#
.SYNOPSIS
    nanobot 安全启动脚本

.DESCRIPTION
    在启动 nanobot gateway 之前，自动检查安全配置。
    若存在严重安全问题，将提示确认后再继续。
    兼容 PowerShell 5.0+ 和 PowerShell 7.0+。

.PARAMETER Args
    传递给 nanobot 的额外参数。

.EXAMPLE
    .\start-secure.ps1
    .\start-secure.ps1 -- --config /path/to/config.json
#>
#Requires -Version 5.0

param(
    [Parameter(ValueFromRemainingArguments=$true)]
    [string[]]$PassThruArgs
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

function Write-Header {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "   nanobot 安全启动检查                 " -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
}

Write-Header

$issues  = [System.Collections.ArrayList]@()
$success = $true

# 1. 检查加密密钥
$encKey = [Environment]::GetEnvironmentVariable('NANOBOT_ENCRYPTION_KEY', 'User')
$trpKey = [Environment]::GetEnvironmentVariable('NANOBOT_TRANSPORT_KEY',  'User')
if ([string]::IsNullOrEmpty($encKey)) {
    [void]$issues.Add("NANOBOT_ENCRYPTION_KEY 未设置 — 会话将以明文存储")
}
if ([string]::IsNullOrEmpty($trpKey)) {
    [void]$issues.Add("NANOBOT_TRANSPORT_KEY 未设置 — 消息总线传输未加密")
}

# 2. 检查 cryptography 库
$pyCheck = python -c "import cryptography" 2>&1
if ($LASTEXITCODE -ne 0) {
    [void]$issues.Add("cryptography 库未安装 — 加密功能不可用（运行: uv sync）")
    $success = $false
}

# 3. 显示检查结果
if ($issues.Count -eq 0) {
    Write-Host "  [OK] 所有安全检查通过。" -ForegroundColor Green
    Write-Host ""
} else {
    Write-Host "  检测到以下安全提示：" -ForegroundColor Yellow
    foreach ($issue in $issues) {
        Write-Host "    ⚠ $issue" -ForegroundColor Yellow
    }
    Write-Host ""

    if (-not $success) {
        Write-Host "存在阻断性问题，无法启动。请先修复上述问题。" -ForegroundColor Red
        exit 1
    }

    $confirm = Read-Host "存在安全警告，是否仍要继续启动？(Y/N) [N]"
    if (-not ($confirm.ToUpper() -eq 'Y')) {
        Write-Host "启动已取消。运行 .\setup_encryption.ps1 配置安全功能。" -ForegroundColor Yellow
        exit 0
    }
}

# 4. 启动 nanobot
Write-Host "正在启动 nanobot gateway..." -ForegroundColor Green
Write-Host ""

if ($PassThruArgs -and $PassThruArgs.Count -gt 0) {
    & nanobot gateway @PassThruArgs
} else {
    & nanobot gateway
}
