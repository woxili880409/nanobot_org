<#
.SYNOPSIS
    nanobot 密钥生成脚本 — 快速生成 AES-256 加密密钥

.DESCRIPTION
    生成随机 256-bit (32 字节) 密钥，base64 编码后打印到屏幕。
    适合 PowerShell 5.0+ 和 PowerShell 7.0+。

.EXAMPLE
    .\generate_keys.ps1
#>
#Requires -Version 5.0

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function New-SecureKey {
    [OutputType([string])]
    param()
    $bytes = [byte[]]::new(32)
    $rng  = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    $rng.Dispose()
    return [Convert]::ToBase64String($bytes)
}

$encKey       = New-SecureKey
$transportKey = New-SecureKey

Write-Host ""
Write-Host "=======================================" -ForegroundColor Cyan
Write-Host "   nanobot AES-256 密钥生成结果        " -ForegroundColor Cyan
Write-Host "=======================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "[会话加密密钥]" -ForegroundColor Green
Write-Host "  $encKey" -ForegroundColor Yellow
Write-Host ""
Write-Host "[传输加密密钥]" -ForegroundColor Green
Write-Host "  $transportKey" -ForegroundColor Yellow
Write-Host ""
Write-Host "---------------------------------------" -ForegroundColor DarkGray
Write-Host "请执行以下命令将密钥设置为用户环境变量：" -ForegroundColor White
Write-Host ""
Write-Host "[Environment]::SetEnvironmentVariable('NANOBOT_ENCRYPTION_KEY', '$encKey', 'User')" -ForegroundColor Cyan
Write-Host "[Environment]::SetEnvironmentVariable('NANOBOT_TRANSPORT_KEY',  '$transportKey', 'User')" -ForegroundColor Cyan
Write-Host ""
Write-Host "注意：密钥仅显示一次，请妥善保管！" -ForegroundColor Red
Write-Host "=======================================" -ForegroundColor Cyan
