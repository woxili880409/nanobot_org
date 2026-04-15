<#
.SYNOPSIS
    nanobot 加密配置向导 — 完整密钥生成、设置与备份

.DESCRIPTION
    交互式向导，用于：
      - 生成新的 AES-256 加密密钥
      - 自动设置用户级环境变量
      - 备份现有密钥到带时间戳的文件
      - 显示当前配置状态
    兼容 PowerShell 5.1+ 和 PowerShell 7.0+。

.PARAMETER GenerateOnly
    仅生成密钥并打印，不设置环境变量。

.PARAMETER Backup
    备份当前环境变量中的密钥到 secret/keys_backup_<timestamp>.txt。

.PARAMETER Status
    显示当前环境变量中的密钥状态（不展示实际值）。

.EXAMPLE
    .\setup_encryption.ps1
    .\setup_encryption.ps1 -GenerateOnly
    .\setup_encryption.ps1 -Backup
    .\setup_encryption.ps1 -Status
#>
#Requires -Version 5.1

[CmdletBinding(DefaultParameterSetName='Interactive')]
param(
    [Parameter(ParameterSetName='GenerateOnly')]
    [switch]$GenerateOnly,

    [Parameter(ParameterSetName='Backup')]
    [switch]$Backup,

    [Parameter(ParameterSetName='Status')]
    [switch]$Status
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

#region Helpers

function New-SecureKey {
    [OutputType([string])]
    param()
    $bytes = [byte[]]::new(32)
    $rng   = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    $rng.Dispose()
    return [Convert]::ToBase64String($bytes)
}

function Set-UserEnvVar {
    param(
        [string]$Name,
        [string]$Value
    )
    [Environment]::SetEnvironmentVariable($Name, $Value, 'User')
    # Also set in current process so it takes effect immediately
    [System.Environment]::SetEnvironmentVariable($Name, $Value, 'Process')
}

function Get-MaskedKey {
    param([string]$Key)
    if ([string]::IsNullOrEmpty($Key)) { return '(未设置)' }
    $len = $Key.Length
    if ($len -le 8) { return '****' }
    return $Key.Substring(0, 4) + ('*' * ($len - 8)) + $Key.Substring($len - 4)
}

function Write-Banner {
    param([string]$Title)
    $line = '=' * 50
    Write-Host ""
    Write-Host $line -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host $line -ForegroundColor Cyan
    Write-Host ""
}

#endregion

#region Modes

function Invoke-StatusMode {
    Write-Banner "nanobot 密钥状态检查"

    $encKey       = [Environment]::GetEnvironmentVariable('NANOBOT_ENCRYPTION_KEY', 'User')
    $transportKey = [Environment]::GetEnvironmentVariable('NANOBOT_TRANSPORT_KEY',  'User')

    Write-Host "NANOBOT_ENCRYPTION_KEY : " -NoNewline
    if ([string]::IsNullOrEmpty($encKey)) {
        Write-Host "(未设置)" -ForegroundColor Red
    } else {
        Write-Host (Get-MaskedKey $encKey) -ForegroundColor Green
        Write-Host "  长度: $($encKey.Length) 字符 (base64 编码)" -ForegroundColor DarkGray
    }

    Write-Host "NANOBOT_TRANSPORT_KEY  : " -NoNewline
    if ([string]::IsNullOrEmpty($transportKey)) {
        Write-Host "(未设置)" -ForegroundColor Red
    } else {
        Write-Host (Get-MaskedKey $transportKey) -ForegroundColor Green
        Write-Host "  长度: $($transportKey.Length) 字符 (base64 编码)" -ForegroundColor DarkGray
    }
    Write-Host ""
}

function Invoke-BackupMode {
    Write-Banner "备份当前加密密钥"

    $encKey       = [Environment]::GetEnvironmentVariable('NANOBOT_ENCRYPTION_KEY', 'User')
    $transportKey = [Environment]::GetEnvironmentVariable('NANOBOT_TRANSPORT_KEY',  'User')

    if ([string]::IsNullOrEmpty($encKey) -and [string]::IsNullOrEmpty($transportKey)) {
        Write-Host "没有找到已设置的密钥，无需备份。" -ForegroundColor Yellow
        return
    }

    $timestamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
    $backupFile = Join-Path $ScriptDir "keys_backup_$timestamp.txt"

    @"
# nanobot 密钥备份 — $timestamp
# 请妥善保管此文件，不要提交到版本控制！
NANOBOT_ENCRYPTION_KEY=$encKey
NANOBOT_TRANSPORT_KEY=$transportKey
"@ | Set-Content -Path $backupFile -Encoding UTF8

    # Set restrictive permissions (best-effort on Windows)
    try {
        $acl  = Get-Acl -Path $backupFile
        $acl.SetAccessRuleProtection($true, $false)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $env:USERNAME, 'FullControl', 'Allow'
        )
        $acl.AddAccessRule($rule)
        Set-Acl -Path $backupFile -AclObject $acl
    } catch {
        Write-Host "  (无法设置文件 ACL，请手动保护备份文件)" -ForegroundColor DarkYellow
    }

    Write-Host "密钥已备份到: $backupFile" -ForegroundColor Green
    Write-Host "请将该文件存储在安全位置！" -ForegroundColor Red
    Write-Host ""
}

function Invoke-GenerateOnlyMode {
    Write-Banner "生成新密钥（仅显示，不设置）"

    $encKey       = New-SecureKey
    $transportKey = New-SecureKey

    Write-Host "NANOBOT_ENCRYPTION_KEY:" -ForegroundColor Green
    Write-Host "  $encKey" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "NANOBOT_TRANSPORT_KEY:" -ForegroundColor Green
    Write-Host "  $transportKey" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "手动设置命令：" -ForegroundColor White
    Write-Host "[Environment]::SetEnvironmentVariable('NANOBOT_ENCRYPTION_KEY', '$encKey', 'User')" -ForegroundColor Cyan
    Write-Host "[Environment]::SetEnvironmentVariable('NANOBOT_TRANSPORT_KEY', '$transportKey', 'User')" -ForegroundColor Cyan
    Write-Host ""
}

function Invoke-InteractiveMode {
    Write-Banner "nanobot 加密配置向导"

    # Check existing keys
    $existingEnc = [Environment]::GetEnvironmentVariable('NANOBOT_ENCRYPTION_KEY', 'User')
    $existingTrp = [Environment]::GetEnvironmentVariable('NANOBOT_TRANSPORT_KEY',  'User')

    if (-not [string]::IsNullOrEmpty($existingEnc) -or -not [string]::IsNullOrEmpty($existingTrp)) {
        Write-Host "检测到已有密钥：" -ForegroundColor Yellow
        Write-Host "  NANOBOT_ENCRYPTION_KEY: $(Get-MaskedKey $existingEnc)" -ForegroundColor DarkGray
        Write-Host "  NANOBOT_TRANSPORT_KEY : $(Get-MaskedKey $existingTrp)" -ForegroundColor DarkGray
        Write-Host ""
        $choice = Read-Host "是否先备份现有密钥？(Y/N) [Y]"
        if ([string]::IsNullOrEmpty($choice) -or $choice.ToUpper() -eq 'Y') {
            Invoke-BackupMode
        }
        Write-Host ""
    }

    Write-Host "正在生成新的 AES-256 密钥..." -ForegroundColor White
    $encKey       = New-SecureKey
    $transportKey = New-SecureKey

    Write-Host "密钥已生成。" -ForegroundColor Green
    Write-Host ""

    $confirm = Read-Host "是否将密钥设置为用户级环境变量？(Y/N) [Y]"
    if (-not ([string]::IsNullOrEmpty($confirm) -or $confirm.ToUpper() -eq 'Y')) {
        Write-Host "已取消。密钥未保存。" -ForegroundColor Red
        return
    }

    Set-UserEnvVar 'NANOBOT_ENCRYPTION_KEY' $encKey
    Set-UserEnvVar 'NANOBOT_TRANSPORT_KEY'  $transportKey

    Write-Host ""
    Write-Host "环境变量已设置成功！" -ForegroundColor Green
    Write-Host ""
    Write-Host "NANOBOT_ENCRYPTION_KEY: $(Get-MaskedKey $encKey)" -ForegroundColor DarkGray
    Write-Host "NANOBOT_TRANSPORT_KEY : $(Get-MaskedKey $transportKey)" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "请在 config.json 中启用加密功能：" -ForegroundColor White
    Write-Host @"
{
  "security": {
    "enableSessionEncryption": true,
    "enableTransportEncryption": true,
    "enableLogSanitization": true
  }
}
"@ -ForegroundColor Cyan
    Write-Host ""
    Write-Host "重要提示：" -ForegroundColor Red
    Write-Host "  • 环境变量仅在重启终端/新进程后生效" -ForegroundColor Yellow
    Write-Host "  • 密钥丢失将导致现有会话数据无法解密" -ForegroundColor Yellow
    Write-Host "  • 建议使用 -Backup 参数定期备份密钥" -ForegroundColor Yellow
    Write-Host ""
}

#endregion

# Entry point
switch ($PSCmdlet.ParameterSetName) {
    'Status'       { Invoke-StatusMode }
    'Backup'       { Invoke-BackupMode }
    'GenerateOnly' { Invoke-GenerateOnlyMode }
    default        { Invoke-InteractiveMode }
}
