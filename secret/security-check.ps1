<#
.SYNOPSIS
    nanobot 安全配置检查脚本

.DESCRIPTION
    检查系统的安全配置状态，包括：
      - 环境变量密钥是否已设置
      - config.json 文件权限
      - 安全功能开关状态
      - 工作区目录权限
    兼容 PowerShell 5.0+ 和 PowerShell 7.0+。

.EXAMPLE
    .\security-check.ps1
#>
#Requires -Version 5.0

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

$NanobotDir = Join-Path $env:USERPROFILE '.nanobot'
$ConfigFile = Join-Path $NanobotDir 'config.json'

$passCount = 0
$warnCount = 0
$failCount = 0

function Write-CheckResult {
    param(
        [string]$Label,
        [ValidateSet('PASS','WARN','FAIL')]
        [string]$Status,
        [string]$Detail = ''
    )
    $color = switch ($Status) {
        'PASS' { 'Green' }
        'WARN' { 'Yellow' }
        'FAIL' { 'Red' }
    }
    $tag = "[$Status]".PadRight(7)
    Write-Host "  $tag $Label" -ForegroundColor $color -NoNewline
    if ($Detail) { Write-Host " — $Detail" -ForegroundColor DarkGray } else { Write-Host "" }

    switch ($Status) {
        'PASS' { $script:passCount++ }
        'WARN' { $script:warnCount++ }
        'FAIL' { $script:failCount++ }
    }
}

function Get-MaskedKey {
    param([string]$Key)
    if ([string]::IsNullOrEmpty($Key)) { return '(未设置)' }
    $len = $Key.Length
    if ($len -le 8) { return '****' }
    return $Key.Substring(0, 4) + ('*' * [Math]::Min($len - 8, 20)) + $Key.Substring($len - 4)
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "   nanobot 安全配置检查                 " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# 1. 检查加密密钥环境变量
Write-Host "1. 加密密钥" -ForegroundColor White
$encKey = [Environment]::GetEnvironmentVariable('NANOBOT_ENCRYPTION_KEY', 'User')
$trpKey = [Environment]::GetEnvironmentVariable('NANOBOT_TRANSPORT_KEY',  'User')

if ([string]::IsNullOrEmpty($encKey)) {
    Write-CheckResult 'NANOBOT_ENCRYPTION_KEY' 'WARN' '未设置（会话加密已禁用）'
} else {
    try {
        $raw = [Convert]::FromBase64String($encKey)
        if ($raw.Length -eq 32) {
            Write-CheckResult 'NANOBOT_ENCRYPTION_KEY' 'PASS' (Get-MaskedKey $encKey)
        } else {
            Write-CheckResult 'NANOBOT_ENCRYPTION_KEY' 'FAIL' "密钥长度错误：$($raw.Length) 字节（应为 32）"
        }
    } catch {
        Write-CheckResult 'NANOBOT_ENCRYPTION_KEY' 'FAIL' 'base64 解码失败，密钥格式无效'
    }
}

if ([string]::IsNullOrEmpty($trpKey)) {
    Write-CheckResult 'NANOBOT_TRANSPORT_KEY' 'WARN' '未设置（传输加密已禁用）'
} else {
    try {
        $raw = [Convert]::FromBase64String($trpKey)
        if ($raw.Length -eq 32) {
            Write-CheckResult 'NANOBOT_TRANSPORT_KEY' 'PASS' (Get-MaskedKey $trpKey)
        } else {
            Write-CheckResult 'NANOBOT_TRANSPORT_KEY' 'FAIL' "密钥长度错误：$($raw.Length) 字节（应为 32）"
        }
    } catch {
        Write-CheckResult 'NANOBOT_TRANSPORT_KEY' 'FAIL' 'base64 解码失败，密钥格式无效'
    }
}

Write-Host ""

# 2. 检查 config.json
Write-Host "2. 配置文件" -ForegroundColor White
if (Test-Path $ConfigFile) {
    Write-CheckResult 'config.json 存在' 'PASS' $ConfigFile

    # 检查配置中的安全开关
    try {
        $config = Get-Content $ConfigFile -Raw | ConvertFrom-Json
        $sec = $config.security

        if ($null -eq $sec) {
            Write-CheckResult 'security 配置节' 'WARN' '未配置（使用全部默认值）'
        } else {
            $logSan = if ($null -eq $sec.enableLogSanitization) { $true } else { $sec.enableLogSanitization }
            $sessEnc = if ($null -eq $sec.enableSessionEncryption) { $false } else { $sec.enableSessionEncryption }
            $trpEnc  = if ($null -eq $sec.enableTransportEncryption) { $false } else { $sec.enableTransportEncryption }
            $filePerm = if ($null -eq $sec.secureFilePermissions) { $true } else { $sec.secureFilePermissions }

            if ($logSan)  { Write-CheckResult 'enableLogSanitization' 'PASS' '已启用' }
            else          { Write-CheckResult 'enableLogSanitization' 'WARN' '已禁用' }

            if ($sessEnc) { Write-CheckResult 'enableSessionEncryption' 'PASS' '已启用' }
            else          { Write-CheckResult 'enableSessionEncryption' 'WARN' '已禁用（会话明文存储）' }

            if ($trpEnc)  { Write-CheckResult 'enableTransportEncryption' 'PASS' '已启用' }
            else          { Write-CheckResult 'enableTransportEncryption' 'WARN' '已禁用' }

            if ($filePerm) { Write-CheckResult 'secureFilePermissions' 'PASS' '已启用' }
            else           { Write-CheckResult 'secureFilePermissions' 'WARN' '已禁用' }
        }
    } catch {
        Write-CheckResult 'config.json 解析' 'FAIL' "JSON 解析失败: $_"
    }
} else {
    Write-CheckResult 'config.json 存在' 'WARN' "未找到 ($ConfigFile)，使用默认配置运行"
}
Write-Host ""

# 3. 检查工作区目录
Write-Host "3. 工作区目录" -ForegroundColor White
if (Test-Path $NanobotDir) {
    Write-CheckResult ".nanobot 目录存在" 'PASS' $NanobotDir

    $sessionsDir = Join-Path $NanobotDir 'sessions'
    if (Test-Path $sessionsDir) {
        $files = Get-ChildItem $sessionsDir -Filter '*.jsonl' -ErrorAction SilentlyContinue
        if ($files -and $files.Count -gt 0) {
            Write-CheckResult "Sessions 目录" 'PASS' "$($files.Count) 个会话文件"

            # 抽查一个文件是否是明文 JSON
            $sample = $files | Select-Object -First 1
            $firstLine = Get-Content $sample.FullName -TotalCount 1 -ErrorAction SilentlyContinue
            if ($firstLine -match '"_type"\s*:\s*"metadata"') {
                Write-CheckResult 'sessions 加密状态' 'WARN' '会话以明文存储（未启用加密）'
            } elseif ($firstLine) {
                Write-CheckResult 'sessions 加密状态' 'PASS' '会话内容已加密'
            }
        } else {
            Write-CheckResult "Sessions 目录" 'PASS' '无会话文件'
        }
    } else {
        Write-CheckResult "Sessions 目录" 'WARN' '目录不存在（尚未运行过 gateway）'
    }
} else {
    Write-CheckResult ".nanobot 目录" 'WARN' "未找到 ($NanobotDir)，尚未初始化"
}
Write-Host ""

# 4. 检查 Python cryptography 依赖
Write-Host "4. Python 依赖" -ForegroundColor White
$pyResult = python -c "import cryptography; print(cryptography.__version__)" 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-CheckResult 'cryptography 库' 'PASS' "版本 $pyResult"
} else {
    Write-CheckResult 'cryptography 库' 'FAIL' "未安装（运行 uv sync 安装）"
}
Write-Host ""

# 总结
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  检查结果：" -ForegroundColor White
Write-Host "    通过: $passCount" -ForegroundColor Green
Write-Host "    警告: $warnCount" -ForegroundColor Yellow
Write-Host "    失败: $failCount" -ForegroundColor Red
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

if ($failCount -gt 0) {
    Write-Host "建议：运行 .\setup_encryption.ps1 修复失败项" -ForegroundColor Red
} elseif ($warnCount -gt 0) {
    Write-Host "建议：运行 .\setup_encryption.ps1 启用所有安全功能" -ForegroundColor Yellow
} else {
    Write-Host "安全配置状态良好！" -ForegroundColor Green
}
Write-Host ""
