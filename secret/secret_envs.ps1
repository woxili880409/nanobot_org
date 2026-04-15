<#
.SYNOPSIS
    nanobot 环境变量配置模板

.DESCRIPTION
    编辑此文件，填入实际的敏感信息，然后运行脚本设置环境变量。
    此文件不应提交到版本控制（已在 .gitignore 中排除）。
    兼容 PowerShell 5.0+ 和 PowerShell 7.0+。

.EXAMPLE
    # 1. 先用文本编辑器填写下方变量
    notepad .\secret_envs.ps1
    # 2. 运行脚本
    .\secret_envs.ps1
#>
#Requires -Version 5.0

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ============================================================
# 请在下方填入实际值（替换 REPLACE_WITH_xxx）
# ============================================================

# --- 加密密钥（通过 .\generate_keys.ps1 生成）---
$NANOBOT_ENCRYPTION_KEY = "REPLACE_WITH_YOUR_ENCRYPTION_KEY"
$NANOBOT_TRANSPORT_KEY  = "REPLACE_WITH_YOUR_TRANSPORT_KEY"

# --- LLM 提供商 API 密钥（按需填写）---
$NANOBOT_PROVIDERS__ANTHROPIC__API_KEY  = ""   # Claude / Anthropic
$NANOBOT_PROVIDERS__OPENAI__API_KEY     = ""   # OpenAI
$NANOBOT_PROVIDERS__OPENROUTER__API_KEY = ""   # OpenRouter
$NANOBOT_PROVIDERS__DEEPSEEK__API_KEY   = ""   # DeepSeek
$NANOBOT_PROVIDERS__GROQ__API_KEY       = ""   # Groq

# --- Telegram Bot Token ---
# 通过 @BotFather 创建 Bot 后获取
$TELEGRAM_BOT_TOKEN = ""

# ============================================================
# 以下代码自动设置上方配置的非空变量
# ============================================================

$vars = @{
    'NANOBOT_ENCRYPTION_KEY'                 = $NANOBOT_ENCRYPTION_KEY
    'NANOBOT_TRANSPORT_KEY'                  = $NANOBOT_TRANSPORT_KEY
    'NANOBOT_PROVIDERS__ANTHROPIC__API_KEY'  = $NANOBOT_PROVIDERS__ANTHROPIC__API_KEY
    'NANOBOT_PROVIDERS__OPENAI__API_KEY'     = $NANOBOT_PROVIDERS__OPENAI__API_KEY
    'NANOBOT_PROVIDERS__OPENROUTER__API_KEY' = $NANOBOT_PROVIDERS__OPENROUTER__API_KEY
    'NANOBOT_PROVIDERS__DEEPSEEK__API_KEY'   = $NANOBOT_PROVIDERS__DEEPSEEK__API_KEY
    'NANOBOT_PROVIDERS__GROQ__API_KEY'       = $NANOBOT_PROVIDERS__GROQ__API_KEY
    'TELEGRAM_BOT_TOKEN'                     = $TELEGRAM_BOT_TOKEN
}

$setCount = 0
foreach ($pair in $vars.GetEnumerator()) {
    if (-not [string]::IsNullOrWhiteSpace($pair.Value) -and $pair.Value -notmatch '^REPLACE_WITH') {
        [Environment]::SetEnvironmentVariable($pair.Key, $pair.Value, 'User')
        [System.Environment]::SetEnvironmentVariable($pair.Key, $pair.Value, 'Process')
        Write-Host "  [OK] $($pair.Key)" -ForegroundColor Green
        $setCount++
    }
}

Write-Host ""
Write-Host "已设置 $setCount 个环境变量。" -ForegroundColor Cyan
Write-Host "重启终端后生效。" -ForegroundColor DarkGray
