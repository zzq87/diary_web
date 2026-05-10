# 添加 Windows 防火墙入站规则（管理员 PowerShell）
New-NetFirewallRule -DisplayName "WSL Diary Web" -Direction Inbound -LocalPort 9000 -Protocol TCP -Action Allow
