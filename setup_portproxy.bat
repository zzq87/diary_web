@echo off
echo === 添加 WSL 端口转发 ===
netsh interface portproxy delete v4tov4 listenport=9000 2>nul
set CONNECT_ADDR=%DIARY_PROXY_CONNECT_ADDR%
if "%CONNECT_ADDR%"=="" set CONNECT_ADDR=192.168.1.2
netsh interface portproxy add v4tov4 listenport=9000 connectaddress=%CONNECT_ADDR% connectport=9000
echo.
echo 转发规则已添加 (目标: %CONNECT_ADDR%)
echo 现在可以通过 http://localhost:9000 访问日记本
echo.
pause
