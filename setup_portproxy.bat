@echo off
echo === 添加 WSL 端口转发 ===
netsh interface portproxy delete v4tov4 listenport=9000 2>nul
netsh interface portproxy add v4tov4 listenport=9000 connectaddress=192.168.1.2 connectport=9000
echo.
echo 转发规则已添加
echo 现在可以通过 http://localhost:9000 访问日记本
echo.
pause
