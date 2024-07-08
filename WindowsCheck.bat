@echo off
echo -------------------------------------------------------------
echo " _____ ____ ____    ____  ____    _          _"
echo "|_   _/ ___|  _ \  |  _ \/ ___|  | |    __ _| |__"
echo "  | || |   | |_) | | | | \___ \  | |   / _\` | '_ \\"
echo "  | || |___|  __/  | |_| |___) | | |__| (_| | |_) |"
echo "  |_| \____|_|     |____/|____/  |_____\__,_|_.__/"
echo -------------------------------------------------------------

echo "系统信息检查"
echo ------------------系统信息检查--------------------- >> 检查结果.log
systeminfo >> 检查结果.log
echo ----------------------------------------------------- >> 检查结果.log

echo "网络连接检查"
echo ------------------网络连接检查--------------------- >> 检查结果.log
netstat -ano >> 检查结果.log
echo ----------------------------------------------------- >> 检查结果.log

echo "计划任务检查"
echo ------------------计划任务检查--------------------- >> 检查结果.log
schtasks /query >> 检查结果.log
echo ----------------------------------------------------- >> 检查结果.log

echo "进程检查"
echo ------------------进程检查--------------------- >> 检查结果.log
tasklist >> 检查结果.log
echo ----------------------------------------------------- >> 检查结果.log

echo "端口检查" %需管理员权限%
echo ------------------端口信息检查--------------------- >> 检查结果.log
netstat -anb >> 检查结果.log
echo ----------------------------------------------------- >> 检查结果.log

echo "启动服务检查"
echo ------------------启动服务检查--------------------- >> 检查结果.log
net start >> 检查结果.log
echo ----------------------------------------------------- >> 检查结果.log

echo "注册表启动项检查"
echo ------------------注册表启动项检查--------------------- >> 检查结果.log
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run >> 检查结果.log 
reg query HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run >> 检查结果.log
echo ----------------------------------------------------- >> 检查结果.log

echo "用户检查"
echo ------------------用户检查--------------------- >> 检查结果.log
net user & net localgroup administrators >> 检查结果.log
echo HKEY_LOCAL_MACHINE\SAM\SAM\Domains\Account\Users\Names [1 2 19] > regg.ini & echo HKEY_LOCAL_MACHINE\SAM\SAM\ [1 2 19] >> regg.ini & regini regg.ini & reg query HKEY_LOCAL_MACHINE\SAM\SAM\Domains\Account\Users\Names >> 检查结果.log & del regg.ini
echo ----------------------------------------------------- >> 检查结果.log

echo "RDP登录检查"
echo ------------------RDP登录检查--------------------- >> 检查结果.log
wevtutil epl Microsoft-Windows-TerminalServices-LocalSessionManager/Operational RDP_Check.evtx
echo ----------------------------------------------------- >> 检查结果.log

echo "导出完成，请搭配检查手册对结果进行分析"