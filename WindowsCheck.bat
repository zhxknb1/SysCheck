@echo off
echo -------------------------------------------------------------
echo " _____ ____ ____    ____  ____    _          _"
echo "|_   _/ ___|  _ \  |  _ \/ ___|  | |    __ _| |__"
echo "  | || |   | |_) | | | | \___ \  | |   / _\` | '_ \\"
echo "  | || |___|  __/  | |_| |___) | | |__| (_| | |_) |"
echo "  |_| \____|_|     |____/|____/  |_____\__,_|_.__/"
echo -------------------------------------------------------------

echo "ϵͳ��Ϣ���"
echo ------------------ϵͳ��Ϣ���--------------------- >> �����.log
systeminfo >> �����.log
echo ----------------------------------------------------- >> �����.log

echo "�������Ӽ��"
echo ------------------�������Ӽ��--------------------- >> �����.log
netstat -ano >> �����.log
echo ----------------------------------------------------- >> �����.log

echo "�ƻ�������"
echo ------------------�ƻ�������--------------------- >> �����.log
schtasks /query >> �����.log
echo ----------------------------------------------------- >> �����.log

echo "���̼��"
echo ------------------���̼��--------------------- >> �����.log
tasklist >> �����.log
echo ----------------------------------------------------- >> �����.log

echo "�˿ڼ��" %�����ԱȨ��%
echo ------------------�˿���Ϣ���--------------------- >> �����.log
netstat -anb >> �����.log
echo ----------------------------------------------------- >> �����.log

echo "����������"
echo ------------------����������--------------------- >> �����.log
net start >> �����.log
echo ----------------------------------------------------- >> �����.log

echo "ע�����������"
echo ------------------ע�����������--------------------- >> �����.log
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run >> �����.log 
reg query HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run >> �����.log
echo ----------------------------------------------------- >> �����.log

echo "�û����"
echo ------------------�û����--------------------- >> �����.log
net user & net localgroup administrators >> �����.log
echo HKEY_LOCAL_MACHINE\SAM\SAM\Domains\Account\Users\Names [1 2 19] > regg.ini & echo HKEY_LOCAL_MACHINE\SAM\SAM\ [1 2 19] >> regg.ini & regini regg.ini & reg query HKEY_LOCAL_MACHINE\SAM\SAM\Domains\Account\Users\Names >> �����.log & del regg.ini
echo ----------------------------------------------------- >> �����.log

echo "RDP��¼���"
echo ------------------RDP��¼���--------------------- >> �����.log
wevtutil epl Microsoft-Windows-TerminalServices-LocalSessionManager/Operational RDP_Check.evtx
echo ----------------------------------------------------- >> �����.log

echo "������ɣ���������ֲ�Խ�����з���"