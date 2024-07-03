#!/bin/bash
# Author: zhxknb1
# Description: 用于检查Linux系统安全性的脚本
# Date: 2024-05-20

# 判断当前用户是否为管理员（具有uid为0的超级用户权限）
if [ $UID -ne 0 ]; then
  echo "当前用户不是管理员，请以管理员身份运行此脚本。"
  exit 1
fi

# 记录脚本开始时间
start_time=`date +"%Y-%m-%d %H:%M:%S"`

# 设置结果文件路径
result_file='Linux_check_result.txt'

# 关于
echo "
                           _     
  o       ._ _   o  ._   _|_   _ 
  |  |_|  | | |  |  | |   |   (_)
 _|             南京聚铭网络安全服务"

# 记录开始执行检查
echo "开始执行检查 ${start_time}" >> ${result_file}

# 检查系统信息
echo "系统信息:" >> ${result_file}
uname -a >> ${result_file}
echo "系统信息结果已输出完成"

# 进程检查
echo "进程检查:" >> ${result_file}
top -d 2 -n 3 -b >> ${result_file}
ps -aux >> ${result_file}
echo "进程信息结果已输出完成"

# 用户检查
echo "用户检查:" >> ${result_file}
echo "管理员用户:" >> ${result_file}
awk -F: '{if($3==0)print $1}'  /etc/passwd >> ${result_file}
echo "可登录用户:" >> ${result_file}
cat /etc/passwd  | grep -E "/bin/bash$" >> ${result_file}
echo "空口令用户:" >> ${result_file}
awk -F: 'length($2)==0 {print $1}' /etc/shadow >> ${result_file}
echo "用户检查结果已输出完成"


# 网络检查
echo "网络检查:" >> ${result_file}
echo "网络连接信息:" >> ${result_file}
netstat -ano >> ${result_file}
echo "已建立的连接信息:" >> ${result_file}
netstat -antlp | grep ESTABLISHED >> ${result_file}
echo "已监听端口信息:" >> ${result_file}
netstat -antlp | grep LISTEN >> ${result_file}
echo "连接的进程信息:" >> ${result_file}
netstat –anp >> ${result_file}
echo "网络检查结果已输出完成"

# 定时任务检查
echo "定时任务检查:" >> ${result_file}
crontab -l >> ${result_file}
echo "定时任务检查结果已输出完成"

# 检查登录日志
echo "日志检查:" >> ${result_file}
echo "统计登录成功的 IP 地址和出现次数:" >> ${result_file}
grep "Accepted" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -nr >> ${result_file}
echo "统计登录失败的 IP 地址和出现次数:" >> ${result_file}
grep "Failed" /var/log/auth.log | awk '{print $13}' | sort | uniq -c | sort -nr |head -n 100 >> ${result_file}
echo "日志检查结果已输出完成"

# 历史命令检查
echo "历史命令检查:" >> ${result_file}
echo "筛选可疑历史命令:" >> ${result_file}
cat /root/.bash_history | grep -E "(whois|sqlmap|nmap|tar|wget|zip|miner|masscan|proxy|msfconsole|msf|fscan|frp)" | grep -v grep >> ${result_file}
echo "历史命令检查结果已输出完成"

# 启动项检查
echo "启动项检查:" >> ${result_file}
echo "查询服务启动项:" >> ${result_file}
ls -alt /etc/init.d/ >> ${result_file}
echo "查询开机启动项程序" >> ${result_file}
cat /etc/rc.local >> ${result_file}
echo "启动项检查结果已输出完成"

end_time=`date +"%Y-%m-%d %H:%M:%S"`
echo "执行检查完成 ${end_time}" >> ${result_file}