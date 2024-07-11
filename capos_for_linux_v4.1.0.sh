#!/bin/sh
# 
# ******************************************************************
# 更新:          2024.6.18
# 版本:          v4.1.0
#
# 描述:          网络安全等级保护安全基线配置核查脚本，兼容Red-Hat、CentOS、EulerOS、Asianux、Ubuntu 16、Oracle、MySQL、PostgreSQL。
#
# 使用方法：     建议在root权限下将本脚本导入/tmp目录下执行，可通过 > 重定向到其他文件后，导出查看。
#               sudo sh capos_for_linux_v4.1.0.sh -a > Check_`hostname`.txt      自动核查；
#               sudo sh capos_for_linux_v4.1.0.sh -l > Check_`hostname`.txt      信息收集；
#               sudo sh capos_for_linux_v4.1.0.sh -o > Check_`hostname`.txt      Oracle数据库核查；
#               sudo sh capos_for_linux_v4.1.0.sh -pgsql > Check_`hostname`.txt  PostgreSQL数据库核查；
#               sudo sh capos_for_linux_v4.1.0.sh -m > Check_`hostname`.txt      MySQL数据库核查，会提示输出root账户口令
#                                                                                输入后回车开始核查，也可以输入字母 q 退出MySQL数据库核查；
#               sudo sh capos_for_linux_v4.1.0.sh -h                             -h 或其他错误参数显示帮助提示信息。
#
# 更新记录：
#  v4.1.0
#    1) redhat_or_centos_ceping方法中增加了对 /etc/pam.d/sshd 中登录失败模块的核查；
#      2) redhat_or_centos_ceping方法中增加了对Red-Hat7版本 /etc/security/pwquality.conf 口令复杂度配置文件的核查；
#    3) 注释中修改并添加了用法信息，更新记录,并对功能方法简单介绍；
#    4) 考虑到部分服务器最小化权限安装，ifconfig 修改为 ip a，netstat 修改为 ss。
# 
# ******************************************************************

# 全局变量

# 系统版本
DISTRO=

# 系统版本号
DISTRO_NUMBER=

# 是否运行有Oracle数据
ORACLE=

# Orcle版本号
ORACLE_NUMBER=

# 是否运行有MySQL数据
MYSQL=

# MySQL版本号
MYSQL_NUMBER=

# 是否运行有PostgreSQL数据
PGSQL=

# PostgreSQL版本号
PGSQL_NUMBER=

# 数据库种类汇总
DBS=

# Web容器版本
WEBSERVER=

# Web容器版本
WEBSERVER_NUMBER=

# 提示信息颜色预设变量
SETCOLOR_SUCCESS="echo -en \\033[1;32m"
SETCOLOR_FAILURE="echo -en \\033[1;31m"
SETCOLOR_WARNING="echo -en \\033[1;33m"
SETCOLOR_NORMAL="echo -en \\033[0;39m"
time=`date +['%Y-%m-%d %H:%M:%S']`

# 普通信息
LogMsg()
{
        echo -e "$time 信息: $*" 
        $SETCOLOR_NORMAL
}

# 告警信息
LogWarnMsg()
{
        $SETCOLOR_WARNING
        echo -e "$time 警告: $*" 
        $SETCOLOR_NORMAL
}

# 成功信息
LogSucMsg()
{
        $SETCOLOR_SUCCESS
        echo -e "$time 成功: $*"
        $SETCOLOR_NORMAL
}

# 错误信息
LogErrorMsg()
{
        $SETCOLOR_FAILURE
        echo -e "$time 错误: $*"
        $SETCOLOR_NORMAL
}

# ******************************************************************
# 重定向文件头部文件描述信息
# ******************************************************************

output_file_banner()
{
  echo -e "******************************************************************"
  echo -e "描述：\t本脚本适用于 Linux 服务器、数据库和 Linux 运维终端网络安全等级保护测评核查"
  echo -e "运行时间：\t"`date +'%Y-%m-%d %H:%M'`
  echo -e "******************************************************************"
  echo -e
}

# ******************************************************************
# LOGO输出，美化作用
# ******************************************************************

print_logo()
{
cat <<EOF
******************************************************************
 ██████╗ █████╗ ██████╗  ██████╗ ███████╗{Mannix v4.1.0 2024.6.18} 
██╔════╝██╔══██╗██╔══██╗██╔═══██╗██╔════╝
██║     ███████║██████╔╝██║   ██║███████╗
██║     ██╔══██║██╔═══╝ ██║   ██║╚════██║
╚██████╗██║  ██║██║     ╚██████╔╝███████║
 ╚═════╝╚═╝  ╚═╝╚═╝      ╚═════╝ ╚══════╝
******************************************************************
EOF
}

# ******************************************************************
# 脚本帮助提示信息
# ******************************************************************

helpinfo()
{
cat <<EOF
"使用方法： $0 [OPTION] [PARAMETER]"

${0} -h        => 查看使用方法
${0} -l        => 显示信息收集
${0} -o        => Oracle数据库
${0} -m [password]          => MySQL数据库
${0} -pgsql      => PostgreSQL数据库
${0} -s        => 网站服务
${0} -a        => 自动核查

EOF
}

# ******************************************************************
# 获取操作系统版本信息: DISTRO->系统类型 ,DISTRO_NUMBER->版本号
# ******************************************************************

get_system_version()
{
  if grep -Eqii "CentOS" /etc/issue || grep -Eq "CentOS" /etc/*-release; then
        DISTRO='CentOS'
    if grep -Eq "9\." /etc/*-release; then
      DISTRO_NUMBER='9'
    elif grep -Eq "8\." /etc/*-release; then
      DISTRO_NUMBER='8'
    elif grep -Eq "7\." /etc/*-release; then
      DISTRO_NUMBER='7'
    elif grep -Eq "6\." /etc/*-release; then
      DISTRO_NUMBER='6'
    elif grep -Eq "5\." /etc/*-release; then
      DISTRO_NUMBER='5'
    elif grep -Eq "4\." /etc/*-release; then
      DISTRO_NUMBER='4'
    else
      DISTRO_NUMBER='不支持的版本'
    fi  
    elif grep -Eqi "Red Hat Enterprise Linux Server" /etc/issue || grep -Eq "Red Hat Enterprise Linux Server" /etc/*-release || grep -Eq "Asianux" /etc/*-release; then
        DISTRO='RedHat'
    if grep -Eq "9\." /etc/*-release; then
      DISTRO_NUMBER='9'
    elif grep -Eq "8\." /etc/*-release; then
      DISTRO_NUMBER='8'
    elif grep -Eq "7\." /etc/*-release; then
      DISTRO_NUMBER='7'
    elif grep -Eq "6\." /etc/*-release; then
      DISTRO_NUMBER='6'
    elif grep -Eq "5\." /etc/*-release; then
      DISTRO_NUMBER='5'
    elif grep -Eq "4\." /etc/*-release; then
      DISTRO_NUMBER='4'
    else
      DISTRO_NUMBER='不支持的版本'
    fi
  elif grep -Eq "EulerOS" /etc/*-release; then
        DISTRO='EulerOS'
    DISTRO_NUMBER='7'
    elif grep -Eqi "Ubuntu" /etc/issue || grep -Eq "Ubuntu" /etc/*-release; then
        DISTRO='Ubuntu'  
  elif [[ -n `uname -a | grep AIX` ]]; then 
    DISTRO='AIX'
    DISTRO_NUMBER=`oslevel`
    else
        DISTRO='不支持的版本'
    fi
}

# ******************************************************************
# 获取Web容器版本信息:WEBSERVER->类型, WEBSERVER_NUMBER->版本号
# ******************************************************************

get_webserver_info()
{
  [[ -n `whereis nginx | awk -F: '{print $2}'` ]] && WEBSERVER="nginx" && WEBSERVER_NUMBER=$(nginx -v | awk -F/ '{print $2}')
  [[ -n `lastlog | grep weblogic` ]] && [[ -n `ss -pantu | grep ':7001'` ]] && WEBSERVER="weblogic" 
  [[ -n `cat /etc/passwd | grep apache` ]] && [[ -n `ss -pantu | grep ':80' | grep 'httpd'` ]] && WEBSERVER="apache" && WEBSERVER_NUMBER=$(apachectl -v | awk -F/ '{print $2}' | grep -v ^$)
}

# ******************************************************************
# 获取数据库类型和版本信息：识别后所属全局变量 ORACLE MYSQL PGSQL 会进行赋值
# ******************************************************************

get_database_version()
{
  if [[ -n `ss -pantu | grep tnslsnr` ]]; then
    ORACLE="Oracle"
    banner=`su - oracle << EOF 
sqlplus / as sysdba 
exit 
EOF`

    [[ $banner =~ "11g" ]] && ORACLE_NUMBER="11g"
    [[ $banner =~ "10g" ]] && ORACLE_NUMBER="10g"
    [[ $banner =~ "12c" ]] && ORACLE_NUMBER="12c"
  fi

  if [[ -n `ss -pantu | grep mysqld` ]]; then
    MYSQL="MySQL"
    MYSQL_NUMBER=`mysql -V | awk '{print $5}'`
    MYSQL_NUMBER=${MYSQL_NUMBER%?}
  fi
  
  if [[ -n `ss -pantu | grep postgres` ]]; then
    PGSQL="PostgreSQL"
    PGSQL_NUMBER=`su - postgres << EOF 
psql -d postgres -U postgres -At -c "select version();" | awk '{print $2}'
exit 
EOF`
PGSQL_NUMBER=`echo -e ${PGSQL_NUMBER} | awk '{print $2}'`  
  fi
  
  DBS="${ORACLE} ${ORACLE_NUMBER}  ${MYSQL} ${MYSQL_NUMBER} ${PGSQL} ${PGSQL_NUMBER}"
  
  [[ -n `ss -pantu | grep 'redis'` ]] && DBS="${DBS} Redis"
  [[ -n `ss -pantu | grep mongodb` ]] && DBS="${DBS} Mongodb"
}

# ******************************************************************
# Redhat系列操作系统信息收集
# ******************************************************************

redhat_info_collection()
{
  echo -e "********************************  1.信息收集  ********************************"
  echo -e
  echo -e "******************************** 信息收集开始 ********************************"
  echo -e
  echo -e "硬件平台：\t"`grep 'DMI' /var/log/dmesg | awk -F'DMI:' '{print $2}'` 
  echo -e "CPU 型号：\t"`cat /proc/cpuinfo | grep name | cut -f2 -d: | uniq`
  echo -e "CPU 个数：\t"`cat /proc/cpuinfo | grep processor | wc -l | awk '{print $1}'`
  echo -e "CPU 类型：\t"`cat /proc/cpuinfo | grep vendor_id | tail -n 1 | awk '{print $3}'`
  Disk=$(fdisk -l |grep '磁盘' |awk -F , '{print $1}' | sed 's/Disk identifier.*//g' | sed '/^$/d')
  echo -e "磁盘信息：\n${Disk}\n${Line}"
  echo -e "内核信息：\t"`uname -a`
  echo -e "系统版本：\t"`cat /etc/redhat-release`
  check_ip_format=`ip a | grep "inet addr"`
  if [ ! -n "$check_ip_format" ]; then
    # 8.x 7.x
    Ipddr=`ip a | grep -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -v 127 | awk '{print $2}'`
  else
    # 6.x
    Ipddr=`ip a | grep -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -v 127 | awk '{print $2}' | awk -F: '{print $2}'`
  fi
  echo -e "主机名：\t"`hostname`
  echo -e "语言："$LANG
  echo -e "Ip地址：\t${Ipddr}" 
  echo -e "中间件或网站服务：\t${WEBSERVER} ${WEBSERVER_NUMBER}"
  echo -e "数据库：\t${DBS}"
  echo -e
  echo -e "******************************** 信息收集结束 ********************************"
  echo -e
}

# ******************************************************************
# Ubuntu操作系统信息收集
# ******************************************************************

ubuntu_info_collection()
{
  echo -e "********************************  1.信息收集  ********************************"
  echo -e
  echo -e "******************************** 信息收集开始 ********************************"
  echo -e
  echo -e "硬件平台：\t"`lspci |grep Host | head -1 | awk -F: '{print $3}'` 
  echo -e "CPU 型号：\t"`cat /proc/cpuinfo | grep name  | uniq | awk -F: '{print $2}'`
  echo -e "CPU 个数：\t"`cat /proc/cpuinfo | grep processor | wc -l | awk '{print $1}'`
  echo -e "CPU 类型：\t"`cat /proc/cpuinfo | grep vendor_id | tail -n 1 | awk '{print $3}'`
  Disk=$(fdisk -l |grep '磁盘' |awk -F , '{print $1}' | sed 's/Disk identifier.*//g' | sed '/^$/d')
  echo -e "磁盘信息：\t${Disk}\n${Line}"
  echo -e "内核信息：\t`uname -a`"
  echo -e "系统版本：\t"`cat /etc/lsb-release | grep "DISTRIB_DESCRIPTION" | awk -F'=' '{print $2}'`
  check_ip_format=`ip a | grep "inet addr"`
  if [ ! -n "$check_ip_format" ]; then
    Ipddr=`ip a | grep -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -v 127 | awk '{print $2}'`
  else
    Ipddr=`ip a | grep -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -v 127 | awk '{print $2}' | awk -F: '{print $2}'`
  fi
  echo -e "主机名：\t"`hostname`
  echo -e "语言：" $LANG
  echo -e "Ip地址：\t${Ipddr}" 
  echo -e "中间件或网站服务：\t${WEBSERVER}  ${WEBSERVER_NUMBER}"
  echo -e "数据库：\t${DBS}"
  echo -e
  echo -e "******************************** 信息收集结束 ********************************"
  echo -e
}

# ******************************************************************
# AIX小型机信息收集，暂不支持
# ******************************************************************

AIX_info_collection()
{
  prtconf | cat
  Ipddr=`ip a | grep -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -v 127 | awk '{print $2}'`
  echo -e "Ip地址：\t${Ipddr}" 
}

# ******************************************************************
# 信息收集 -l 参数执行该方法
# ******************************************************************

information_collection()
{
  get_system_version
  get_database_version
  get_webserver_info
  case $DISTRO in
        CentOS)
      redhat_info_collection;;    
        RedHat)    
      redhat_info_collection;; 
    EulerOS)    
      redhat_info_collection;;   
    Ubuntu)    
      ubuntu_info_collection;; 
    AIX)    
      AIX_info_collection   ;;     
    esac
}

# ***************************************************************************
# 红帽系列操作系统执行该方法，主要支持 8.X 7.X 6.X 版本
# ***************************************************************************

redhat_or_centos_ceping()
{
  LogMsg "操作系统核查启动 ......" 1>&2

  echo -e "******************************** 系统核查开始 ********************************"
  echo -e

  echo -e "********************************  2.身份鉴别  ********************************"
  echo -e

  echo -e "a）应对登录的账户进行身份标识和鉴别，身份标识具有唯一性，身份鉴别信息具有复杂度要求并定期更换"
  echo -e

  echo -e "查看UID的配置"
  echo -e

  grep -i id /etc/login.defs | grep -v ^# | grep -E 'UID_M*'
  echo -e

  echo -e "查看GID的配置"
  echo -e

  grep -i id /etc/login.defs | grep -v ^# | grep -E 'GID_M*'
  echo -e

  echo -e "查看允许登录的账户"
  echo -e

  cat /etc/passwd | grep -v ^# | grep '/bin/bash'
  echo -e

  echo -e "查看是否允许配置SSH空口令账户"
  echo -e

  sudo cat /etc/ssh/sshd_config | grep -v ^# | grep PermitEmptyPasswords
  echo -e

  echo -e "查看设置口令的账户"
  echo -e

  cat /etc/shadow | grep -v ^# | grep -v "*" | grep -v '!'
  echo -e

  echo -e "查看口令有效期"
  echo -e

  grep -i pass /etc/login.defs | grep -v ^#
  echo -e

  echo -e "口令复杂度及历史记忆次数"
  echo -e

  grep -i password /etc/pam.d/system-auth | grep -v ^#
  echo -e

  # ******************************** 空口令账户核查 ******************************** #

  echo -e "******************************************************************"
  echo -e "空口令账户"
  echo -e "******************************************************************"
  echo -e
  
  flag=
  null_password=`awk -F: 'length($2)==0 {print $1}' /etc/shadow`
  
  if [ -n "$null_password" ]; then
    flag='y'
    echo -e $null_password
  fi
  
  null_password=`awk -F: 'length($2)==0 {print $1}' /etc/passwd`
  if [ -n "$null_password" ]; then
    flag='y'
    echo -e $null_password
  fi
  
  null_password=`awk -F: '$2=="!" {print $1}' /etc/shadow`
  if [ -n "$null_password" ]; then
    flag='y'
    echo -e $null_password
  fi
  
  null_password=`awk -F: '$2!="x" {print $1}' /etc/passwd`
  if [ -n "$null_password" ]; then
    flag='y'
    echo -e $null_password
  fi
  
  [[ ! -n "$flag" ]] && echo -e "[是] 本系统不存在空口令账户!"
  echo -e
  
  # ******************************** 特权账户数量核查 ******************************** #

  echo -e "******************************************************************"
  echo -e "管理员账户"
  echo -e "******************************************************************"
  echo -e

  awk -F: '($3==0)' /etc/passwd
  echo -e

  # ******************************** 口令策略核查 ******************************** #

  echo -e "******************************************************************"
  echo -e "口令复杂度要求"
  echo -e "******************************************************************"
  echo -e

  cat /etc/login.defs | grep -v ^# | grep PASS
  echo -e

  echo -e "******************************************************************"
  echo -e "在/etc/pam.d/system-auth文件中 pam_pwquality.so后添加minlen=8 dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1"
  echo -e "password    requisite     pam_pwquality.so minlen=8 dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1 try_first_pass local_users_only retry=3 enforce_for_root authtok_type="
  echo -e "参数含义：账户口令 8 位以上，大写字母、小写字母、数字及特殊字符至少各1位"
  echo -e "限制root账户必须在/etc/pam.d/system-auth文件中pam_pwquality.so行添加enforce_for_root"
  echo -e "限制口令的重复使用"
  echo -e "password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok remember=5"
  echo -e "******************************************************************"
  echo -e

  cat /etc/pam.d/system-auth | grep -v ^# | grep password
  echo -e

  cat /etc/security/pwquality.conf | grep -v ^# | grep -E "difok|minlen|dcredit|ucredit|lcredit|ocredit|minclass|maxrepeat|maxclassrepeat|gecoscheck|dictpath" | grep -v "#"
  echo -e

  case $DISTRO_NUMBER in
        7)
      passwordStrength=`cat /etc/security/pwquality.conf | grep -v ^# | grep -E 'difok|minlen|dcredit|ucredit|lcredit|ocredit|minclass|maxrepeat|maxclassrepeat|gecoscheck|dictpath'`
      if [ ! -n "$passwordStrength" ]; then
        echo -e "[X]核查后 '/etc/security/pwquality.conf', 不存在 pam_cracklib.so 或 pam_pwquality.so 配置"
      else
        echo -e $passwordStrength
      fi;;        
        *)    
      passwordStrength=`cat /etc/pam.d/system-auth | grep -E 'pam_cracklib.so | pam_pwquality.so'`
      if [ ! -n "$passwordStrength" ]; then
        echo -e "[X]核查后 '/etc/pam.d/system-auth', 不存在 pam_cracklib.so 或 pam_pwquality.so 配置"
      else
        echo -e $passwordStrength
      fi;;    
    esac
  echo -e

  echo -e "b）应具有登录失败处理功能，应配置并启用结束会话、限制非法登录次数和当登录连接超时自动退出等相关措施"
  echo -e

  echo -e "登录锁定"
  echo -e

  grep -i auth /etc/pam.d/system-auth | grep -v ^#
  echo -e

  echo -e "超时退出"
  echo -e

  grep -i tmout /etc/profile | grep -v ^#
  echo -e

  # ******************************** 登录失败策略核查 ******************************** #

  echo -e "******************************************************************"
  echo -e "登录失败处理策略"
  echo -e "添加位置要写在/etc/pam.d/system-auth第一行的下面，即#%PAM-1.0的下面。"
  echo -e "auth        required      pam_tally2.so onerr=fail deny=5 unlock_time=600 even_deny_root root_unlock_time=600"
  echo -e "最多连续5次认证登录都出错锁定账户，600秒后解锁，root账户也可以被锁定，root账户锁定后600秒后解锁"
  echo -e "******************************************************************"
  echo -e

  login_failure=`cat /etc/pam.d/system-auth | grep -v ^# | grep tally`  
  if [ -n "$login_failure" ]; then
    echo -e "口令登录失败处理策略设置：${login_failure}。"
  else
    echo -e "[X]警告：本系统未设置登录失败处理策略！"
  fi
  echo -e

  echo -e "******************************************************************"
  echo -e "SSH 口令登录失败处理策略"
  echo -e "******************************************************************"
  echo -e

  ssh_login_failure=`cat /etc/ssh/sshd_config | grep -v ^# | grep MaxAuthTries`
  ssh_login_failure2=`cat /etc/pam.d/sshd | grep -v ^# | grep deny=`
  if [ -n "$ssh_login_failure" ]; then
    echo -e "SSH 口令登录失败处理策略设置：${ssh_login_failure}。" 
  elif [ -n "$ssh_login_failure2" ]; then  
    echo -e "SSH 口令登录失败处理策略设置：${ssh_login_failure2}。" 
  else
    echo -e "[X] 警告: SSH 远程管理未设置登录失败处理策略（建议3~5次）"
  fi
  echo -e
  
  # ******************************** Shell登录超时退出登录核查 ******************************** #

  echo -e "******************************************************************"
  echo -e "登录超时锁定（建议配置登录超时时间 >= 600秒）"
  echo -e "******************************************************************"
  echo -e

  TMOUT=`cat /etc/profile | grep -v ^# | grep -n "TMOUT"`
  if [ -n "$TMOUT" ]; then
    echo -e $TMOUT  
  else
    echo -e "[X]警告: 本系统未设置登录超时锁定!"
  fi
  echo -e

  echo -e "******************************************************************"
  echo -e "SSH 登录超时锁定（建议配置登录超时时间 >= 600秒）"
  echo -e "******************************************************************"
  echo -e

  cat /etc/ssh/sshd_config | grep -v ^# | grep -E "ClientAliveInterval|ClientAliveCountMax"
  echo -e

  echo -e "c）当进行远程管理时，应采取必要措施、防止鉴别信息在网络传输过程中被窃听"
  echo -e

  echo -e "判断sshd是否启用和telnet是否禁用"
  echo -e

  ps -aux | grep -E sshd | grep -v '+'
  echo -e

  ps -aux | grep -E telnet | grep -v '+'
  echo -e

  echo -e "获取sshd的端口和路径"
  echo -e

  systemctl status sshd.service | grep -oE 'port [0-9]*' | uniq
  echo -e

  ps -aux |grep sshd | grep -v 'grep'| grep -oE '(/[a-z]*)*' | uniq
  echo -e

  ps -aux | grep -E sshd | grep -v 'grep'
  echo -e

  # ******************************** 核查telnet、ftp、smtp是否开启 ******************************** #

  echo -e "******************************************************************"
  echo -e "Telnet Ftp SMTP 状态"
  echo -e "******************************************************************"
  echo -e

  telnet_or_ftp_status=`ss -an | grep -E 'telnet|ftp|smtp'`
  if [ -n "$telnet_or_ftp_status" ]; then
    echo -e $telnet_or_ftp_status
  else  
    echo -e "[是]本系统未开启 'telnet, ftp, smtp' 服务！"
  fi
  echo -e

  echo -e "d)应采用口令、口令技术、生物技术等两种或两种以上组合的鉴别技术对账户进行身份鉴别，且其中一种鉴别技术至少应使用口令技术来实现"
  echo -e

  echo -e "*******************************************************************"
  echo -e "双因素认证人工核查"
  echo -e "*******************************************************************"
  echo -e

  echo -e "**************************** 2.访问控制 ****************************"
  echo -e

  echo -e "a)应对登录的账户分配账户和权限"
  echo -e

  ls -l /etc/passwd /etc/shadow /etc/group
  echo -e

  # ******************************** 重要目录权限核查 ******************************** #

  echo -e "******************************************************************"
  echo -e "文件访问权限"
  echo -e "******************************************************************"
  echo -e

  ls -l /etc/shadow
  ls -l /etc/passwd
  ls -l /etc/group
  ls -l /etc/gshadow 
  ls -l /etc/profile
  ls -l /etc/crontab
  ls -l /etc/securetty 
  ls -l /etc/ssh/ssh_config
  ls -l /etc/ssh/sshd_config
  echo -e

  echo -e "b)应重命名或删除默认账户，修改默认账户的默认口令"
  echo -e

  # 所有账户
  echo -e "******************************************************************"
  echo -e "账户列表"
  echo -e "******************************************************************"
  echo -e
  cat /etc/passwd | cut -d ":" -f1
  echo -e

  # ******************************** 核查是否允许root远程登录 ******************************** #

  echo -e "******************************************************************"
  echo -e "SSH 远程管理 PermitRootLogin 状态"
  echo -e "******************************************************************"
  echo -e

  cat /etc/ssh/sshd_config | grep -v ^# | grep PermitRootLogin
  echo -e

  echo -e "c)应及时删除或停用多余的、过期的账户，避免共享账户的存在"
  echo -e

  # ******************************** 口令过期账户数量核查 ******************************** #

  echo -e "******************************************************************"
  echo -e "口令过期账户"
  echo -e "******************************************************************"
  echo -e

  for timeout_usename in `awk -F: '$2=="!!" {print $1}' /etc/shadow`; do
    timeout_usenamelist+="$timeout_usename,"
  done
  echo -e ${timeout_usenamelist%?}
  echo -e
  
  # ******************************** 多余系统默认账户核查，仅参考，进一步核查是否login权限 ******************************** #

  echo -e "******************************************************************"
  echo -e "可能不需要账户"
  echo -e "******************************************************************"
  echo -e

  for no_need_usename in `cat /etc/shadow | grep -E 'adm|lp|sync|shutdown|halt|mail|uucp|operator|games|gopher|ftp|nuucp|news' | awk -F: '{print $1}'`; do
    no_need_usenamelist+="$no_need_usename,"
  done
  echo -e ${no_need_usenamelist%?}
  echo -e

  echo -e "d)应授予管理账户所需的最小权限，实现管理账户的权限分离"
  echo -e
  # 严格意义上要去看下/etc/sudo*文件中的对特权账户的定义，查看对应配置的账户组和账户

  echo -e "e)应由授权主体配置访问控制策略，访问控制策略规定主体对客体的访问规则"
  echo -e
  # 随机性太大，人工访谈后验证

  echo -e "f)访问控制的粒度应达到主体为账户级或进程级，客体为文件、数据库表级"
  echo -e

  ls -l /etc/passwd /etc/shadow /etc/group
  echo -e

  # 查看profile中umask的值是否为022
  grep -i umask /etc/profile /etc/csh.login /etc/csh.cshrc /etc/bashrc -A1 -B1
  echo -e

  echo -e "g)应对重要主体和客体设置安全标记，并控制主体对有安全标记信息资源的访问"
  echo -e

  # ******************************** 核查SeLinux是否开启 ******************************** #
  echo -e

  echo -e "******************************************************************"
  echo -e "MAC(Mandatory access control) 状态"
  echo -e "******************************************************************"
  echo -e

  cat /etc/selinux/config | grep -v ^# | grep "SELINUX="
  echo -e

  echo -e "**************************** 3.安全审计 ****************************"
  echo -e

  echo -e "a)应启用安全审计功能，审计覆盖到每个账户，对重要的账户行为和重要安全事件进行审计"
  echo -e

  # 日志审计服务状态
  ps -aux | grep auditd | grep -v 'grep'
  echo -e

  # ******* 核查Rsyslog，Auditd服务是否开启，日志是否外发，审计配置，审计策略 ******** #

  echo -e "******************************************************************"
  echo -e "日志审计服务状态"
  echo -e "******************************************************************"
  echo -e

  case $DISTRO_NUMBER in
        7)
      systemctl list-unit-files --type=service | grep "rsyslog"
      systemctl list-unit-files --type=service | grep "auditd";;    
        *)
      service --status-all | grep rsyslogd
      systemctl status auditd.service;;    
    esac
  echo -e

  # 查看审计规则
  cat /etc/audit/audit.rules
  echo -e

  echo -e "b)审计记录应包括事件的日期和时间，账户、事件类型，事件是否成功及其他与审计相关的信息"
  echo -e

  sed -n '1,10p' /var/log/messages
  echo -e

  sed -n '1,10p' /var/log/audit/audit.log
  echo -e

  echo -e "[审计规则]：\n"`auditctl -l`
  echo -e

  echo -e "[审计规则]：\n"`cat /etc/audit/audit.rules | grep -v ^#`
  echo -e  
  
  # ******************************** 核查最新日志的最后10行 ******************************** #

  echo -e "******************************************************************"
  echo -e "核查最新日志的最后10行"
  echo -e "******************************************************************"
  echo -e

  cat /var/log/audit/audit.log | tail -n 10
  echo -e

  ausearch -ts today | tail -n 10
  echo -e

  echo -e "c)应对审计记录进行保护，定期备份，避免受到未预期的删除、修改或覆盖等"
  echo -e

  # 查看日志转存的时间
  grep -i weekly /etc/logrotate.conf -A4
  echo -e

  echo -e "d)应对审计进程进行保护，防止未经授权的中断"
  echo -e

  echo -e "日志服务端口："`grep -i port /etc/rsyslog.conf |grep -v '#'|grep -oE '[0-9]*'`
  echo -e "日志服务器ip："`grep -i @ /etc/rsyslog.conf |grep -v '#'|grep -oE '@ ([0-9]{1,3}.){4}*'|grep -oE '([0-9]{1,3}.){4}*'`
  echo -e

  # ******************************** 核查日志审计相关文件权限 ******************************** #

  echo -e "******************************************************************"
  echo -e "审计日志文件权限"
  echo -e "******************************************************************"
  echo -e

  ls -l /var/log/messages
  ls -l /var/log/secure
  ls -l /var/log/audit/audit.log
  ls -l /etc/rsyslog.conf
  ls -l /etc/audit/auditd.conf
  ls -l /etc/audit/audit.rules
  echo -e

  echo -e "[日志转发到日志服务器]："`grep "^*.*[^I][^I]*@" /etc/rsyslog.conf /etc/rsyslog.d/*.conf`
  echo -e

  echo -e "******************************************************************"
  echo -e "审计规则配置"
  echo -e "注意:Max_log_file=5(Log file capacity); Max_log_file_action=ROTATE(log size); num_logs=4"
  echo -e "******************************************************************"
  echo -e

  cat /etc/audit/auditd.conf | grep -v ^# | grep max_log_file
  echo -e

  cat /etc/audit/auditd.conf | grep -v ^# | grep num_logs
  echo -e

  echo -e "[审计规则]："`auditd -l`
  echo -e

  echo -e "**************************** 4.入侵防范 ****************************"
  echo -e

  echo -e "a)应遵循最小安装的原则仅安装需要的组件和应用程序"
  echo -e

  # ******************************** 系统补丁信息 ******************************** #

  echo -e "******************************************************************"
  echo -e "系统补丁信息"
  echo -e "******************************************************************"
  echo -e

  rpm -qa --last | grep patch
  echo -e

  yum list installed
  echo -e

  echo -e "b)应关闭不需要的系统服务、默认共享和高危端口"
  echo -e

  ss -antp
  echo -e

  # ******************************** 显示所有开启的服务 ******************************** #

  echo -e "******************************************************************"
  echo -e "运行中的服务"
  echo -e "******************************************************************"
  echo -e

  case $DISTRO_NUMBER in
        7)
      systemctl list-unit-files --type=service | grep enabled;;          
        *)
      service --status-all | grep running;;    
    esac
  echo -e

  ss -ntlp
  echo -e

  echo -e "c)应通过设定终端接入方式或网络地址范围对通过网络进行管理的管理终端进行限制"
  echo -e  
  
  # ******************************** 核查地址限制 ******************************** #

  echo -e "******************************************************************"
  echo -e "Hosts.allow Hosts.deny 终端限制"
  echo -e "******************************************************************"
  echo -e

  echo -e "[查看 /etc/hosts.allow]："
  echo -e

  cat /etc/hosts.allow | grep -v ^#
  echo -e

  echo -e "[查看 /etc/hosts.deny]："
  echo -e

  cat /etc/hosts.deny | grep -v ^#
  echo -e

  # ******************************** 核查登录终端数量限制 ******************************** #

  echo -e "******************************************************************"
  echo -e "终端登录列表"
  echo -e "******************************************************************"
  echo -e

  for tty in `cat /etc/securetty `; do
    ttylist+="$tty,"
  done
  echo -e ${ttylist%?}
  echo -e

  cat /var/log/secure | grep refused
  echo -e

  echo -e "d)应能发现可能存在的已知漏洞，并在经过充分测试评估后，及时修补漏洞"
  echo -e

  systemctl status iptables.service
  echo -e

  # ******************************** 核查防火墙配置 ******************************** #

  echo -e "******************************************************************"
  echo -e "防火墙状态"
  echo -e "******************************************************************"
  echo -e

  iptables -L -n
  echo -e

  cat /var/log/secure | grep refused
  echo -e
  
  # ******************************** 核查资源限制 等保1.0遗留 ******************************** #

  echo -e "******************************************************************"
  echo -e "单账户访问资源限制"
  echo -e "******************************************************************"
  echo -e

  echo -e "<domain> <type> <item> <value>"
  echo -e

  cat /etc/security/limits.conf | grep -v ^# 
  echo -e
  
  echo -e "******************************************************************"
  echo -e "系统资源使用情况"
  echo -e "******************************************************************"

  echo -e "[磁盘信息]："
  echo -e

  df -h
  echo -e

  echo -e "[内存信息]："
  echo -e

  free -m
  echo -e
  
  # ******************************** 核查硬件资源运行情况 等保1.0遗留 ******************************** #

  # mem_use_info=(`awk '/MemTotal/{memtotal=$2}/MemAvailable/{memavailable=$2}END{printf "%.2f %.2f %.2f",memtotal/1024/1024," "(memtotal-memavailable)/1024/1024," "(memtotal-memavailable)/memtotal*100}' /proc/meminfo`)
  # echo -e "内存使用百分比：${mem_use_info[2]}%"
  # echo -e
  
  TIME_INTERVAL=5
  LAST_CPU_INFO=$(cat /proc/stat | grep -w cpu | awk '{print $2,$3,$4,$5,$6,$7,$8}')
  LAST_SYS_IDLE=$(echo -e $LAST_CPU_INFO | awk '{print $4}')
  LAST_TOTAL_CPU_T=$(echo -e $LAST_CPU_INFO | awk '{print $1+$2+$3+$4+$5+$6+$7}')
  sleep ${TIME_INTERVAL}
  NEXT_CPU_INFO=$(cat /proc/stat | grep -w cpu | awk '{print $2,$3,$4,$5,$6,$7,$8}')
  NEXT_SYS_IDLE=$(echo -e $NEXT_CPU_INFO | awk '{print $4}')
  NEXT_TOTAL_CPU_T=$(echo -e $NEXT_CPU_INFO | awk '{print $1+$2+$3+$4+$5+$6+$7}')
  SYSTEM_IDLE=`echo -e ${NEXT_SYS_IDLE} ${LAST_SYS_IDLE} | awk '{print $1-$2}'`
  TOTAL_TIME=`echo -e ${NEXT_TOTAL_CPU_T} ${LAST_TOTAL_CPU_T} | awk '{print $1-$2}'`
  CPU_USAGE=`echo -e ${SYSTEM_IDLE} ${TOTAL_TIME} | awk '{printf "%.2f", 100-$1/$2*100}'`
  echo -e "CPU 使用百分比：${CPU_USAGE}%"
  echo -e

  echo -e "e)应能够检测到对重要节点进行入侵的行为，并在发生严重入侵事件时提供报警"
  echo -e
  # 确认iptables的状态，查看网络的IDS
  
  
  # ******************************** 其他参考系统信息 ******************************** #

  echo -e "******************************************************************"
  echo -e "MISC"
  echo -e "******************************************************************"
  echo -e

  echo -e "[系统最后登录信息]："
  echo -e

  lastlog
  echo -e

  echo -e "[计划任务信息]："
  echo -e

  crontab -l
  echo -e

  echo -e "[进程和端口状态]："
  echo -e

  ss -pantu
  echo -e

  ps -ef
  echo -e

  echo -e "******************************** 系统核查结束 ********************************"  
}

# ***************************************************************************
# ubuntu操作核查系统执行该方法，主要支持16 18版本。
# ***************************************************************************

ubuntu_ceping()
{
  LogMsg "操作系统核查启动 ......" 1>&2
  echo -e "******************************** 系统核查开始 ********************************"
  echo -e

  echo -e "********************************  2.身份鉴别  ********************************"
  echo -e

  echo -e "a)应对登录的账户进行身份标识和鉴别，身份标识具有唯一性，身份鉴别信息具有复杂度要求并定期更换"
  echo -e

  echo -e "查看UID的配置"
  echo -e

  grep -i id /etc/login.defs | grep -E 'UID_M*'
  echo -e

  echo -e "查看GID的配置"
  echo -e

  grep -i id /etc/login.defs | grep -E 'GID_M*'
  echo -e

  echo -e "查看允许登录的账户"
  echo -e

  cat /etc/passwd | grep -v 'nologin' | grep -v '/bin/false'
  echo -e

  echo -e "查看设置口令的账户"
  echo -e

  cat /etc/shadow | grep -v "*" | grep -v '!'
  echo -e

  echo -e "查看口令有效期"
  echo -e

  grep -i pass /etc/login.defs | grep -v '#'
  echo -e

  echo -e "口令复杂度及历史记忆次数"
  echo -e

  echo -e "******************************************************************"
  echo -e "空口令账户"
  echo -e "******************************************************************"
  echo -e
  
  flag=
  null_password=`awk -F: 'length($2)==0 {print $1}' /etc/shadow`
  
  if [ -n "$null_password" ]; then
    flag='y'
    echo -e $null_password
  fi
  
  null_password=`awk -F: 'length($2)==0 {print $1}' /etc/passwd`
  if [ -n "$null_password" ]; then
    flag='y'
    echo -e $null_password
  fi
  
  null_password=`awk -F: '$2=="!" {print $1}' /etc/shadow`
  if [ -n "$null_password" ]; then
    flag='y'
    echo -e $null_password
  fi
  
  null_password=`awk -F: '$2!="x" {print $1}' /etc/passwd`
  if [ -n "$null_password" ]; then
    flag='y'
    echo -e $null_password
  fi
  
  [[ ! -n "$flag" ]] && echo -e "[是] 本系统不存在空口令账户!"
  echo -e

  echo -e "******************************************************************"
  echo -e "管理员账户"
  echo -e "******************************************************************"
  echo -e

  awk -F: '($3==0)' /etc/passwd
  echo -e

  echo -e
  echo -e "******************************************************************"
  echo -e "口令复杂度要求"
  echo -e "******************************************************************"
  echo -e

  cat /etc/login.defs | grep PASS | grep -v ^#
  echo -e

  cat /etc/security/pwquality.conf | grep -E "difok|minlen|dcredit|ucredit|lcredit|ocredit|minclass|maxrepeat|maxclassrepeat|gecoscheck|dictpath"
  echo -e

  passwordStrength=`cat /etc/security/pwquality.conf`
  if [ ! -n "$passwordStrength" ]; then
    echo -e "[X]核查后 '/etc/security/pwquality.conf', 不存在 libpam-pwquality 配置，注意：apt-get install libpam-pwquality"
  else
    echo -e $passwordStrength
  fi
  echo -e

  echo -e "b)应具有登录失败处理功能，应配置并启用结束会话、限制非法登录次数和当登录连接超时自动退出等相关措施"
  echo -e

  echo -e "超时退出"
  grep -i tmout /etc/profile
  echo -e

  echo -e "******************************************************************"
  echo -e "登录失败处理策略"
  echo -e "******************************************************************"
  echo -e

  login_failure=`grep pam_pwquality.so /etc/pam.d/common-password`  
  if [ -n "$login_failure" ]; then
    echo -e "口令登录失败处理策略设置：${login_failure}。"
  else
    echo -e "[X]警告：本系统未设置登录失败处理策略！"
  fi
  echo -e
  
  echo -e "******************************************************************"
  echo -e "SSH 口令登录失败处理策略"
  echo -e "******************************************************************"
  echo -e

  ssh_login_failure=`cat /etc/ssh/sshd_config | grep -v ^# | grep MaxAuthTries`
  if [ -n "$ssh_login_failure" ]; then
    echo -e "SSH 口令登录失败处理策略设置：${ssh_login_failure}。"
  else
    echo -e "[X] 警告: SSH 远程管理未设置登录失败处理策略（建议3~5次）"
  fi
  echo -e

  echo -e "******************************************************************"
  echo -e "登录超时锁定（建议配置登录超时时间 >= 600秒）"
  echo -e "******************************************************************"
  echo -e

  TMOUT=`cat /etc/profile | grep -n "TMOUT"`
  if [ -n "$TMOUT" ]; then
    echo -e $TMOUT  
  else
    echo -e "[X]警告: 本系统未设置登录超时锁定!"
  fi
  echo -e

  echo -e "c)当进行远程管理时，应采取必要措施、防止鉴别信息在网络传输过程中被窃听"
  echo -e

  echo -e "判断sshd是否启用和telnet是否禁用"
  echo -e

  ps -aux | grep -E sshd | grep -v '+'
  echo -e

  ps -aux | grep -E telnet | grep -v '+'
  echo -e

  echo -e "获取sshd的端口和路径"
  echo -e

  systemctl status sshd.service | grep -oE 'port [0-9]*' | uniq
  echo -e

  ps -aux |grep sshd | grep -v 'grep'| grep -oE '(/[a-z]*)*' | uniq
  echo -e

  ps -aux | grep -E sshd | grep -v 'grep'
  echo -e

  echo -e "******************************************************************"
  echo -e "Telnet Ftp SMTP 状态"
  echo -e "******************************************************************"
  echo -e

  telnet_or_ftp_status=`ss -an | grep -E 'telnet|ftp|smtp'`
  if [ -n "$telnet_or_ftp_status" ]; then
    echo -e $telnet_or_ftp_status
  else  
    echo -e "[是]本系统未开启 'telnet, ftp, smtp' 服务！"
  fi
  echo -e

  echo -e "d)应采用口令、口令技术、生物技术等两种或两种以上组合的鉴别技术对账户进行身份鉴别，且其中一种鉴别技术至少应使用口令技术来实现"
  echo -e

  echo -e "*******************************************************************"
  echo -e "双因素认证人工核查"
  echo -e "*******************************************************************"
  echo -e

  echo -e "**************************** 2.访问控制 ****************************"
  echo -e

  echo -e "a)应对登录的账户分配账户和权限"
  echo -e

  ls -l /etc/passwd /etc/shadow /etc/group
  echo -e

  echo -e "******************************************************************"
  echo -e "文件访问权限"
  echo -e "******************************************************************"
  echo -e

  ls -l /etc/shadow
  ls -l /etc/passwd
  ls -l /etc/group
  ls -l /etc/gshadow 
  ls -l /etc/profile
  ls -l /etc/crontab
  ls -l /etc/securetty 
  ls -l /etc/ssh/ssh_config
  ls -l /etc/ssh/sshd_config
  echo -e

  echo -e "b)应重命名或删除默认账户，修改默认账户的默认口令"
  echo -e

  # 所有账户
  echo -e "******************************************************************"
  echo -e "账户列表"
  echo -e "******************************************************************"
  echo -e

  cat /etc/passwd | cut -d ":" -f1
  echo -e

  echo -e "******************************************************************"
  echo -e "SSH 远程管理 PermitRootLogin 状态"
  echo -e "******************************************************************"
  echo -e

  cat /etc/ssh/sshd_config | grep Root
  echo -e

  echo -e "c)应及时删除或停用多余的、过期的账户，避免共享账户的存在"
  echo -e

  echo -e "******************************************************************"
  echo -e "口令过期账户"
  echo -e "******************************************************************"
  echo -e

  for timeout_usename in `awk -F: '$2=="!!" {print $1}' /etc/shadow`; do
    timeout_usenamelist+="$timeout_usename,"
  done
  echo -e ${timeout_usenamelist%?}
  echo -e

  echo -e "******************************************************************"
  echo -e "可能不需要账户"
  echo -e "******************************************************************"
  echo -e

  for no_need_usename in `cat /etc/shadow | grep -E 'adm|lp|sync|shutdown|halt|mail|uucp|operator|games|gopher|ftp|nuucp|news' | awk -F: '{print $1}'`; do
    no_need_usenamelist+="$no_need_usename,"
  done
  echo -e ${no_need_usenamelist%?}
  echo -e

  echo -e "d)应授予管理账户所需的最小权限，实现管理账户的权限分离"
  echo -e
  # 严格意义上要去看下/etc/sudo*文件中的对特权账户的定义，查看对应配置的账户组和账户

  echo -e "e)应由授权主体配置访问控制策略，访问控制策略规定主体对客体的访问规则"
  echo -e
  # 随机性太大，人工访谈后验证

  echo -e "f)访问控制的粒度应达到主体为账户级或进程级，客体为文件、数据库表级"
  echo -e
  ls -l /etc/passwd /etc/shadow /etc/group
  echo -e

  # 查看profile中umask的值是否为022
  grep -i umask /etc/profile /etc/csh.login /etc/csh.cshrc /etc/bashrc -A1 -B1
  echo -e

  echo -e "g)应对重要主体和客体设置安全标记，并控制主体对有安全标记信息资源的访问"
  echo -e

  echo -e "******************************************************************"
  echo -e "MAC(Mandatory access control) 状态"
  echo -e "******************************************************************"
  echo -e

  cat /etc/selinux/config | grep -v ^# | grep "SELINUX="
  echo -e

  echo -e "**************************** 3.安全审计 ****************************"
  echo -e

  echo -e "a)应启用安全审计功能，审计覆盖到每个账户，对重要的账户行为和重要安全事件进行审计"
  echo -e

  # 日志审计服务状态
  ps -aux |grep auditd| grep -v 'grep'
  echo -e

  echo -e "******************************************************************"
  echo -e "日志审计服务状态"
  echo -e "******************************************************************"
  echo -e

  systemctl list-unit-files --type=service | grep "rsyslog"
  systemctl list-unit-files --type=service | grep "auditd"     
  echo -e

  # 查看审计规则
  cat /etc/audit/audit.rules
  echo -e

  echo -e "b)审计记录应包括事件的日期和时间，账户、事件类型，事件是否成功及其他与审计相关的信息"
  echo -e

  sed -n '1,10p' /var/log/messages
  echo -e

  sed -n '1,10p' /var/log/audit/audit.log
  echo -e

  echo -e "[审计规则]："`auditctl -l`
  echo -e

  echo -e "[审计规则]："`cat /etc/audit/audit.rules`
  echo -e

  echo -e "******************************************************************"
  echo -e "核查最新日志的最后10行"
  echo -e "******************************************************************"
  echo -e

  cat /var/log/audit/audit.log | tail -n 10
  echo -e

  ausearch -ts today | tail -n 10
  echo -e

  echo -e "c)应对审计记录进行保护，定期备份，避免受到未预期的删除、修改或覆盖等"
  echo -e

  # 查看日志转存的时间
  grep -i weekly /etc/logrotate.conf -A4
  echo -e

  echo -e "d)应对审计进程进行保护，防止未经授权的中断"
  echo -e

  echo -e "日志服务端口："`grep -i port /etc/rsyslog.conf |grep -v '#'|grep -oE '[0-9]*'`
  echo -e "日志服务器ip："`grep -i @ /etc/rsyslog.conf |grep -v '#'|grep -oE '@ ([0-9]{1,3}.){4}*'|grep -oE '([0-9]{1,3}.){4}*'`
  echo -e

  echo -e "******************************************************************"
  echo -e "审计日志文件权限"
  echo -e "******************************************************************"
  echo -e

  ls -l /var/log/auth.log
  ls -l /var/log/faillog
  ls -l /etc/rsyslog.conf
  ls -l /etc/audit/auditd.conf
  ls -l /etc/audit/audit.rules
  echo -e

  echo -e "[日志转发到日志服务器]："`grep "^*.*[^I][^I]*@" /etc/rsyslog.conf /etc/rsyslog.d/*.conf`
  echo -e

  echo -e "[审计规则配置]："`cat /etc/audit/auditd.conf | grep -v ^#`
  echo -e

  echo -e "[审计规则]："`auditd -l`
  echo -e

  echo -e "******************************************************************"
  echo -e "审计规则配置"
  echo -e "注意:Max_log_file=5(Log file capacity); Max_log_file_action=ROTATE(log size); num_logs=4"
  echo -e "******************************************************************"
  echo -e

  cat /etc/audit/auditd.conf | grep max_log_file | grep -v ^#
  cat /etc/audit/auditd.conf | grep max_log_file_action | grep -v ^#
  echo -e

  echo -e "**************************** 4.入侵防范 ****************************"
  echo -e

  echo -e "a)应遵循最小安装的原则仅安装需要的组件和应用程序"
  echo -e

  echo -e "******************************************************************"
  echo -e "系统补丁信息"
  echo -e "******************************************************************"
  echo -e

  echo -e "b)应关闭不需要的系统服务、默认共享和高危端口"
  echo -e

  ss -antp
  echo -e

  echo -e "******************************************************************"
  echo -e "运行中的服务"
  echo -e "******************************************************************"
  echo -e

  systemctl list-unit-files --type=service | grep enabled  
  echo -e

  ss -ntlp
  echo -e

  echo -e "c)应通过设定终端接入方式或网络地址范围对通过网络进行管理的管理终端进行限制"
  echo -e

  echo -e "******************************************************************"
  echo -e "Hosts.allow Hosts.deny 终端限制"
  echo -e "******************************************************************"
  echo -e

  echo -e "[查看 /etc/hosts.allow]："
  echo -e

  cat /etc/hosts.allow | grep -v ^#
  echo -e

  echo -e "[查看 /etc/hosts.deny]："
  echo -e

  cat /etc/hosts.deny | grep -v ^#
  echo -e

  cat /var/log/secure | grep refused
  echo -e

  echo -e "d)应能发现可能存在的已知漏洞，并在经过充分测试评估后，及时修补漏洞"
  echo -e

  systemctl status iptables.service
  echo -e
  
  echo -e "******************************************************************"
  echo -e "防火墙状态"
  echo -e "******************************************************************"
  echo -e

  iptables --list
  echo -e

  cat /var/log/secure | grep refused
  echo -e
  
  echo -e "******************************************************************"
  echo -e "单账户访问资源限制"
  echo -e "******************************************************************"
  echo -e

  echo -e "<domain> <type> <item> <value>"
  echo -e

  cat /etc/security/limits.conf | grep -v ^# 
  echo -e
  
  echo -e "******************************************************************"
  echo -e "系统资源使用情况"
  echo -e "******************************************************************"
  echo -e

  echo -e "[磁盘信息]："
  echo -e
  df -h
  echo -e

  echo -e "[内存信息]："
  echo -e
  free -m
  echo -e
  
  # mem_use_info=(`awk '/MemTotal/{memtotal=$2}/MemAvailable/{memavailable=$2}END{printf "%.2f %.2f %.2f",memtotal/1024/1024," "(memtotal-memavailable)/1024/1024," "(memtotal-memavailable)/memtotal*100}' /proc/meminfo`)
  # echo -e "内存使用百分比：${mem_use_info[2]}%"
  # echo -e
  
  TIME_INTERVAL=5
  LAST_CPU_INFO=$(cat /proc/stat | grep -w cpu | awk '{print $2,$3,$4,$5,$6,$7,$8}')
  LAST_SYS_IDLE=$(echo -e $LAST_CPU_INFO | awk '{print $4}')
  LAST_TOTAL_CPU_T=$(echo -e $LAST_CPU_INFO | awk '{print $1+$2+$3+$4+$5+$6+$7}')
  sleep ${TIME_INTERVAL}
  NEXT_CPU_INFO=$(cat /proc/stat | grep -w cpu | awk '{print $2,$3,$4,$5,$6,$7,$8}')
  NEXT_SYS_IDLE=$(echo -e $NEXT_CPU_INFO | awk '{print $4}')
  NEXT_TOTAL_CPU_T=$(echo -e $NEXT_CPU_INFO | awk '{print $1+$2+$3+$4+$5+$6+$7}')
  SYSTEM_IDLE=`echo -e ${NEXT_SYS_IDLE} ${LAST_SYS_IDLE} | awk '{print $1-$2}'`
  TOTAL_TIME=`echo -e ${NEXT_TOTAL_CPU_T} ${LAST_TOTAL_CPU_T} | awk '{print $1-$2}'`
  CPU_USAGE=`echo -e ${SYSTEM_IDLE} ${TOTAL_TIME} | awk '{printf "%.2f", 100-$1/$2*100}'`
  echo -e "CPU 使用百分比：${CPU_USAGE}%"
  echo -e

  echo -e "******************************************************************"
  echo -e "MISC"
  echo -e "******************************************************************"
  echo -e

  echo -e "#[系统最后登录信息]："
  echo -e
  lastlog
  echo -e

  echo -e "#[计划任务信息]："
  echo -e
  crontab -l
  echo -e

  echo -e "#[进程和端口状态]："
  echo -e
  ss -pantu
  echo -e

  ps -ef
  echo -e

  echo -e "******************************** 系统核查结束 ********************************"
}

# ***************************************************************************
# AIX操作核查系统执行该方法，暂不支持。
# ***************************************************************************
AIX_ceping()
{
  LogMsg "Checking operating system......" 1>&2
  echo -e "******************************** System checking start ********************************"
  echo -e
  echo -e "******************************************************************"
  echo -e "Checking Empty password users"
  echo -e "******************************************************************"
  flag=
  null_password=`awk -F: 'length($2)==0 {print $1}' /etc/shadow`
  
  if [ -n "$null_password" ]; then
    flag='y'
    echo -e $null_password
  fi
  
  null_password=`awk -F: 'length($2)==0 {print $1}' /etc/passwd`
  if [ -n "$null_password" ]; then
    flag='y'
    echo -e $null_password
  fi
  
  null_password=`awk -F: '$2=="!" {print $1}' /etc/shadow`
  if [ -n "$null_password" ]; then
    flag='y'
    echo -e $null_password
  fi
  
  null_password=`awk -F: '$2!="x" {print $1}' /etc/passwd`
  if [ -n "$null_password" ]; then
    flag='y'
    echo -e $null_password
  fi
  
  [[ ! -n "$flag" ]] && echo -e "[是] This system no empty password users!"
  
  echo -e
  echo -e "******************************************************************"
  echo -e "Checking UID=0 users"
  echo -e "******************************************************************"
  awk -F: '$3==0 {print $1}' /etc/passwd
  echo -e
  ps -ef
}


# ******************************************************************
# Oracle数据库核查，参数 -o 执行该方法，已测试兼容版本：10g 11g 12c
# ******************************************************************
oracle_ceping()
{
  [ ! -n "$ORACLE" ] && LogErrorMsg "Not found Oracle database,please run '${0} -l'" 1>&2 && exit 1
  LogMsg "Checking Oracle database system......" 1>&2
  echo -e "******************************** Oracle checking start ********************************"
  echo -e
  # 临时SQL文件
  sqlFile=/tmp/tmp_oracle.sql
  # 写入SQL语句
  echo -e "set echo -e off feedb off timi off pau off trimsp on head on long 2000000 longchunksize 2000000" > ${sqlFile}
  echo -e "set linesize 150" > ${sqlFile}
  echo -e "set pagesize 80" > ${sqlFile} 
  echo -e "col username format a22" > ${sqlFile}
  echo -e "col account_status format a20" > ${sqlFile}
  echo -e "col password format a20" > ${sqlFile}
  echo -e "col CREATED format a20" > ${sqlFile}
  echo -e "col USER_ID, format a10" > ${sqlFile}
  echo -e "col profile format a20" > ${sqlFile}
  echo -e "col resource_name format a35" > ${sqlFile}
  echo -e "col limit format a10" > ${sqlFile}
  echo -e "col TYPE format a15" > ${sqlFile}
  echo -e "col VALUE format a20" > ${sqlFile}

  echo -e "col grantee format a25" > ${sqlFile}
  echo -e "col owner format a10" > ${sqlFile}
  echo -e "col table_name format a10" > ${sqlFile}
  echo -e "col grantor format a10" > ${sqlFile}
  echo -e "col privilege format a10" > ${sqlFile}

  echo -e "col AUDIT_OPTION format a30" > ${sqlFile}
  echo -e "col SUCCESS format a20" > ${sqlFile}
  echo -e "col FAILURE format a20" > ${sqlFile}
  echo -e "col any_path format a100" > ${sqlFile}

  echo -e "PROMPT # ******************************************************************#" > ${sqlFile}
  echo -e "PROMPT # Oracle version info" > ${sqlFile}
  echo -e "PROMPT # ******************************************************************#" > ${sqlFile}
  echo -e "select * from v\$version;" > ${sqlFile}
  echo -e "PROMPT" > ${sqlFile}

  echo -e "PROMPT # ******************************************************************#" > ${sqlFile}
  echo -e "PROMPT # All database instances" > ${sqlFile}
  echo -e "PROMPT # ******************************************************************#" > ${sqlFile}
  echo -e "select name from v\$database;" > ${sqlFile}
  echo -e "PROMPT" > ${sqlFile}

  echo -e "PROMPT # ******************************************************************#" > ${sqlFile}
  echo -e "PROMPT # Checking all user status(note sample account:scott,outln,ordsys)" > ${sqlFile}
  echo -e "PROMPT # ******************************************************************#" > ${sqlFile}
  echo -e "select username, CREATED, USER_ID, account_status, profile from dba_users;" > ${sqlFile}
  echo -e "PROMPT" > ${sqlFile}

  echo -e "PROMPT # ******************************************************************#" > ${sqlFile}
  echo -e "PROMPT # Policie Checking of password and attempt login failed" > ${sqlFile}
  echo -e "PROMPT # ******************************************************************#" > ${sqlFile}
  echo -e "select profile, resource_name, limit from dba_profiles where resource_type='PASSWORD';" > ${sqlFile}
  echo -e "PROMPT" > ${sqlFile}

  echo -e "PROMPT # ******************************************************************#" > ${sqlFile}
  echo -e "PROMPT # Show the default password account" > ${sqlFile}
  echo -e "PROMPT # ******************************************************************#" > ${sqlFile}
  echo -e "select * from dba_users_with_defpwd;" > ${sqlFile}
  echo -e "PROMPT" > ${sqlFile}
  
  echo -e "PROMPT # ******************************************************************#" > ${sqlFile}
  echo -e "PROMPT # Show all users about granted_role='DBA'" > ${sqlFile}
  echo -e "PROMPT # ******************************************************************#" > ${sqlFile}
  echo -e "select grantee from dba_role_privs where granted_role='DBA';" > ${sqlFile}
  echo -e "PROMPT" > ${sqlFile}

  echo -e "PROMPT # ******************************************************************#" > ${sqlFile}
  echo -e "PROMPT # Default users grantee roles about grantee='PUBLIC'" > ${sqlFile}
  echo -e "PROMPT # ******************************************************************#" > ${sqlFile}
  echo -e "select granted_role from dba_role_privs where grantee='PUBLIC';" > ${sqlFile}
  echo -e "PROMPT" > ${sqlFile}

  echo -e "PROMPT # ******************************************************************#" > ${sqlFile}
  echo -e "PROMPT # Checking access of data dictionary must boolean=FALSE" > ${sqlFile}
  echo -e "PROMPT # ******************************************************************#" > ${sqlFile}
  echo -e "show parameter O7_DICTIONARY_ACCESSIBILITY;" > ${sqlFile}
  echo -e "PROMPT" > ${sqlFile}

  echo -e "PROMPT # ******************************************************************#" > ${sqlFile}
  echo -e "PROMPT # Audit state" > ${sqlFile}
  echo -e "PROMPT # ******************************************************************#" > ${sqlFile}
  echo -e "show parameter audit;" > ${sqlFile}
  echo -e "PROMPT" > ${sqlFile}

  echo -e "PROMPT # ******************************************************************#" > ${sqlFile}
  echo -e "PROMPT # Important security events covered by audit" > ${sqlFile}
  echo -e "PROMPT # ******************************************************************#" > ${sqlFile}
  echo -e "select AUDIT_OPTION, SUCCESS, FAILURE from dba_stmt_audit_opts;" > ${sqlFile}
  echo -e "PROMPT" > ${sqlFile}

  echo -e "PROMPT # ******************************************************************#" > ${sqlFile}
  echo -e "PROMPT # Protecting audit records status" > ${sqlFile}
  echo -e "PROMPT # ******************************************************************#" > ${sqlFile}
  echo -e "select grantee, owner, table_name, grantor, privilege from dba_tab_privs where table_name='AUD$';" > ${sqlFile}
  echo -e "PROMPT" > ${sqlFile}

  echo -e "PROMPT # ******************************************************************#" > ${sqlFile}
  echo -e "PROMPT # Checking login 'IDLE_TIME' value" > ${sqlFile}
  echo -e "PROMPT # ******************************************************************#" > ${sqlFile}
  echo -e "select resource_name, limit from dba_profiles where profile='DEFAULT' and resource_type='KERNEL' and resource_name='IDLE_TIME';" > ${sqlFile}
  echo -e "PROMPT" > ${sqlFile}

  echo -e "PROMPT # ******************************************************************#" > ${sqlFile}
  echo -e "PROMPT # Checking single user resource limit status" > ${sqlFile}
  echo -e "PROMPT # ******************************************************************#" > ${sqlFile}
  echo -e "select resource_name, limit from dba_profiles where profile='DEFAULT' and resource_type='SESSIONS_PER_USERS';" > ${sqlFile}
  echo -e "PROMPT" > ${sqlFile}

  echo -e "PROMPT # ******************************************************************#" > ${sqlFile}
  echo -e "PROMPT # Checking cpu time limit for a single session" > ${sqlFile}
  echo -e "PROMPT # ******************************************************************#" > ${sqlFile}
  echo -e "select resource_name, limit from dba_profiles where profile='DEFAULT' and resource_type='CPU_PER_SESSION';" > ${sqlFile}
  echo -e "PROMPT" > ${sqlFile}

  echo -e "PROMPT # ******************************************************************#" > ${sqlFile}
  echo -e "PROMPT # Show maximum number of connections" > ${sqlFile}
  echo -e "PROMPT # ******************************************************************#" > ${sqlFile}
  echo -e "show parameter processes;" > ${sqlFile}
  echo -e "PROMPT" > ${sqlFile}

  echo -e "PROMPT # ******************************************************************#" > ${sqlFile}
  echo -e "PROMPT # Access control function" > ${sqlFile}
  echo -e "PROMPT # ******************************************************************#" > ${sqlFile}
  echo -e "select any_path from resource_view where any_path like '/sys/acls/%.xml';" > ${sqlFile}
  echo -e "PROMPT" > ${sqlFile}

  echo -e "PROMPT # ******************************************************************#" > ${sqlFile}
  echo -e "PROMPT # Remote_os_authent" > ${sqlFile}
  echo -e "PROMPT # ******************************************************************#" > ${sqlFile}
  echo -e "select value from v\$parameter where name='remote_os_authent';" > ${sqlFile}
  echo -e "PROMPT" > ${sqlFile}

  echo -e "PROMPT # ******************************************************************#" > ${sqlFile}
  echo -e "PROMPT # 'Oracle Label Security' install status" > ${sqlFile}
  echo -e "PROMPT # ******************************************************************#" > ${sqlFile}
  echo -e "select username, account_status, profile from dba_users where username='LBACSYS';" > ${sqlFile}
  echo -e "select object_type,count(*) from dba_objects where OWNER='LBACSYS' group by object_type;" > ${sqlFile}
  echo -e "PROMPT" > ${sqlFile}
  echo -e "exit" > ${sqlFile}
  chmod 777 ${sqlFile}

  # 切换至oracle账户执行SQL语句，执行完毕后退回root账户
  su - oracle << EOF
sqlplus / as sysdba @ ${sqlFile}
exit
EOF
  # 删除临时SQL文件
  rm $sqlFile -f
  
  # 查找sqlnet.ora文件
  sqlnet_ora_path=`find / -name "sqlnet.ora" | grep -v samples`
  echo -e
  echo -e "******************************************************************#" 
  echo -e "Checking Oracle configuration files(path:${sqlnet_ora_path})"
  echo -e "******************************************************************#"
  cat $sqlnet_ora_path | grep -Ev "^$|^[#;]"
  echo -e
  echo -e "******************************** Oracle checking end ********************************"
  echo -e
}

# ******************************************************************
# Mysql数据库核查，参数 -m 执行该方法。SQL语句暂不支持。
# ******************************************************************
mysql_ceping()
{   
  [ ! -n "$MYSQL" ] && LogErrorMsg "Not found Mysql database,please run '${0} -l'" 1>&2 && exit 1
  LogMsg "Checking Mysql database system......" 1>&2
  echo -e
  echo -e "******************************** Mysql checking start ********************************"
  echo -e
  MYSQL_BIN=$(which mysql)
  loginfotmp=/tmp/tmpinfo  

  # 核查是否为空口令。
  if [ ! -n "$1" ];then
    while :
      do
        while [ ! -n "${mysql_pwd}" ]
          do
            read -p "Enter the mysql(user:root) password: " mysql_pwd
            [[ "q" == $mysql_pwd ]] && LogMsg "Already skip Mysql check." 1>&2 && return
          done
      
        $MYSQL_BIN -uroot -p$mysql_pwd -e "exit" &> $loginfotmp
        loginfo=`grep "ERROR" ${loginfotmp}`
        rm -f $loginfotmp
        if [ ! -n "$loginfo" ]; then
          break
        else
          mysql_pwd=          
          LogErrorMsg "Please confirm the password or check the configuration about mysql connect!" 1>&2
          LogMsg "Of course, you can ‘Ctrl + C’ exit or enter 'q' spin mysql checking." 1>&2
          continue
        fi
      done
  else
    mysql_pwd=$1
    $MYSQL_BIN -uroot -p$mysql_pwd -e "exit" &> $loginfotmp
    loginfo=`grep "ERROR" ${loginfotmp}`
    rm -f $loginfotmp
    if [ -n "$loginfo" ]; then
      LogErrorMsg "Please confirm the password or check the configuration!" 1>&2
      exit 1
    fi
    
  fi
  
  echo -e "******************************************************************"
  echo -e "Mysql checking"
  echo -e "******************************************************************"
  echo -e "Mysql database status"
  echo -e
  $MYSQL_BIN -uroot -p$mysql_pwd -e "\s"
  echo -e
  echo -e "show databases;"
  echo -e
  $MYSQL_BIN -uroot -p$mysql_pwd -e 'show databases;'
  echo -e
  echo -e "select version();"
  echo -e
  $MYSQL_BIN -uroot -p$mysql_pwd -D mysql -e 'select host, user, password from user;'
  echo -e
  echo -e "password policy( > v5.7 )"
  echo -e
  $MYSQL_BIN -uroot -p$mysql_pwd -D mysql -e "show variables like 'validate_password%';"
  echo -e
  echo -e "show tables;"
  echo -e
  $MYSQL_BIN -uroot -p$mysql_pwd -D mysql -e 'show tables;'
  echo -e
  echo -e "select user, Shutdown_priv, Grant_priv, File_priv from user;"
  echo -e
  $MYSQL_BIN -uroot -p$mysql_pwd -D mysql -e 'select user, Shutdown_priv, Grant_priv, File_priv from user;'
  echo -e
  echo -e "select * from db;"
  echo -e
  $MYSQL_BIN -uroot -p$mysql_pwd -D mysql -e 'select * from db;'
  echo -e
  echo -e "select * from tables_priv;"
  echo -e
  $MYSQL_BIN -uroot -p$mysql_pwd -D mysql -e 'select * from tables_priv;'
  echo -e
  echo -e "select * from columns_priv;"
  echo -e
  $MYSQL_BIN -uroot -p$mysql_pwd -D mysql -e 'select * from columns_priv;'
  echo -e  
  echo -e "show global variables like '%general_log%';"
  echo -e
  $MYSQL_BIN -uroot -p$mysql_pwd -D mysql -e "show global variables like '%general_log%';"
  echo -e  
  echo -e "show variables like 'log_%';"
  echo -e
  $MYSQL_BIN -uroot -p$mysql_pwd -D mysql -e "show variables like 'log_%';"
  echo -e
  echo -e "show variables like 'log_bin';"
  echo -e
  $MYSQL_BIN -uroot -p$mysql_pwd -D mysql -e "show variables like 'log_bin';"
  echo -e
  echo -e "show variables like '%timeout%';"
  echo -e
  $MYSQL_BIN -uroot -p$mysql_pwd -D mysql -e "show variables like '%timeout%';"
  echo -e
  mysql_cnf=`find / -name my.cnf `
  echo -e
  echo -e "Checking Mysql configuration files(path:${mysql_cnf})"
  echo -e
  cat $mysql_cnf | grep -v ^$
  echo -e
  $MYSQL_BIN -uroot -p$mysql_pwd -D mysql -e "select user,host FROM mysql.user;"
  echo -e
  $MYSQL_BIN -uroot -p$mysql_pwd -D mysql -e "select * from mysql.user where length(authentication_string) = 0 or authentication_string is null;"
  echo -e
  $MYSQL_BIN -uroot -p$mysql_pwd -D mysql -e "show variables like 'validate%';"
  echo -e
  $MYSQL_BIN -uroot -p$mysql_pwd -D mysql -e "show VARIABLES like '%password%';"
  echo -e
  $MYSQL_BIN -uroot -p$mysql_pwd -D mysql -e "show variables like '%max_connect_errors%';"
  echo -e
  $MYSQL_BIN -uroot -p$mysql_pwd -D mysql -e "show variables like '%have_ssl%';"
  echo -e
  $MYSQL_BIN -uroot -p$mysql_pwd -D mysql -e "show grants for 'root'@'localhost';"
  echo -e
  echo -e "select * from mysql.user where user = 'root';"
  echo -e
  $MYSQL_BIN -uroot -p$mysql_pwd -D mysql -e "select * from mysql.user where user = 'root';"
  echo -e
  $MYSQL_BIN -uroot -p$mysql_pwd -D mysql -e "show variables where variable_name like 'version';"
  echo -e
  echo -e "******************************** Mysql checking end ********************************"
  echo -e
}

# ******************************************************************
# PostgreSQL数据库核查，参数 -pgsql 执行该方法。
# ******************************************************************
pgsql_ceping()
{
  [ ! -n "$PGSQL" ] && LogErrorMsg "Not found PostgreSQL database,please run '${0} -l'" 1>&2 && exit 1
  LogMsg "Checking PostgreSQL database system......" 1>&2
  echo -e
  echo -e "******************************** PostgreSQL checking start ********************************"
  echo -e
  sqlFile=/tmp/tmp_postgres.sql
  PGDATA=`su - postgres << EOF 
cat ~/.bash_profile | grep PGDATA=
exit 
EOF`
  PGDATA=`echo -e ${PGDATA} | awk -F'PGDATA=' '{print $2}'`

  echo -e "\echo -e # ******************************************************************#" > ${sqlFile}
  echo -e "\echo -e # PostgreSQL version info" > ${sqlFile}
  echo -e "\echo -e # ******************************************************************#" > ${sqlFile}
  echo -e "select version();" > ${sqlFile}

  echo -e "\echo -e # ******************************************************************#" > ${sqlFile}
  echo -e "\echo -e # List of all instances" > ${sqlFile}
  echo -e "\echo -e # ******************************************************************#" > ${sqlFile}
  echo -e "\l" > ${sqlFile}

  echo -e "\echo -e # ******************************************************************#" > ${sqlFile}
  echo -e "\echo -e # List of all users info" > ${sqlFile}
  echo -e "\echo -e # ******************************************************************#" > ${sqlFile}
  echo -e "select * from pg_shadow;" > ${sqlFile}

  echo -e "\echo -e # ******************************************************************#" > ${sqlFile}
  echo -e "\echo -e # Access control function" > ${sqlFile}
  echo -e "\echo -e # ******************************************************************#" > ${sqlFile}
  echo -e "select * from pg_roles;" > ${sqlFile}
  echo -e "select * from information_schema.table_privileges where grantee='cc';" > ${sqlFile}

  echo -e "\echo -e # ******************************************************************#" > ${sqlFile}
  echo -e "\echo -e # Log and audit" > ${sqlFile}
  echo -e "\echo -e # ******************************************************************#" > ${sqlFile}
  echo -e "show log_destination; show log_connections; show log_disconnections; show log_statement; show logging_collector; show log_rotation_size; show log_rotation_age;" > ${sqlFile}

  echo -e "\echo -e # ******************************************************************#" > ${sqlFile}
  echo -e "\echo -e # PostgreSQL MISC" > ${sqlFile}
  echo -e "\echo -e # ******************************************************************#" > ${sqlFile}
  echo -e "select name, setting from pg_settings where context = 'user' order by 1;" > ${sqlFile}

  echo -e "\q" > ${sqlFile}
  chmod 777 ${sqlFile}
# 切换至postgres账户执行SQL语句，执行完毕后退回root账户
su - postgres << EOF
psql -d postgres -U postgres -f ${sqlFile}
exit
EOF
  rm -f ${sqlFile}
  
  echo -e
  echo -e "******************************************************************"
  echo -e "Check password module for ‘libdir/passwordcheck’"
  echo -e "******************************************************************"
  grep "passwordcheck" $PGDATA/postgresql.conf
  echo -e
  echo -e
  echo -e "******************************************************************"
  echo -e "Limit address"
  echo -e "******************************************************************"
  grep -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' $PGDATA/postgresql.conf
  grep "listen_addresses" $PGDATA/postgresql.conf
  echo -e
  echo -e
  echo -e "******************************************************************"
  echo -e "To see the first 10 rows of ‘$PGDATA/pg_log/’"
  echo -e "******************************************************************"
  pg_logfile=`ls $PGDATA/pg_log/ | grep -E 'postgresql-*' | tail -n 1`
  cat $PGDATA/pg_log/${pg_logfile} | tail -n 10
  echo -e
  echo -e
  echo -e "******************************************************************"
  echo -e "Login timeout"
  echo -e "******************************************************************"
  grep 'tcp_keepalives' $PGDATA/postgresql.conf
  echo -e
  echo -e
  echo -e "******************************************************************"
  echo -e "Max_connections and Shared_buffers"
  echo -e "******************************************************************"
  cat $PGDATA/postgresql.conf | grep -E 'max_connections|shared_buffers' | grep -Ev "^$|^[#;]"
  echo -e
  echo -e "******************************** PostgreSQL checking end ********************************"
  echo -e
}

# ******************************************************************
# Redis缓存数据库核查，测评内容暂未实现。
# ******************************************************************
redis_ceping()
{
  echo -e
  echo -e
  redis-server -v
  redis_conf=`find / -name "redis.conf"`
  cp $redis_conf ./
  echo -e
  echo -e
}

# ******************************************************************
# WEB容器或中间件核查，测评内容暂未实现。
# ******************************************************************
webserver_ceping()
{
  echo -e
  echo -e
  case $WEBSERVER in
        "nginx")
      nginx_cfg=`find / -name "nginx.conf" | grep -v tmp` 
      cp $nginx_cfg ./              ;;       
    "weblogic")
      echo -e "weblogic ceping function wait edit";;
    "apache")
      httpd_conf=$(find / -name httpd.conf)
      cp $httpd_conf  ./;;
    *)  echo -e "Not found web server!";;
    esac
  echo -e
  echo -e
}

# ******************************************************************
# 参数 -a 自动核查入口
# ******************************************************************
check_system()
{
  case $DISTRO in
        CentOS)
      redhat_or_centos_ceping;;    
        RedHat)
      redhat_or_centos_ceping;; 
    EulerOS)
      redhat_or_centos_ceping;;  
    Ubuntu)
      ubuntu_ceping;; 
    AIX)
      AIX_ceping;;
    esac
  
  [[ "Oracle" == "$ORACLE" ]] && oracle_ceping
  [[ "MySQL" == "$MYSQL" ]] && mysql_ceping
  [[ "PostgreSQL" == "$PGSQL" ]] && pgsql_ceping
  [[ $DBS == "Redis" ]] && redis_ceping
  [[ -n "$WEBSERVER" ]] && webserver_ceping
  LogSucMsg "Checking completed！" 1>&2
}


# ******************************************************************
# main_ceping 方法，脚本执行入口
# ******************************************************************
main_ceping()
{  
  print_logo
  # root账户执行核查，非root账户告警退出
  [ "`whoami`" != "root" ] && LogErrorMsg "Please use root user or sudo!" 1>&2 && exit 1
  case $1 in
        -h)
      helpinfo      ;;
    -l)    
      information_collection          ;;
    -o)
      oracle_ceping      ;;
    -m)
      mysql_ceping $2      ;;
    -pgsql)
      pgsql_ceping      ;;
    -s)
      get_webserver_info
      webserver_ceping    ;;
        -a)
      output_file_banner
      information_collection
      check_system      ;;
    *)  helpinfo                            ;;
    esac    
}

# main_ceping方法接收参数
main_ceping $1 $2