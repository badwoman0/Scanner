todo:
1.  协议规则补充
2.  设备指纹解析


bugs:
1.  ssl连接设置超时的问题
2.  从yaml解析规则应直接解析为字节切片


查询ip详细信息：
ipinfo.GetIPinfo() 函数，应保证每个ip只查一次








├── aix
│   ├── local
│   ├── rpc_cmsd_opcode21.rb
│   └── rpc_ttdbserverd_realpath.rb
├── android
│   ├── adb
│   ├── browser
│   ├── fileformat
│   └── local
├── apple_ios
│   ├── browser
│   ├── email
│   └── ssh
├── bsd
│   └── finger
├── bsdi
│   └── softcart
├── dialup
│   └── multi
├── example.py
├── example.rb
├── example_linux_priv_esc.rb
├── example_webapp.rb
├── firefox
│   └── local
├── freebsd
│   ├── ftp
│   ├── http
│   ├── local
│   ├── misc
│   ├── samba
│   ├── tacacs
│   ├── telnet
│   └── webapp
├── hpux
│   └── lpd
├── irix
│   └── lpd
├── linux
│   ├── antivirus
│   ├── browser
│   ├── fileformat
│   ├── ftp
│   ├── games
│   ├── http
│   ├── ids
│   ├── imap
│   ├── local
│   ├── misc
│   ├── mysql
│   ├── pop3
│   ├── postgres
│   ├── pptp
│   ├── proxy
│   ├── redis
│   ├── samba
│   ├── smtp
│   ├── snmp
│   ├── ssh
│   ├── telnet
│   └── upnp
├── mainframe
│   └── ftp
├── multi
│   ├── browser
│   ├── elasticsearch
│   ├── fileformat
│   ├── ftp
│   ├── gdb
│   ├── hams
│   ├── handler.rb
│   ├── http
│   ├── ids
│   ├── kubernetes
│   ├── local
│   ├── misc
│   ├── mysql
│   ├── ntp
│   ├── php
│   ├── postgres
│   ├── realserver
│   ├── samba
│   ├── sap
│   ├── scada
│   ├── script
│   ├── ssh
│   ├── svn
│   ├── upnp
│   ├── vnc
│   ├── vpn
│   └── wyse
├── netware
│   ├── smb
│   └── sunrpc
├── openbsd
│   └── local
├── osx
│   ├── afp
│   ├── arkeia
│   ├── browser
│   ├── email
│   ├── ftp
│   ├── http
│   ├── local
│   ├── mdns
│   ├── misc
│   ├── rtsp
│   └── samba
├── qnx
│   ├── local
│   └── qconn
├── solaris
│   ├── dtspcd
│   ├── local
│   ├── lpd
│   ├── samba
│   ├── ssh
│   ├── sunrpc
│   └── telnet
├── unix
│   ├── dhcp
│   ├── fileformat
│   ├── ftp
│   ├── http
│   ├── irc
│   ├── local
│   ├── misc
│   ├── smtp
│   ├── sonicwall
│   ├── ssh
│   ├── webapp
│   └── x11
└── windows
    ├── antivirus
    ├── arkeia
    ├── backdoor
    ├── backupexec
    ├── brightstor
    ├── browser
    ├── dcerpc
    ├── email
    ├── emc
    ├── fileformat
    ├── firewall
    ├── ftp
    ├── games
    ├── http
    ├── ibm
    ├── iis
    ├── imap
    ├── isapi
    ├── ldap
    ├── license
    ├── local
    ├── lotus
    ├── lpd
    ├── misc
    ├── mmsp
    ├── motorola
    ├── mssql
    ├── mysql
    ├── nfs
    ├── nimsoft
    ├── nntp
    ├── novell
    ├── nuuo
    ├── oracle
    ├── pop3
    ├── postgres
    ├── proxy
    ├── rdp
    ├── sage
    ├── scada
    ├── sip
    ├── smb
    ├── smtp
    ├── ssh
    ├── ssl
    ├── telnet
    ├── tftp
    ├── unicenter
    ├── vnc
    ├── vpn
    ├── winrm
    └── wins


可能存在的问题
1.  性质等于让msf重新做了一次设备识别
2.  结果可能有矛盾，例如设备指纹为nginx的机器上扫出来apache的漏洞# Scanner
