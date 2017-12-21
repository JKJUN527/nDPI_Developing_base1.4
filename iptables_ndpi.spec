Name: iptables_ndpi		
Version: 1.4.0	
Release: 39
Vendor: capsheaf
Summary: iptables ndpi mod based on 1.4
Group: flowmeter
Url: https://github.com/ntop/nDPI
License: GPL		
Source: %{name}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{vendor}-%{release}
BuildRequires: gcc,autoconf,automake,libpcap-devel,libtool,iptables-devel >= 1.4.7-10
Packager: capsheaf

%define debug no

%description
%{summary}
this is the core of app control


%prep
# unpack %{name}.tar.gz
%setup -c $RPM_BUILD_ROOT
# configure nDPI
pushd nDPI
./autogen.sh
./configure --enable-debug=%{debug}
popd


%build
# build nDPI
pushd nDPI
make
popd

# build flowmeter
pushd nDPI/example/
make clean
make
popd

# build xt_ndpi.ko
make

%install
mkdir -p $RPM_BUILD_ROOT/lib64/xtables
mkdir -p $RPM_BUILD_ROOT/lib/modules/$(uname -r)/kernel/net/netfilter
mkdir -p $RPM_BUILD_ROOT/etc/cron.daily/
mkdir -p $RPM_BUILD_ROOT/etc/ndpi
mkdir -p $RPM_BUILD_ROOT/var/log/flowmeter
install -o nobody -g nobody -d $RPM_BUILD_ROOT/var/efw/flowmeter/
touch $RPM_BUILD_ROOT/etc/ndpi/config

cat >> $RPM_BUILD_ROOT/etc/ndpi/config << EOF
IP_FILE=/var/efw/flowmeter/all_ip.txt
LOG_SIZE_FM=1048576900
MAX_USER_COUNT=131070
EOF

cat >> $RPM_BUILD_ROOT/etc/cron.daily/clearflowmeterlog << EOF
#!/bin/sh"
> /var/log/flowmeter/data_log_rt
exit 0
EOF

touch $RPM_BUILD_ROOT/var/efw/flowmeter/all_ip.txt
chown nobody:nobody  $RPM_BUILD_ROOT/var/efw/flowmeter/all_ip.txt
echo "192.168.0.0/24" > $RPM_BUILD_ROOT/var/efw/flowmeter/all_ip.txt
# echo "br0" > $RPM_BUILD_ROOT/var/efw/flowmeter/interfaces.txt

pushd nDPI/example/
install -D flowmeter  $RPM_BUILD_ROOT/usr/bin/flowmeter
install -D pcapReader  $RPM_BUILD_ROOT/usr/bin/pcapReader
popd

install -d $RPM_BUILD_ROOT/usr/local/bin/
# install  restartflowmeter.py $RPM_BUILD_ROOT/usr/local/bin/
# install  flowmeter_parser.py $RPM_BUILD_ROOT/usr/local/bin/
# mkdir $RPM_BUILD_ROOT/etc/rc.d/start/ -p
# echo "/usr/local/bin/restartflowmeter.py" > $RPM_BUILD_ROOT/etc/rc.d/start/99flowmeter
# echo "/usr/local/bin/flowmeter_parser.py" >> $RPM_BUILD_ROOT/etc/rc.d/start/99flowmeter
# echo "exit 0" >> $RPM_BUILD_ROOT/etc/rc.d/start/99flowmeter

# grep  -qEe "/usr/local/bin/restartflowmeter.py" /etc/sudoers || \
# echo "nobody  ALL=NOPASSWD: /usr/local/bin/restartflowmeter.py" >> /etc/sudoers

make install prefix=$RPM_BUILD_ROOT

# generate version file
mkdir -p $RPM_BUILD_ROOT/var/efw/unify_update/app_lib/
echo "version=`date '+%Y-%m-%d'`" > $RPM_BUILD_ROOT/var/efw/unify_update/app_lib/release

#sh autogen.sh 
#./configure --prefix=$RPM_BUILD_DIR  && make clean && make && make install
#cp ./all_ip.txt ./bpf.txt ./example/protos.txt $RPM_BUILD_ROOT/etc/ndpi/ -f

#app_ctrl
#chmod +x $fn
cp app_ctrl/* "$RPM_BUILD_ROOT" -rf

sort  -k 3 -t ',' -f -b $RPM_BUILD_ROOT/var/efw/objects/application/app_system -o $RPM_BUILD_ROOT/var/efw/objects/application/app_system
cat $RPM_BUILD_ROOT/var/efw/objects/application/app_system | awk '{split($0,arr,",");print arr[1],",",arr[3],",",arr[4],",",arr[0],arr[1],",","1";}' | tr -d ' ' > $RPM_BUILD_ROOT/var/efw/objects/application/app_rule
#rm $RPM_BUILD_ROOT/usr/local/bin/*pyc -vf

%clean

%pre

%post
grep  -qEe "/usr/bin/flowmeter" /etc/sudoers || \
echo "nobody  ALL=NOPASSWD: /usr/bin/flowmeter" >> /etc/sudoers
mkdir /var/log/flowmeter -p

#privilege
chown nobody:nobody $RPM_BUILD_ROOT/var/efw/unify_update
chown nobody:nobody $RPM_BUILD_ROOT/var/efw/unify_update/app_lib

echo "Loading module.."

# clear used ndpi rules
iptables -t mangle -D QOS -j NDPI
iptables -t mangle -S QOS | grep -v "\-N" |awk -F '-j ' '{cmd="iptables -t mangle -F "$2;print cmd;system(cmd)}'
iptables -t mangle -F POLICYROUTING
iptables -t mangle -F LOCALPOLICYROUTING
iptables -t filter -F APP_CTRL
iptables -t filter -I APP_CTRL -m state --state NEW -j DROP

modprobe -r xt_ndpi || echo "rmmod fail, you must rmmod custom or restart iptables or reboot"
depmod
modprobe xt_ndpi && echo "load mod ok"
ldconfig

# recover iptables
/usr/local/bin/run-detached /usr/local/bin/restartqos
/usr/local/bin/run-detached /usr/local/bin/app_ctrl.py -f
/usr/local/bin/run-detached /usr/local/bin/setpolicyrouting.py -f
/usr/local/bin/run-detached /usr/local/bin/restartflowmeter.py -f

#reset it 

echo "Load Over"

#app_ctrl
#echo "" >> /etc/sudoers
#grep -qEe "/usr/local/bin/application_get_tree.py" /etc/sudoers ||  echo "nobody  ALL=NOPASSWD: /usr/local/bin/application_get_tree.py" >> /etc/sudoers
#grep -qEe "/usr/local/bin/iface_util.py" /etc/sudoers ||  echo "nobody  ALL=NOPASSWD: /usr/local/bin/iface_util.py" >> /etc/sudoers
#grep -qEe "/usr/local/bin/getZoneJson.py" /etc/sudoers ||  echo "nobody  ALL=NOPASSWD: /usr/local/bin/getZoneJson.py" >> /etc/sudoers
#grep -qEe "/usr/local/bin/app_ctrl.py" /etc/sudoers ||  echo "nobody  ALL=NOPASSWD: /usr/local/bin/app_ctrl.py" >> /etc/sudoers
#grep -qEe "/usr/local/bin/app_ctrl_func.py" /etc/sudoers ||  echo "nobody  ALL=NOPASSWD: /usr/local/bin/app_ctrl_func.py" >> /etc/sudoers
#grep -qEe "/usr/local/bin/app_ctrl_convert.py" /etc/sudoers ||  echo "nobody  ALL=NOPASSWD: /usr/local/bin/app_ctrl_convert.py" >> /etc/sudoers
#grep -qEe "/usr/local/bin/iptables_tmpl.py" /etc/sudoers ||  echo "nobody  ALL=NOPASSWD: /usr/local/bin/iptables_tmpl.py" >> /etc/sudoers

cp -f /etc/rc.d/start/99ff_app_ctrl /etc/firewall/hooks/
cp -f /etc/rc.d/start/99ff_app_ctrl /etc/HA/backupshutservice/
cp -f /etc/rc.d/start/99ff_app_ctrl /etc/HA/masterservice/
cp -f /etc/rc.d/start/99ff_app_ctrl /etc/HA/faultshutservice/
/bin/sh /etc/rc.d/start/99ff_app_ctrl
install -o nobody -g nobody  -d /var/efw/appfilter
touch /var/efw/appfilter/config
chmod 755 /var/efw/appfilter/config
chown nobody:nobody /var/efw/appfilter/config

%preun
echo "Seperating xt_ndpi from iptables .."
#modprobe -r xt_ndpi && echo "Seperated OK"
#echo "Removing /lib/modules/2.6.32-431.el6.x86_64/kernel/net/netfilter/xt_ndpi.ko"
#rm -f /lib/modules/2.6.32-431.el6.x86_64/kernel/net/netfilter/xt_ndpi.ko
#echo "Removing /lib64/xtables/libipt_ndpi.so"
#rm -f /lib64/xtables/libipt_ndpi.so
#echo "Removed Over"
#echo "NDPI FILES:all_ip.txt bpf.txt protos.txt have been copied into /etc/ndpi"
#echo "You can use flowmeter_ndpi -i br0 -u /etc/ndpi/all_ip.txt to start it"
#echo "total ip SHOULD NOT LARGER THAN 500 !"
#echo "IF YOU WANT TO USE THIS CORRECT, ENSURE YOUR SERVER TIME IS SAME AS BEIJING!"

%files
%defattr(-,root,root)
#flowmeter
%attr(0755,root,root) /etc/cron.daily/clearflowmeterlog
%attr(-,nobody,nobody)/var/efw/unify_update/app_lib/*
%attr(0755,root,root) /etc/ndpi/*
%attr(0755,root,root) /usr/bin/*
%attr(0755,nobody,nobody) /var/efw/flowmeter/*
#iptables_ndpi
%attr(644,root,root)/lib/modules/2.6.32-431.el6.x86_64/kernel/net/netfilter/xt_ndpi.ko
%attr(755,root,root)/lib64/xtables/*.so

#app_ctrl
%defattr(-,nobody,nobody)
%attr(0644,nobody,nobody) %{_prefix}/../var/efw/objects/application/*
#%attr(0755,root,root) /usr/local/bin/*.py
%attr(0755,root,root) /etc/rc.d/start/99ff_app_ctrl
%attr(0755,root,root) /etc/AAA/script/99ff_app_ctrl
%doc

%changelog
* Wed Dec 20 2017 jiajun
- release:39
- 修复cf、twitter、facebook
* Tue Dec 5 2017 jiajun
- release:38
- 修复花生壳、战舰世界、大智慧365、招商证券、腾讯视频、酷6视频
* Wed Nov 21 2017 jiajun
- release:37.1
- 修复qq飞车、dota2、添加wegame游戏管理控制、修复系统崩溃
* Thu Nov 9 2017 jiajun
- release:37
- 修复ftp控制问题、酷狗音乐、战舰世界、将ssl流量归类为网络流量
* Tue Oct 30 2017 jiajun
- release:36
- 修改ftp_data支持流控，内部测试beta版
* Tue Oct 10 2017 jiajun
- release:35
- 修改app_ctrl\修复qq飞车--回归测试之前出现的bug，目前稳定
* Fri Sep 22 2017 jiajun
- release:34.5
- 新增CS：GO  天涯明月刀、qq飞车及魔域未识别问题、qqmusic流量控制、修复内核代码崩溃问题 

* Wed Sep 13 2017 jiajun
- release:34.4
- 新增qq音乐阻断、新增新倩女幽魂游戏 

* Wed Sep 13 2017 jiajun
- release:34.3
- 修复花生壳不能阻断识别问题、修复百度云网页版不能识别问题

* Wed Aug 30 2017 jiajun
- release:34.2
- 修复花生壳与smtp识别冲突、修改升级软件包时对qos链中-j NDPI 的处理
- 更新qq飞车、dnf，特征
- 更新tftp特征

* Wed Aug 30 2017 jiajun
- release:34.1
- 分离app_ctrl中脚本文件到app_ctrl RPM包

* Tue Aug 29 2017 jiajun
- release:33.2
- 加载模块时开启skb记录时间戳、修复天下3游戏登录不能阻断问题\
- 将app_ctrl包合并一起
* Thu Aug 24 2017 jiajun
- release:33.1
- 

* Thu Aug 24 2017 jiajun
- release:32.5
- 修改lru 删除释放节点、修复内存泄漏

* Thu Aug 24 2017 jiajun
- release:32.4
- 修改lru num 为1024
* Wed Aug 24 2017 jiajun
- release:32.3
- 修复腾讯视频误报、优酷视频网页版不能阻断，酷6网页版不能阻断
* Mon Aug 21 2017 jiajun
- release:32.2
- 修改l2tp协议

* Mon Aug 21 2017 pengtian
- release:32.1
- 删减webqq域名，修改flowmeter

* Mon Aug 21 2017 jkjun
- release:31.test8
- 新增qq飛車、DNF、战舰世界、魔域、剑网3等游戏的识别
- 修改内核关于对不同skb判断错误bug
- 修复流媒体软件包误报问题

* Mon Aug 07 2017 jkjun
- release:31.test7
- 修改游戏bug

* Wed Jun 30 2017 pengtian
- release:32.test
- change update spin_lock, update upgrage spec in post(policyrouting) and default to DROP in upgrading

* Wed Jun 30 2017 pengtian
- release:30
- change Makefile to clean some *.o *.cmd *.Plo, and change max protocols in ndpi_macro.h

* Fri Jun 23 2017 pengtian
- release:29
- add cb support, NDPI target(bugfix)

* Fri Jun 16 2017 jkjun
- release:26
- 更新了流量统计src和dst流量以及日志格式,增加清空流量统计每天的日志

* Thu Jun 15 2017 jkjun
- release:25.test3
- update funshion protocol close debug
* Tue Jun 08 2017 jkjun
- release:25.test2
- update thunder http protocol
- MUST USE WITH app_ctrl > 33 
* Tue Jun 06 2017 jkjun
- release:25.test1
- remove a log url protocol, update some protocol, move flowmeter to here
- MUST USE WITH app_ctrl > 33 
* Tue Jun 06 2017 jkjun
- release:25 
- remove a log url protocol, update some protocol, move flowmeter to here
- MUST USE WITH app_ctrl > 33 

* Fri May 26 2017 pengtian
- release:24 
- remove a log url protocol, update some protocol, move flowmeter to here
- MUST USE WITH app_ctrl > 23 

* Wed Feb 8 2017 pengtian
- release:23.full 
- update qq stage 
- MUST USE WITH app_ctrl-23.full

* Wed Feb 8 2017 pengtian
- release:22.full 
- MUST USE WITH app_ctrl-22.full

* Wed Jan 19 2017 pengtian- release:20.full 
- release:21.full 
- MUST USE WITH app_ctrl-21.full

* Wed Jan 11 2017 pengtian
- add a lot of protocols

* Mon Dec 5 2016 pengtian
- repair a bug when add sina result is sinaweibo

* Sun Dec 4 2016 pengtian
- upgdate thunder!!!  remove some longurl with "http://" prefix

* Mon Nov 21 2016 pengtian
- modify a kernel bug in HandleLongUrl which will cause kernel breakdown when curl 'xxxx.com'

* Wed Nov 10 2016 pengtian
- modify aliwangwang.c and some null name protocol

* Tue Nov 9 2016 pengtian
- add many protocol
- modify many exists protocol
- PS: qq is almost ok. but may has a bug to uneffective

* Wed Aug 31 2016 pengtian
- modify a bug: if use SSL will use as SSL_NO_CERT
- modify a bug
