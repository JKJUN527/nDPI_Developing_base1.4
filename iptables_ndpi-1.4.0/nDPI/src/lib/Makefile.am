lib_LTLIBRARIES = libndpi.la

noinst_HEADERS = ../include/ndpi_main.h \
		../include/ndpi_protocol_history.h \
		../include/ndpi_protocols.h \
		../include/ndpi_structs.h \
		../include/ndpi_utils.h \
		../include/linux_compat.h


# this will create a library 1.4.0
LIB_AC=1
LIB_REV=4
LIB_ANC=0

# ntop
AM_CFLAGS=-fPIC

libndpi_la_CPPFLAGS = -I$(top_srcdir)/src/include/  -I$(top_srcdir)/src/lib/third_party/include/
libndpi_la_LDFLAGS=-version-info ${LIB_AC}:${LIB_REV}:${LIB_ANC}

libndpi_la_SOURCES = \
			third_party/src/ahocorasick.c \
			third_party/src/node.c \
			third_party/src/sort.c \
			ndpi_main.c \
			protocols/battlefield.c \
			protocols/bgp.c \
			protocols/bittorrent.c \
			protocols/dhcp.c \
			protocols/dhcpv6.c \
			protocols/dns.c \
			protocols/edonkey.c \
			protocols/flash.c \
			protocols/ftp_control.c \
			protocols/ftp_data.c \
			protocols/http_activesync.c \
			protocols/http.c \
			protocols/icecast.c \
			protocols/ipp.c \
			protocols/irc.c \
			protocols/jabber.c \
			protocols/ldap.c \
			protocols/mail_imap.c \
			protocols/mail_pop.c \
			protocols/mail_smtp.c \
			protocols/mdns.c \
			protocols/mgcp.c \
			protocols/mms.c \
			protocols/mssql.c \
			protocols/mysql.c \
			protocols/netbios.c \
			protocols/nfs.c \
			protocols/non_tcp_udp.c \
			protocols/tcp_udp.c \
			protocols/ntp.c \
			protocols/oscar.c \
			protocols/postgres.c \
			protocols/pplive.c \
			protocols/qqlive.c \
			protocols/ppstream.c \
			protocols/pptp.c \
			protocols/sohu.c \
			protocols/youku.c \
			protocols/qq.c \
			protocols/rdp.c \
			protocols/rtp.c \
			protocols/shoutcast.c \
			protocols/smb.c \
			protocols/snmp.c \
			protocols/sopcast.c \
			protocols/soulseek.c \
			protocols/ssdp.c \
			protocols/ssh.c \
			protocols/ssl.c \
			protocols/rip.c \
			protocols/l2tp.c \
			protocols/syslog.c \
			protocols/tds.c \
			protocols/telnet.c \
			protocols/tftp.c \
			protocols/thunder.c \
			protocols/tvants.c \
			protocols/tvuplayer.c \
			protocols/veohtv.c \
			protocols/world_of_warcraft.c \
			protocols/xbox.c \
			protocols/zattoo.c \
			protocols/dcerpc.c \
			protocols/radius.c \
			protocols/aliwangwang.c \
			protocols/baiduhi.c \
			protocols/wechat.c \
			protocols/funshion.c \
			protocols/nizhan.c \
			protocols/lol.c \
			protocols/dragonoath.c \ 
			protocols/wendao.c \
			protocols/tianxia3.c \
			protocols/haofang.c \
			protocols/cf.c \
			protocols/zhentu.c \
			protocols/zhengfu.c \
			protocols/dota2.c \
			protocols/jinwutuan.c \
			protocols/jizhan.c \
			protocols/tonghuashun.c \
			protocols/dazhihui365.c \
			protocols/huarong.c \
			protocols/qianlong.c \
			protocols/pinganzhengquan.c \
			protocols/zhinanzhen.c \
			protocols/zhaoshangzhengquan.c \
			protocols/tongdaxin.c\
			protocols/dingtalk.c \
			protocols/webqq.c \
			protocols/fetion.c \
			protocols/qqspeed.c \
			protocols/dnf.c \
			protocols/world_of_warship.c \
			protocols/jx3.c \
			protocols/eudemons.c \
			protocols/huashengke.c \
			protocols/qqmusic.c \
			protocols/qiannyh.c
			
#protocols/skype.c \
# NTOP protocols are at the end
