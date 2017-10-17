#
# (C) 2013 - Luca Deri <deri@ntop.org>
#

ifneq (, $(shell which svnversion))
SVNDEF := -DSVN_REV="\"$(shell svnversion -n .)\""
endif

ifeq (,$(BUILD_KERNEL))
BUILD_KERNEL=$(shell uname -r)
endif
PREFIX=$(prefix)
PWD=$(shell pwd)
HERE=$(PWD)
NDPI_HOME=../nDPI
#NDPI_HOME=/home/deri/iptables_ndpi/nDPI

INSTDIR :=$(PREFIX)/lib/modules/$(BUILD_KERNEL)/kernel/net/netfilter/
NDPI_LIB=$(NDPI_HOME)/src/lib
NDPI_LIB_PROTOCOLS=$(NDPI_LIB)/protocols
NDPI_INCLUDE=$(NDPI_HOME)/src/include

EXTRA_CFLAGS += -I$(PWD) -I$(PWD)/$(NDPI_INCLUDE) -I$(PWD)/$(NDPI_LIB)/third_party/include $(SVNDEF) #-DNDPI_ENABLE_DEBUG_MESSAGES

NDPI_LIB_OBJS= \
	$(NDPI_LIB)/third_party/src/ahocorasick.o \
	$(NDPI_LIB)/third_party/src/node.o \
	$(NDPI_LIB)/third_party/src/sort.o \
	$(NDPI_LIB)/ndpi_main.o \
	$(NDPI_LIB_PROTOCOLS)/battlefield.o \
	$(NDPI_LIB_PROTOCOLS)/bgp.o \
	$(NDPI_LIB_PROTOCOLS)/bittorrent.o \
	$(NDPI_LIB_PROTOCOLS)/dhcp.o \
	$(NDPI_LIB_PROTOCOLS)/dhcpv6.o \
	$(NDPI_LIB_PROTOCOLS)/dns.o \
	$(NDPI_LIB_PROTOCOLS)/edonkey.o \
	$(NDPI_LIB_PROTOCOLS)/flash.o \
	$(NDPI_LIB_PROTOCOLS)/ftp_control.o \
	$(NDPI_LIB_PROTOCOLS)/ftp_data.o \
	$(NDPI_LIB_PROTOCOLS)/http_activesync.o \
	$(NDPI_LIB_PROTOCOLS)/http.o \
	$(NDPI_LIB_PROTOCOLS)/icecast.o \
	$(NDPI_LIB_PROTOCOLS)/ipp.o \
	$(NDPI_LIB_PROTOCOLS)/irc.o \
	$(NDPI_LIB_PROTOCOLS)/jabber.o \
	$(NDPI_LIB_PROTOCOLS)/ldap.o \
	$(NDPI_LIB_PROTOCOLS)/mail_imap.o \
	$(NDPI_LIB_PROTOCOLS)/mail_pop.o \
	$(NDPI_LIB_PROTOCOLS)/mail_smtp.o \
	$(NDPI_LIB_PROTOCOLS)/mdns.o \
	$(NDPI_LIB_PROTOCOLS)/mgcp.o \
	$(NDPI_LIB_PROTOCOLS)/mms.o \
	$(NDPI_LIB_PROTOCOLS)/mssql.o \
	$(NDPI_LIB_PROTOCOLS)/mysql.o \
	$(NDPI_LIB_PROTOCOLS)/netbios.o \
	$(NDPI_LIB_PROTOCOLS)/nfs.o \
	$(NDPI_LIB_PROTOCOLS)/non_tcp_udp.o \
	$(NDPI_LIB_PROTOCOLS)/tcp_udp.o \
	$(NDPI_LIB_PROTOCOLS)/ntp.o \
	$(NDPI_LIB_PROTOCOLS)/oscar.o \
	$(NDPI_LIB_PROTOCOLS)/postgres.o \
	$(NDPI_LIB_PROTOCOLS)/pplive.o \
	$(NDPI_LIB_PROTOCOLS)/qqlive.o \
	$(NDPI_LIB_PROTOCOLS)/ppstream.o \
	$(NDPI_LIB_PROTOCOLS)/pptp.o \
	$(NDPI_LIB_PROTOCOLS)/sohu.o \
	$(NDPI_LIB_PROTOCOLS)/youku.o \
	$(NDPI_LIB_PROTOCOLS)/qq.o \
	$(NDPI_LIB_PROTOCOLS)/rdp.o \
	$(NDPI_LIB_PROTOCOLS)/rtp.o \
	$(NDPI_LIB_PROTOCOLS)/shoutcast.o \
	$(NDPI_LIB_PROTOCOLS)/smb.o \
	$(NDPI_LIB_PROTOCOLS)/snmp.o \
	$(NDPI_LIB_PROTOCOLS)/sopcast.o \
	$(NDPI_LIB_PROTOCOLS)/soulseek.o \
	$(NDPI_LIB_PROTOCOLS)/ssdp.o \
	$(NDPI_LIB_PROTOCOLS)/ssh.o \
	$(NDPI_LIB_PROTOCOLS)/ssl.o \
	$(NDPI_LIB_PROTOCOLS)/l2tp.o \
	$(NDPI_LIB_PROTOCOLS)/rip.o \
	$(NDPI_LIB_PROTOCOLS)/syslog.o \
	$(NDPI_LIB_PROTOCOLS)/tds.o \
	$(NDPI_LIB_PROTOCOLS)/telnet.o \
	$(NDPI_LIB_PROTOCOLS)/tftp.o \
	$(NDPI_LIB_PROTOCOLS)/thunder.o \
	$(NDPI_LIB_PROTOCOLS)/tvants.o \
	$(NDPI_LIB_PROTOCOLS)/tvuplayer.o \
	$(NDPI_LIB_PROTOCOLS)/veohtv.o \
	$(NDPI_LIB_PROTOCOLS)/world_of_warcraft.o \
	$(NDPI_LIB_PROTOCOLS)/xbox.o \
	$(NDPI_LIB_PROTOCOLS)/zattoo.o \
	$(NDPI_LIB_PROTOCOLS)/dcerpc.o \
	$(NDPI_LIB_PROTOCOLS)/radius.o \
	$(NDPI_LIB_PROTOCOLS)/aliwangwang.o \
	$(NDPI_LIB_PROTOCOLS)/baiduhi.o \
	$(NDPI_LIB_PROTOCOLS)/wechat.o \
	$(NDPI_LIB_PROTOCOLS)/funshion.o \
	$(NDPI_LIB_PROTOCOLS)/nizhan.o \
	$(NDPI_LIB_PROTOCOLS)/lol.o \
	$(NDPI_LIB_PROTOCOLS)/dragonoath.o \
	$(NDPI_LIB_PROTOCOLS)/wendao.o \
	$(NDPI_LIB_PROTOCOLS)/tianxia3.o \
	$(NDPI_LIB_PROTOCOLS)/haofang.o \
	$(NDPI_LIB_PROTOCOLS)/cf.o \
	$(NDPI_LIB_PROTOCOLS)/zhentu.o \
	$(NDPI_LIB_PROTOCOLS)/zhengfu.o \
	$(NDPI_LIB_PROTOCOLS)/dota2.o \
	$(NDPI_LIB_PROTOCOLS)/jinwutuan.o \
	$(NDPI_LIB_PROTOCOLS)/jizhan.o \
	$(NDPI_LIB_PROTOCOLS)/tonghuashun.o \
	$(NDPI_LIB_PROTOCOLS)/dazhihui365.o \
	$(NDPI_LIB_PROTOCOLS)/huarong.o \
	$(NDPI_LIB_PROTOCOLS)/qianlong.o \
	$(NDPI_LIB_PROTOCOLS)/pinganzhengquan.o \
	$(NDPI_LIB_PROTOCOLS)/zhinanzhen.o \
	$(NDPI_LIB_PROTOCOLS)/zhaoshangzhengquan.o \
	$(NDPI_LIB_PROTOCOLS)/tongdaxin.o \
	$(NDPI_LIB_PROTOCOLS)/dingtalk.o \
	$(NDPI_LIB_PROTOCOLS)/webqq.o \
	$(NDPI_LIB_PROTOCOLS)/fetion.o \
	$(NDPI_LIB_PROTOCOLS)/qqspeed.o \
	$(NDPI_LIB_PROTOCOLS)/dnf.o \
	$(NDPI_LIB_PROTOCOLS)/world_of_warship.o \
	$(NDPI_LIB_PROTOCOLS)/jx3.o \
	$(NDPI_LIB_PROTOCOLS)/eudemons.o \
	$(NDPI_LIB_PROTOCOLS)/huashengke.o \
	$(NDPI_LIB_PROTOCOLS)/qqmusic.o \
	$(NDPI_LIB_PROTOCOLS)/qiannyh.o \
	$(NDPI_LIB_PROTOCOLS)/qqwuxia.o \
	$(NDPI_LIB_PROTOCOLS)/csgo.o \
	$(NDPI_LIB_PROTOCOLS)/minecraft.o \
	$(NDPI_LIB_PROTOCOLS)/kugou_music.o \
	$(NDPI_LIB_PROTOCOLS)/yy.o

#	$(NDPI_LIB_PROTOCOLS)/skype.o \
SRC=lru.c lru.h ndpi.c ndpi.h main.c
OBJS=main.o ndpi.o lru.o

obj-m := xt_ndpi.o 
xt_ndpi-y := $(OBJS) $(NDPI_LIB_OBJS)
#ccflags-y += -I$(NDPI_HOME)/src/lib -I$(NDPI_HOME)/src/protocols

all: Makefile $(SRC)
	@if test "$(USER)" = "root"; then \
		echo "********** WARNING WARNING WARNING **********"; \
		echo "*"; \
		echo "* Compiling as root might lead you to compile errors"; \
		echo "* Please compile as unpriviliged user"; \
		echo "*"; \
		echo "*********************************************"; \
	fi
	make -C /lib/modules/$(BUILD_KERNEL)/build SUBDIRS=$(HERE) EXTRA_CFLAGS='$(EXTRA_CFLAGS)' modules

ln:
	ln -s $(NDPI_LIB)/*\.o .

install:
	cp xt_ndpi.ko $(INSTDIR)
	depmod

clean:
	make -C /lib/modules/$(BUILD_KERNEL)/build SUBDIRS=$(HERE) clean
	\rm -f *~ Module.symvers  Module.markers  modules.order *# *.o

