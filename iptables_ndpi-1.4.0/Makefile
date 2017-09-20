#PROTOS=--HTTP --Skype
#PROTOS=--Apple
#PROTOS1=--Skype --HTTP 
#PROTOS2=--NOT_YET
#PROTOS=--Unknown

PREFIX=$(prefix)

all:
	cd userland; make clean&&make
	cd kernel; make clean &&make

clean:
	cd userland; make clean
	cd kernel; make clean
	find . -name  "*~" |xargs rm -rf
	find . -name "*.*o" |xargs rm -rf

install:
	iptables -F FORWARD
	modprobe -r xt_ndpi || echo 'o_0'
	cd userland; make install prefix=$(PREFIX)
	cd kernel; make install prefix=$(PREFIX)
	insmod kernel/xt_ndpi.ko

ndpi:
	#svn co https://svn.ntop.org/svn/ntop/trunk/nDPI/
	#cd nDPI; ./configure; make
	cd nDPI
	make clean
	make

start: install
	# Remove
	modprobe -r xt_ndpi || echo 'o_0'
	# Insert
	modprobe xt_ndpi
	depmod
	#iptables -A INPUT -m ndpi $(PROTOS) -j DROP
	#iptables -A OUTPUT -m ndpi $(PROTOS) -j DROP
	#iptables -A INPUT -m ndpi $(PROTOS1) -j DROP
	#iptables -A OUTPUT -m ndpi $(PROTOS1) -j DROP
	#iptables -A INPUT -m ndpi $(PROTOS2) -j ACCEPT
	#iptables -A OUTPUT -m ndpi $(PROTOS2) -j ACCEPT
	#iptables -L -n

stop:
	iptables -F
	modprobe -r xt_ndpi
	> /var/log/messages
	#iptables -D INPUT 1
	#iptables -D OUTPUT 1
	#iptables -D INPUT 1
	#iptables -D OUTPUT 1
	#iptables -D INPUT 1
	#iptables -D OUTPUT 1

test_pre:
	#iptables -N PT || iptables -F PT
	#iptables -N ZL || iptables -F ZL
	iptables -N JK || iptables -F JK
	#iptables -I INPUT 1 -j ZL
	#iptables -I OUTPUT 1 -j ZL
	#iptables -I FORWARD 1 -j ZL
	#iptables -I INPUT 1 -j PT
	#iptables -I OUTPUT 1 -j PT
	iptables -I FORWARD 1 -j JK

test:
	make stop
<<<<<<< HEAD
	iptables -A FORWARD -m ndpi --protos nizhan -j REJECT
	#iptables -A FORWARD -m ndpi --protos ku6 -j REJECT
	#iptables -A FORWARD -m ndpi --protos jx3 -j REJECT
	#iptables -A FORWARD -m ndpi --protos qqspeed -j REJECT
	#iptables -A FORWARD -m ndpi --protos jx3 -j REJECT
	#iptables -A FORWARD -m ndpi --protos eudemons -j REJECT
	#iptables -A FORWARD -m ndpi --protos tianxia3 -j REJECT
	#iptables -A FORWARD -m ndpi --protos csgo -j REJECT
	#iptables -F FORWARD
	#> /var/log/messages
	#iptables -A FORWARD -m ndpi --protos QQMusic -j REJECT
=======
	iptables -A FORWARD -m ndpi --protos QQMusic -j REJECT
>>>>>>> origin/master
	watch -n 0.5 'iptables -S -v'
	#iptables -A JK -p udp --sport 12345 -j REJECT
m:
	iptables -F
	make test_end
	make stop
	make && make install
	make test_pre
	make test
	watch -n 0.5 'iptables -S -v'
test_end:
	#iptables -F WL 
	#iptables -F ZL
	iptables -F JK || echo '0_0'
go:
	make clean
	(cd userland;make clean ;make)
	make
	make test_end || echo 'o_0'
	make install
	make start
	make test
status:
	iptables -S -v
