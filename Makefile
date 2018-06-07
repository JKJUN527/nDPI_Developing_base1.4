PREFIX=$(prefix)

# complie only
all:
	cd nDPI; make
	cd userland; make clean&&make
	cd kernel; make clean &&make

# install to disk
install:
	cd userland; make install prefix=$(PREFIX)
	cd kernel; make install prefix=$(PREFIX)

# insmod xt_ndpi.ko
insmod: stop install
	insmod kernel/xt_ndpi.ko

# build ndpi
ndpi:
	(cd nDPI; \
	./autogen.sh; \
	./configure; \
	make clean; \
	make; )

start: install
	# Remove
	-modprobe -r xt_ndpi
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
	-rmmod xt_ndpi
	> /var/log/messages

# just for test
test: insmod
	iptables -I FORWARD  -j NDPI
	iptables -A FORWARD  -m ndpi --protos wechattx -j DROP
	#iptables -A FORWARD  -m ndpi --protos dahuaxiyou2 -j DROP
	watch -n 0.5 'iptables -S -v'
status:
	iptables -S -v

clean:
	cd userland; make clean
	cd kernel; make clean
	find . -name  "*~" |xargs rm -rf
	find . -name "*.*o" |xargs rm -rf
	rm -rf rpmbuild/
	rm -rf *.rpm

prep:
	mkdir -p ./rpmbuild/{SOURCES,RPMS,SRPMS}
tar: prep
	git archive --format=tar.gz HEAD > ./rpmbuild/SOURCES/iptables_ndpi.tar.gz
# build rpm package
rpm: tar
	rpmbuild -D "_topdir $(PWD)/rpmbuild" -ba iptables_ndpi.spec
	find ./rpmbuild -name '*.rpm' -exec cp {} ./ \;
	rm -rf ./rpmbuild

.PHONY: prep rpm clean tar
