#
# (C) 2013 - ntop.org
#

INC=-I../kernel -I../nDPI/src/include -I../include
LIB=../nDPI/src/lib/.libs/libndpi.a
CFLAGS = -fPIC -I../include -O2 -Wall
PREFIX=$(prefix)
XTBL := $(shell pkg-config --variable=xtlibdir xtables)

#EXISTS=$(shell if [ ! -d $(PREFIX)/lib64/xtables ];then echo "n" ; else echo 'y' ; fi ; )
########


all: libipt_ndpi.so

install:
	echo $(XTBL)
	if [ -n "$(PREFIX)$(XTBL)" -a -d "$(PREFIX)$(XTBL)" ]; then install -v libipt_ndpi.so $(PREFIX)$(XTBL); ln -fs libipt_ndpi.so $(PREFIX)$(XTBL)/libxt_NDPI.so ; else echo "No pkg-config --variable=xtlibdir xtables"; fi

lib%.so: lib%.o
	$(CC) -shared -o $@ $^ $(LIB)

lib%.o: lib%.c
	$(CC) $(CFLAGS) $(INC) -D_INIT=lib$*_init -c -o $@ $<

#install:
	
	#ifeq ( $(EXISTS) , "n" )
	#	mkdir $(PREFIX)/lib64/xtables
	#endif
	#cp libipt_ndpi.so $(PREFIX)/lib64/xtables -f

unistall:
	rm -f $(PREFIX)/lib64/xtables/libipt_ndpi.so
clean:
	/bin/rm -f *.o *.so *~
