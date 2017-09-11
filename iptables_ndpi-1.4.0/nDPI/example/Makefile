INC=-I../src/include/ -I./ -I /usr/include -I/usr/local/include

LIB=../src/lib/.libs/libndpi.a -lpcap
#CFILES= flowmeter_util.c flowmeter.c
FLAGS=-g
WALL=
pcapReader: clean
	#pcapReader.c Makefile ../src/lib/.libs/libndpi.a
	gcc $(WALL) $(FLAGS) $(INC) pcapReader.c -o pcapReader $(LIB) -lpthread
#fm:	
	#gcc $(WALL) $(FLAGS) $(INC) $(CFILES) -o flowmeter $(LIB) -lpthread -lm -ljson -liLOG3

clean:
	\/bin/rm -f pcapReader
	\/bin/rm -f flowmeter

