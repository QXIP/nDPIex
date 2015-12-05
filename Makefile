all: ndpiex

ndpiex: ndpiex.c
	gcc -Wall -o ndpiex ndpiex.c -I./nDPI/src/include/ ./nDPI/src/lib/.libs/libndpi.a -lpcap

clean:
	rm -f ndpiex *.o *~
