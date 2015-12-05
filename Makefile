all: ndpiex

ndpiex: ndpiex.c
	gcc -Wall -o ndpiex ndpiex.c -I./nDPI/src/include/ ./nDPI/src/lib/.libs/libndpi.a -lpcap
lib:
	gcc ndpiexlib.c -fPIC -shared -o ndpiexlib.so -I./nDPI/src/include/ ./nDPI/src/lib/.libs/libndpi.a -lndpi -lpcap

clean:
	rm -f ndpiex ndpiexlib.so *.o *~
