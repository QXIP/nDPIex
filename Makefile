all: ndpiex

ndpiex: ndpiex.c
	gcc -Wall -o ndpiex ndpiex.c -I./nDPI/src/include/ ./nDPI/src/lib/.libs/libndpi.a -lpcap

lib:
	gcc ndpiexlib.c -fPIC -shared -o ndpiexlib.so -I./nDPI/src/include/ ./nDPI/src/lib/.libs/libndpi.a -lndpi -lpcap

ndpi:
	@echo [ -d nDPI ] || git clone http://github.com/ntop/nDPI;
	cd nDPI; ./autogen.sh && ./configure && make

clean:
	rm -f ndpiex ndpiexlib.so *.o *~
