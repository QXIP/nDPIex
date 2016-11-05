#!/bin/bash

if [ ! -d "nDPI" ]; then
	git clone https://github.com/ntop/nDPI
fi
cd nDPI
git pull
./autogen.sh && ./configure -with-pic
make && make install
cd ..
make
make lib

