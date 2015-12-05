# ndpiex
nDPI example

# Installation
The first step is download and compile the nDPI library:
```bash
cd ndpiex
git clone https://github.com/ntop/nDPI
cd nDPI
./configure –with-pic
make
cd ..
```
The second and last step is to compile ndpiex:
```bash
make
```

# Usage
./ndpiex -f file.pcap
