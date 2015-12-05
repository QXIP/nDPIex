# nDPIex
nDPI example

# Installation
The first step is download and compile the nDPI library:
```bash
cd ndpiex
git clone https://github.com/ntop/nDPI
cd nDPI
./configure -with-pic
make
cd ..
```
Compile stand-alone ndpiex:
```bash
make
```

Compile binding ndpiexlib:
```bash
make lib
```

## Usage
```bash
./ndpiex -f file.pcap
```

### Lua FFI example
```bash
cd lua; ./run_lua
```
