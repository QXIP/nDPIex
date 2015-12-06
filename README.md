# nDPIex
nDPI example collection

| Version        | Status      | 
| ------------- |:------------:| 
| 0.1    | experimental | 



# Installation
Compile latest nDPI from github:
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

Compile FFI binding ndpiexlib:
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

### Node FFI example
```bash
cd nodejs; npm install && npm start
```
