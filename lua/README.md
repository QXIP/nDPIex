# nDPI Lua FFI example

* Requires ```ndpiexlib```

```
./run_lua
```

### nDPIex FFI Binding
```
ffi.cdef([[
/* Pcap */
typedef struct pcap pcap_t;
struct pcap_pkthdr {
  uint64_t ts_sec;         /* timestamp seconds */
  uint64_t ts_usec;        /* timestamp microseconds */
  uint32_t incl_len;       /* number of octets of packet saved in file */
  uint32_t orig_len;       /* actual length of packet */
};

int printf(const char *format, ...);
pcap_t *pcap_open_offline(const char *fname, char *errbuf);
void pcap_close(pcap_t *p);
const uint8_t *pcap_next(pcap_t *p, struct pcap_pkthdr *h);

typedef void (*callback)(int, const uint8_t *packet);

void addProtocolHandler(callback handler);
void init();
void setDatalinkType(pcap_t *handle);
void processPacket(const struct pcap_pkthdr *header, const uint8_t *packet);
void finish();

]])

```
