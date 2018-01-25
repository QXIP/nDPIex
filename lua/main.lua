#!/usr/bin/luajit

-- ndpi lua binding
-- Usage: luajit main.lua /path/to/file.pcap

local arg = ...
local pfile = ""

if arg==nil then
   pfile = "../pcap/lamernews.pcap"
else
   pfile = arg
end

print("Loading " .. pfile )

local ffi = require('ffi')
local C = ffi.C

local ndpi = ffi.load("../ndpiexlib.so")
local pcap = ffi.load("pcap")

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

/* NDPIReader */
typedef void (*callback)(int, const uint8_t *packet);

void addProtocolHandler(callback handler);
void init();
void setDatalinkType(pcap_t *handle);
void processPacket(const struct pcap_pkthdr *header, const uint8_t *packet);
void finish();

]])

local L7PROTO = {
"Unknown","FTP_CONTROL","POP3","SMTP","IMAP","DNS","IPP","HTTP","MDNS","NTP","NetBIOS","NFS","SSDP","BGP","SNMP","XDMCP","SMB","Syslog","DHCP","PostgreSQL","MySQL","TDS","Direct_Download_Link","POPS","AppleJuice","DirectConnect","Socrates","WinMX","VMware","SMTPS","Filetopia","iMESH","Kontiki","OpenFT","FastTrack","Gnutella","eDonkey","BitTorrent","EPP","AVI","Flash","OggVorbis","MPEG","QuickTime","RealMedia","WindowsMedia","MMS","Xbox","QQ","Move","RTSP","IMAPS","IceCast","PPLive","PPStream","Zattoo","ShoutCast","Sopcast","Tvants","TVUplayer","HTTP_APPLICATION_VEOHTV","QQLive","Thunder","Soulseek","SSL_No_Cert","IRC","Ayiya","Unencryped_Jabber","MSN","Oscar","Yahoo","BattleField","Quake","VRRP","Steam","HalfLife2","WorldOfWarcraft","Telnet","STUN","IPsec","GRE","ICMP","IGMP","EGP","SCTP","OSPF","IP_in_IP","RTP","RDP","VNC","PcAnywhere","SSL","SSH","Usenet","MGCP","IAX","TFTP","AFP","Stealthnet","Aimini","SIP","TruPhone","ICMPV6","DHCPV6","Armagetron","Crossfire","Dofus","Fiesta","Florensia","Guildwars","HTTP_Application_ActiveSync","Kerberos","LDAP","MapleStory","MsSQL","PPTP","Warcraft3","WorldOfKungFu","Meebo","Facebook","Twitter","DropBox","GMail","GoogleMaps","YouTube","Skype","Google","DCE_RPC","NetFlow","sFlow","HTTP_Connect","HTTP_Proxy","Citrix","NetFlix","LastFM","GrooveShark","SkyFile_PrePaid","SkyFile_Rudics","SkyFile_PostPaid","Citrix_Online","Apple","Webex","WhatsApp","AppleiCloud","Viber","AppleiTunes","Radius","WindowsUpdate","TeamViewer","Tuenti","LotusNotes","SAP","GTP","UPnP","LLMNR","RemoteScan","Spotify","WebM","H323","OpenVPN","NOE","CiscoVPN","TeamSpeak","TOR","CiscoSkinny","RTCP","RSYNC","Oracle","Corba","UbuntuONE","Whois-DAS","Collectd","SOCKS5","SOCKS4","RTMP","FTP_DATA","Wikipedia","ZeroMQ","Amazon","eBay","CNN","Megaco","Redis","Pando_Media_Booster","VHUA","Telegram","FacebookChat","Pandora","Vevo",
}

function onProtocol(id, packet)
   if id >= 2 then
	   io.write("Proto: ")
	   print(  ffi.string(packet), "ID:", id)
   end
end

-- Register protocol handler
ndpi.addProtocolHandler(onProtocol)

local pcap = ffi.load("pcap")

local filename = pfile
local fname = ffi.new("char[?]", #filename, filename)
local errbuf = ffi.new("char[512]")

-- Read pcap file
local handle = pcap.pcap_open_offline(fname, errbuf)
if handle == nil then
   C.printf(errbuf)
end

ndpi.init()
ndpi.setDatalinkType(handle)

local header = ffi.new("struct pcap_pkthdr")
-- Inspect each packet
local total_packets = 0
while (1) do
   local packet = pcap.pcap_next(handle, header)
   if packet == nil then break end
   ndpi.processPacket(header, packet)
   total_packets = total_packets + 1
end
pcap.pcap_close(handle)

-- Print results
ndpi.finish()

print("Total packets: "..total_packets)

