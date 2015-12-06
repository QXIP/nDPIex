/*  nDPI Node.js Binding PoC 	*/
/*  (c) 2015 QXIP BV 		*/
/*  http://qxip.net 		*/

var VERSION = "0.1.1";

/* NODE REQs */ 

var ref = require('ref');
var ffi = require('ffi');
var Struct = require('ref-struct');
var ArrayType = require('ref-array');

var pcap = require("pcap"),
    pcap_session = pcap.createSession("", "");


/* NDPI CALLBACK */

// On Windows UTF-16 (2-bytes), Unix UTF-32 (4-bytes)
var wchar_size = process.platform == 'win32' ? 2 : 4

var wchar_t = Object.create(ref.types.CString);
wchar_t.get = function get (buf, offset) {
  var _buf = buf.readPointer(offset)
  if (_buf.isNull()) {
    return;
  }
  var stringBuf = _buf.reinterpretUntilZeros(wchar_size)
  return stringBuf.toString('win32' ? 'utf16le' : 'utf32li') // TODO: decode UTF-32 on Unix
};

wchar_t.set = function set (buf, offset, val) {
  // TODO: better UTF-16 and UTF-32 encoding
  var _buf = new Buffer((val.length + 1) * wchar_size)
  _buf.fill(0)
  var l = 0
  for (var i = wchar_size - 1; i < _buf.length; i += wchar_size) {
    _buf[i] = val.charCodeAt(l++)
  }
  return buf.writePointer(_buf, offset)
};

var callback_Ptr = ArrayType(wchar_t);

/* APP VARS */

var voidPtr = exports.voidPtr = ref.refType(ref.types.void);
var u_char = exports.u_char = Struct({
  __u_char: ref.types.uchar,
});
var u_charPtr = exports.u_charPtr = ref.refType(u_char);

var uint8_t = exports.uint8_t = voidPtr;
var uint8_tPtr = exports.uint8_tPtr = ref.refType(uint8_t);

var callback = exports.callback = ffi.Function(ref.types.void, [
  ref.types.int32,
  ref.refType(ref.types.uchar),
]);

var pcap_t = exports.pcap_t = voidPtr;
var pcap_tPtr = exports.pcap_tPtr = ref.refType(pcap_t);
var pcap_handler = exports.pcap_handler = ffi.Function(ref.types.void, [
  ref.refType(ref.types.uchar),
  voidPtr,
  ref.refType(ref.types.uchar),
]);
var pcap_handlerPtr = exports.pcap_handlerPtr = ref.refType(pcap_handler);

// PCAP Header
var pcap_pkthdr = Struct({
  'ts_sec': 'long', 
  'ts_usec': 'long',
  'incl_len': 'int',
  'orig_len': 'int'
});

var pktHdr = new pcap_pkthdr;
pktHdr = ref.refType(ref.types.void);

var ndpi = exports.ndpi = new ffi.Library('../ndpiexlib.so', {
  init: [ref.types.void, [
  ]],
  setDatalinkType: [ref.types.void, [
      pcap_tPtr,
  ]],
  processPacket: [ref.types.void, [
    voidPtr,
    uint8_t,
  ]],
  finish: [ref.types.void, [
  ]],
  addProtocolHandler: [ref.types.void, [
    callback
  ]],
});

var L7PROTO = [
"Unknown","FTP_CONTROL","POP3","SMTP","IMAP","DNS","IPP","HTTP","MDNS","NTP","NetBIOS","NFS","SSDP","BGP","SNMP","XDMCP","SMB","Syslog","DHCP","PostgreSQL","MySQL","TDS","Direct_Download_Link","POPS","AppleJuice","DirectConnect","Socrates","WinMX","VMware","SMTPS","Filetopia","iMESH","Kontiki","OpenFT","FastTrack","Gnutella","eDonkey","BitTorrent","EPP","AVI","Flash","OggVorbis","MPEG","QuickTime","RealMedia","WindowsMedia","MMS","Xbox","QQ","Move","RTSP","IMAPS","IceCast","PPLive","PPStream","Zattoo","ShoutCast","Sopcast","Tvants","TVUplayer","HTTP_APPLICATION_VEOHTV","QQLive","Thunder","Soulseek","SSL_No_Cert","IRC","Ayiya","Unencryped_Jabber","MSN","Oscar","Yahoo","BattleField","Quake","VRRP","Steam","HalfLife2","WorldOfWarcraft","Telnet","STUN","IPsec","GRE","ICMP","IGMP","EGP","SCTP","OSPF","IP_in_IP","RTP","RDP","VNC","PcAnywhere","SSL","SSH","Usenet","MGCP","IAX","TFTP","AFP","Stealthnet","Aimini","SIP","TruPhone","ICMPV6","DHCPV6","Armagetron","Crossfire","Dofus","Fiesta","Florensia","Guildwars","HTTP_Application_ActiveSync","Kerberos","LDAP","MapleStory","MsSQL","PPTP","Warcraft3","WorldOfKungFu","Meebo","Facebook","Twitter","DropBox","GMail","GoogleMaps","YouTube","Skype","Google","DCE_RPC","NetFlow","sFlow","HTTP_Connect","HTTP_Proxy","Citrix","NetFlix","LastFM","GrooveShark","SkyFile_PrePaid","SkyFile_Rudics","SkyFile_PostPaid","Citrix_Online","Apple","Webex","WhatsApp","AppleiCloud","Viber","AppleiTunes","Radius","WindowsUpdate","TeamViewer","Tuenti","LotusNotes","SAP","GTP","UPnP","LLMNR","RemoteScan","Spotify","WebM","H323","OpenVPN","NOE","CiscoVPN","TeamSpeak","TOR","CiscoSkinny","RTCP","RSYNC","Oracle","Corba","UbuntuONE","Whois-DAS","Collectd","SOCKS5","SOCKS4","RTMP","FTP_DATA","Wikipedia","ZeroMQ","Amazon","eBay","CNN","Megaco","Redis","Pando_Media_Booster","VHUA","Telegram","FacebookChat","Pandora","Vevo"
]

/* APP */

console.log("nDPI Node v"+VERSION);

var counter = 0;
var init = ndpi.init();

/* PCAP LOOP */

console.log("Listening on " + pcap_session.device_name);

function onProto(id, packet) {
	if (id > 0) console.log("Proto: "+id+" "+L7PROTO[id]);
}

function ndpiPipe(h,p){
		ndpi.addProtocolHandler(onProto);
		ndpi.processPacket(h, p);
}

pcap_session.on('packet', function (raw_packet) {
        if (raw_packet.header) {
		counter++;
		ndpiPipe(raw_packet.header.ref(), raw_packet.buf );
        }
});


var exit = false;

process.on('exit', function() {
                exports.callback; onProto;
                console.log('Total Packets: '+counter);
});

process.on('SIGINT', function() {
    console.log();
    if (exit) {
    	console.log("Exiting...");
	ndpi.finish();
        process.exit();
    } else {
    	console.log("Press CTRL-C within 2 seconds to Exit...");
        exit = true;
	setTimeout(function () {
    	  // console.log("Continuing...");
	  exit = false;
	}, 2000)
    }
});
