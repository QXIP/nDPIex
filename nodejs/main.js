/*  nDPI Node.js Binding PoC 		*/
/*  (c) 2015 L. Mangani, QXIP BV 	*/
/*  http://qxip.net 			*/

var VERSION = "0.1.4";

/* NODE REQs */ 

var ffi = require('ffi');
var ref = require("ref");
var Struct = require('ref-struct');
var ArrayType = require('ref-array');

/* PCAP Parser */

var pcapp = require('pcap-parser');
if (process.argv[2]) {
	var pcap_parser = pcapp.parse(process.argv[2]);
} else {
    console.error("usage: node pcap.js /path/to/file.pcap");
    console.error();
    process.exit();
}

/* NDPI Types */

	var voidPtr = exports.voidPtr = ref.refType(ref.types.void);
	var u_char = exports.u_char = Struct({
	  __u_char: ref.types.uchar,
	});
	var u_charPtr = exports.u_charPtr = ref.refType(u_char);
	
	var pcap_t = exports.pcap_t = voidPtr;
	var pcap_tPtr = exports.pcap_tPtr = ref.refType(pcap_t);
	var pcap_handler = exports.pcap_handler = ffi.Function(ref.types.void, [
	  ref.refType(ref.types.uchar),
	  voidPtr,
	  ref.refType(ref.types.uchar),
	]);
	var pcap_handlerPtr = exports.pcap_handlerPtr = ref.refType(pcap_handler);
	
	var uint8_t = exports.uint8_t = voidPtr;
	var uint8_tPtr = exports.uint8_tPtr = ref.refType(uint8_t);


/* callback */ 
	var onProto = function(id, packet) {
		if (id > 0) { console.log("Proto: "+L7PROTO[id]+" ("+id+")") }
	}

	var callback = exports.callback = ffi.Function(ref.types.void, [
	  ref.types.int32,
	  ref.refType(uint8_t),
	]);

	var ndpi = ffi.Library('../ndpiexlib.so', {
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

	/* PCAP Header  */

	var pcap_pkthdr = Struct({
	  'ts_sec': 'uint64', 
	  'ts_usec': 'uint64',
	  'incl_len': 'uint32',
	  'orig_len': 'uint32'
	});

	var pcap_pkthdr_ptr = ref.refType(pcap_pkthdr);

/* APP VARS */

	var L7PROTO = [
	"Unknown","FTP_CONTROL","POP3","SMTP","IMAP","DNS","IPP","HTTP","MDNS","NTP","NetBIOS","NFS","SSDP","BGP","SNMP","XDMCP","SMB","Syslog","DHCP","PostgreSQL","MySQL","TDS","Direct_Download_Link","POPS","AppleJuice","DirectConnect","Socrates","WinMX","VMware","SMTPS","Filetopia","iMESH","Kontiki","OpenFT","FastTrack","Gnutella","eDonkey","BitTorrent","EPP","AVI","Flash","OggVorbis","MPEG","QuickTime","RealMedia","WindowsMedia","MMS","Xbox","QQ","Move","RTSP","IMAPS","IceCast","PPLive","PPStream","Zattoo","ShoutCast","Sopcast","Tvants","TVUplayer","HTTP_APPLICATION_VEOHTV","QQLive","Thunder","Soulseek","SSL_No_Cert","IRC","Ayiya","Unencryped_Jabber","MSN","Oscar","Yahoo","BattleField","Quake","VRRP","Steam","HalfLife2","WorldOfWarcraft","Telnet","STUN","IPsec","GRE","ICMP","IGMP","EGP","SCTP","OSPF","IP_in_IP","RTP","RDP","VNC","PcAnywhere","SSL","SSH","Usenet","MGCP","IAX","TFTP","AFP","Stealthnet","Aimini","SIP","TruPhone","ICMPV6","DHCPV6","Armagetron","Crossfire","Dofus","Fiesta","Florensia","Guildwars","HTTP_Application_ActiveSync","Kerberos","LDAP","MapleStory","MsSQL","PPTP","Warcraft3","WorldOfKungFu","Meebo","Facebook","Twitter","DropBox","GMail","GoogleMaps","YouTube","Skype","Google","DCE_RPC","NetFlow","sFlow","HTTP_Connect","HTTP_Proxy","Citrix","NetFlix","LastFM","GrooveShark","SkyFile_PrePaid","SkyFile_Rudics","SkyFile_PostPaid","Citrix_Online","Apple","Webex","WhatsApp","AppleiCloud","Viber","AppleiTunes","Radius","WindowsUpdate","TeamViewer","Tuenti","LotusNotes","SAP","GTP","UPnP","LLMNR","RemoteScan","Spotify","WebM","H323","OpenVPN","NOE","CiscoVPN","TeamSpeak","TOR","CiscoSkinny","RTCP","RSYNC","Oracle","Corba","UbuntuONE","Whois-DAS","Collectd","SOCKS5","SOCKS4","RTMP","FTP_DATA","Wikipedia","ZeroMQ","Amazon","eBay","CNN","Megaco","Redis","Pando_Media_Booster","VHUA","Telegram","FacebookChat","Pandora","Vevo"
	]

/* APP */

console.log("nDPI Node v"+VERSION);
counter = 0;

/* NDPI LOOP */

	// ndpi.addProtocolHandler(onProto);
	ndpi.init();

	pcap_parser.on('globalHeader', function (globalHeader) {
		var ltype = new Buffer(globalHeader.linkLayerType);
		//	ltype.type = ref.refType(pcap_t);
		ndpi.setDatalinkType(ltype.ref())
	});


	function ndpiPipe(h,p){
	   try {
		ndpi.addProtocolHandler(onProto);
	    	ndpi.processPacket(h, p );
	   } catch(e) { console.log(e); }

	}

pcap_parser.on('packet', function (raw_packet) {
	counter++;
	var onProto = function(id, packet) {
		if (id > 0) { console.log("Proto: "+L7PROTO[id]+" ("+id+")") }
	}
	var header = raw_packet.header;
	// Build PCAP Hdr Struct
	var newHdr = new pcap_pkthdr();
		newHdr.ts_sec=header.timestampSeconds;
		newHdr.ts_usec=header.timestampMicroseconds;
		newHdr.incl_len=header.capturedLength;
		newHdr.orig_len=header.originalLength;

    	ndpiPipe(newHdr.ref(), raw_packet.data );

});

pcap_parser.on('end', function () {
	ndpi.finish();
});

var exit = false;

process.on('exit', function() {
		exports.callback;
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
	  exit = false;
	}, 2000)
    }
});


