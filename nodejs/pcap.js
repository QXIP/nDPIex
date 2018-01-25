"use strict"
/*  nDPI Node.js Binding PoC 	*/
/*  (c) 2015 QXIP BV 		*/
/*  http://qxip.net 		*/

var VERSION = "0.1.1";

/* NODE REQs */ 

var ref = require('ref');
var ffi = require('ffi');
var Struct = require('ref-struct');
var ArrayType = require('ref-array');
var fs = require('fs');
var pcap = require("pcap"),
    pcap_session = pcap.createSession("", "");

//var CONF = JSON.parse(fs.readFileSync("./config.json","r+"));
var CONF = {};

var BaseClient = require('./client').BaseClient;

class MyClient extends BaseClient{
    handleStringMessage(msg){
        try{
            var message = JSON.parse(msg);
            //TODO:do some message
        }catch (e){
            console.log(e.toString());
        }
    }
}

//var client = new MyClient(CONF['serverAddr']);
var client = null;
var IPv4 = require('pcap/decode/ipv4');
var TCP = require('pcap/decode/tcp');
var UDP = require('pcap/decode/udp');
var runner = {};

/* NDPI CALLBACK */

// On Windows UTF-16 (2-bytes), Unix UTF-32 (4-bytes)
runner.wchar_size = process.platform == 'win32' ? 2 : 4

runner.wchar_t = Object.create(ref.types.CString);
runner.wchar_t.get = function get (buf, offset) {
  var _buf = buf.readPointer(offset)
  if (_buf.isNull()) {
    return;
  }
  var stringBuf = _buf.reinterpretUntilZeros(runner.wchar_size)
  return stringBuf.toString('win32' ? 'utf16le' : 'utf32li') // TODO: decode UTF-32 on Unix
};

runner.wchar_t.set = function set (buf, offset, val) {
  // TODO: better UTF-16 and UTF-32 encoding
  var _buf = new Buffer((val.length + 1) * runner.wchar_size)
  _buf.fill(0)
  var l = 0
  for (var i = runner.wchar_size - 1; i < _buf.length; i += runner.wchar_size) {
    _buf[i] = val.charCodeAt(l++)
  }
  return buf.writePointer(_buf, offset)
};

runner.callback_Ptr = ArrayType(runner.wchar_t);

/* APP VARS */

runner.voidPtr = exports.voidPtr = ref.refType(ref.types.void);
runner.uint8_t = exports.uint8_t = runner.voidPtr;
runner.uint8_tPtr = exports.uint8_tPtr = ref.refType(runner.uint8_t);
runner.callback = exports.callback = ffi.Function(ref.types.void, [
  ref.types.int32,
  ref.refType(ref.types.uchar)
]);
runner.pcap_t = exports.pcap_t = runner.voidPtr;
runner.pcap_tPtr = exports.pcap_tPtr = ref.refType(runner.pcap_t);
runner.pcap_handler = exports.pcap_handler = ffi.Function(ref.types.void, [
  ref.refType(ref.types.uchar),
  runner.voidPtr,
  ref.refType(ref.types.uchar)
]);
runner.pcap_handlerPtr = exports.pcap_handlerPtr = ref.refType(runner.pcap_handler);

// PCAP Header
var pcap_pkthdr = Struct({
  'ts_sec': 'long',
  'ts_usec': 'long',
  'incl_len': 'int',
  'orig_len': 'int'
});

var pktHdr = new pcap_pkthdr;
pktHdr = ref.refType(ref.types.void);

runner.gcallback = ffi.Callback('void', [ref.types.int32, ref.refType(ref.types.uchar)],
  function(id) {
    console.log("id: ", id);
  });

runner.ndpi = exports.ndpi = new ffi.Library('../ndpiexlib.so', {
  init: [ref.types.void, [
  ]],
  setDatalinkType: [ref.types.void, [
      runner.pcap_tPtr,
  ]],
  processPacket: [ref.types.void, [
    runner.voidPtr,
    runner.uint8_t,
  ]],
  finish: [ref.types.void, [
  ]],
  addProtocolHandler: [ref.types.void, [
    runner.callback
  ]],
});


var L7PROTO = [
"Unknown","FTP_CONTROL","POP3","SMTP","IMAP","DNS","IPP","HTTP","MDNS","NTP","NetBIOS","NFS","SSDP","BGP","SNMP","XDMCP","SMB","Syslog","DHCP","PostgreSQL","MySQL","TDS","Direct_Download_Link","POPS","AppleJuice","DirectConnect","Socrates","WinMX","VMware","SMTPS","Filetopia","iMESH","Kontiki","OpenFT","FastTrack","Gnutella","eDonkey","BitTorrent","EPP","AVI","Flash","OggVorbis","MPEG","QuickTime","RealMedia","WindowsMedia","MMS","Xbox","QQ","Move","RTSP","IMAPS","IceCast","PPLive","PPStream","Zattoo","ShoutCast","Sopcast","Tvants","TVUplayer","HTTP_APPLICATION_VEOHTV","QQLive","Thunder","Soulseek","SSL_No_Cert","IRC","Ayiya","Unencryped_Jabber","MSN","Oscar","Yahoo","BattleField","Quake","VRRP","Steam","HalfLife2","WorldOfWarcraft","Telnet","STUN","IPsec","GRE","ICMP","IGMP","EGP","SCTP","OSPF","IP_in_IP","RTP","RDP","VNC","PcAnywhere","SSL","SSH","Usenet","MGCP","IAX","TFTP","AFP","Stealthnet","Aimini","SIP","TruPhone","ICMPV6","DHCPV6","Armagetron","Crossfire","Dofus","Fiesta","Florensia","Guildwars","HTTP_Application_ActiveSync","Kerberos","LDAP","MapleStory","MsSQL","PPTP","Warcraft3","WorldOfKungFu","Meebo","Facebook","Twitter","DropBox","GMail","GoogleMaps","YouTube","Skype","Google","DCE_RPC","NetFlow","sFlow","HTTP_Connect","HTTP_Proxy","Citrix","NetFlix","LastFM","GrooveShark","SkyFile_PrePaid","SkyFile_Rudics","SkyFile_PostPaid","Citrix_Online","Apple","Webex","WhatsApp","AppleiCloud","Viber","AppleiTunes","Radius","WindowsUpdate","TeamViewer","Tuenti","LotusNotes","SAP","GTP","UPnP","LLMNR","RemoteScan","Spotify","WebM","H323","OpenVPN","NOE","CiscoVPN","TeamSpeak","TOR","CiscoSkinny","RTCP","RSYNC","Oracle","Corba","UbuntuONE","Whois-DAS","Collectd","SOCKS5","SOCKS4","RTMP","FTP_DATA","Wikipedia","ZeroMQ","Amazon","eBay","CNN","Megaco","Redis","Pando_Media_Booster","VHUA","Telegram","FacebookChat","Pandora","Vevo"
]

/* APP */

console.log("nDPI Node v"+VERSION);

var counter = 0;
var init = runner.ndpi.init();

var reboot = function(){
	runner.ndpi.finish();
	runner.ndpi.init();
	//console.log('nDPI restarted!');
}

/* PCAP LOOP */

console.log("Listening on " + pcap_session.device_name);

runner.onProto = function(id, packet) {
	if (id > 0) console.log("Proto: "+id+" "+L7PROTO[id]);
}


runner.getFlowInfo = function(packet,l7_protocol){
	if(packet.payload.payload instanceof IPv4){
		var ip = packet.payload.payload;
		var saddr = ip.saddr;
		var daddr = ip.daddr;
		var sport = null;
	    	var dport = null;
		var tsl_packet = packet.payload.payload.payload;
		var tsl_protocol = '';
		if(tsl_packet instanceof TCP){
			tsl_protocol = 'tcp';
			sport = tsl_packet.sport;
			dport = tsl_packet.dport;
		}else if (tsl_packet instanceof UDP){
			tsl_protocol = 'udp';
			sport = tsl_packet.sport;
			dport = tsl_packet.dport;
		}else{
			tsl_protocol = 'unknown';
			sport = tsl_packet.sport;
			dport = tsl_packet.dport;
			console.log('skip!');
		}
		return {l7_protocol,tsl_protocol,saddr,daddr,sport,dport};
	}
}


runner.onPacketAnalyzedCallback = function(flow_info){
  console.log("flow from "+flow_info.saddr+":"+flow_info.sport+" to "+flow_info.daddr+":"+flow_info.dport+" with protocol : "+flow_info.l7_protocol);
}

runner.ndpi.addProtocolHandler(runner.onProto);
runner.ndpiPipe = function(header,packet,callback){
    try {
	runner.ndpi.addProtocolHandler(function(id,p){
	    if(id > 0){
		callback(runner.getFlowInfo(pcap.decode.packet(packet),L7PROTO[id]));
	    }
	});
	runner.ndpi.processPacket(header, packet.buf);
    } catch(e) { console.log(e); }
}

pcap_session.on('packet', function (raw_packet) {
    if (raw_packet.header) {
        counter++;
        runner.ndpiPipe(raw_packet.header.ref(), raw_packet, runner.onPacketAnalyzedCallback );
	if (counter % 200 === 0) { reboot(); }
    }
});



var exit = false;

process.on('exit', function() {
    console.log('Total Packets: '+counter);
    runner;
});

process.on('SIGINT', function() {
    console.log();
    if (exit) {
    	console.log("Exiting...");
	runner.ndpi.finish();
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


