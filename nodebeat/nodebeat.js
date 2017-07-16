/*  nDPI Node.js Binding PoC 	*/
/*  (c) 2015 QXIP BV 		*/
/*  http://qxip.net 		*/

var VERSION = "0.2";
console.log("nDPI NodeBeat v"+VERSION);
console.log("CTRL-C to exit!");
var counts = { task: 0, batch: 0, drain: 0, pkts: 0 };
var debug = false;

if(process.argv.indexOf("-d") != -1){
    debug = true;
}

if(process.argv.indexOf("-s") != -1){
    var elastic = process.argv[process.argv.indexOf("-s") + 1]; 
}

if (!elastic) { console.log('missing argument! -s <elasticsearch:port>');process.exit(0);}

// Create Client Config
var client = { host: elastic };
if (debug) client.log = 'trace';

/* NODE REQs */ 

	var ref = require('ref');
	var ffi = require('ffi');
	var Struct = require('ref-struct');
//	var ArrayType = require('ref-array');
	var pcap = require("pcap");
	var pcap_session = pcap.createSession("", "");
	
/* Elastic Queue */

	var ElasticQueue, Queue;
	var ElasticQueue = require('elastic-queue');
	
	Queue = new ElasticQueue({
		elasticsearch: { client: client },
		batchSize: 50,
		commitTimeout: 1000,
		rateLimit: 1000
	});
	
	Queue.on('task', function(batch) {
		counts.task++;
		return;
	});
	
	Queue.on('batchComplete', function(resp) {
		counts.batch++;
		return;
	});
	
	Queue.on('drain', function() {
		counts.drain++;
		return;
	  	// console.log("\n\nQueue is Empty\n\n");
	  	// Queue.close();
	  	// return process.exit();
	});
	

/* NDPI CALLBACK */


	/* APP VARS */

	var voidPtr = exports.voidPtr = ref.refType(ref.types.void);
	var u_char = exports.u_char = Struct({
	  __u_char: ref.types.uchar,
	});
	var u_charPtr = exports.u_charPtr = ref.refType(u_char);
	
	var uint8_t = exports.uint8_t = voidPtr;
	var uint8_tPtr = exports.uint8_tPtr = ref.refType(uint8_t);
	
	// var callbackPtr = ffi.Callback(ref.types.void, [ ref.types.int32, ref.refType(ref.types.uchar) ], onProto);
	// var callbackF = ffi.ForeignFunction(callbackPtr, ref.types.void, [ ref.types.int32, ref.refType(ref.types.uchar) ]);

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
	var pcap_pkthdr = exports.pcap_pkthdr = Struct({
	  'ts_sec': 'long', 
	  'ts_usec': 'long',
	  'incl_len': 'int',
	  'orig_len': 'int'
	});
	
	var pktHdr = exports.pktHdr = new pcap_pkthdr;
	pktHdr = ref.refType(ref.types.void);

	/* NDPI Hook */
	var ndpi = exports.ndpi = new ffi.Library('../ndpiexlib.so', {
	  init: [ref.types.void, [
	  ]],
	  getResults: [ref.types.void, [
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


	/* PCAP LOOP */

	var getIndex = exports.getIndex = function(){
		var now = new Date();
		return "ndpibeat-"+new Date(Date.UTC(now.getFullYear(), now.getMonth(), now.getDate())).toISOString().slice(0, 10).replace(/-/g, '.');
	}

	var onProto = exports.onProto = function(id, packet) {
	    if (id > 0) {
		// console.log("Proto: "+id+" "+L7PROTO[id]);
		var doc = {
		  index: getIndex(),
		  type: 'ndpi',
		  body: {
		      ts: (new Date()).toISOString(),
		      proto_name: L7PROTO[id],
		      proto_id: id
		  }
		};
	
		Queue.push(doc, function(err, resp) {
		  if (err) {
		    return console.log(err);
		  }
		  // return console.log(resp);
		});
	    }
	}

	/* APP */

	var init = ndpi.init();

	console.log("Listening on " + pcap_session.device_name);

	var ndpiPipe = exports.ndpiPipe = function(h,p){
		try {
			ndpi.addProtocolHandler(onProto);
			ndpi.processPacket(h, p );
		} catch(e) { console.log(e); }
	}

	pcap_session.on('packet', function (raw_packet) {
	        if (raw_packet.header) {
			counts.pkts++;
			ndpiPipe(raw_packet.header.ref(), raw_packet.buf );
	        } return;
	});

	var exit = false;

	process.on('exit', function() {
                callback; onProto; ndpiPipe;pcap_session;pcap;
                console.log('Total Packets: '+counts.pkts);
	});

/* Exit */

process.on('SIGINT', function() {
    console.log();
    console.log('Stats:',counts);
    console.log('Packets Captured:'+counts.pkts);
    if (exit) {
    	console.log("Exiting...");
	ndpi.finish();
        process.exit();
    } else {
    	console.log("Press CTRL-C within 2 seconds to Exit...");
	ndpi.getResults();
        exit = true;
	setTimeout(function () {
    	  // console.log("Continuing...");
	  exit = false;
	}, 2000)
    }
});
