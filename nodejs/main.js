/*  nDPI Node.js Binding PoC 		*/
/*  (c) 2015 L. Mangani, QXIP BV 	*/
/*  http://qxip.net 			*/

var VERSION = "0.1.4";

/* NODE REQs */ 

var ffi = require('ffi-napi');
//var ffi = require('ffi');
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
	const onProto = function(id, packet) {
		if (id > 0) { console.log("Proto: "+packet+" ("+id+")") }
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

/* APP */

console.log("nDPI Node v"+VERSION);
counter = 0;

/* NDPI LOOP */

// ndpi.addProtocolHandler(onProto);
ndpi.init();
console.log("INIT");

	pcap_parser.on('globalHeader', function (globalHeader) {
		var ltype = new Buffer(globalHeader.linkLayerType);
		//	ltype.type = ref.refType(pcap_t);
		ndpi.setDatalinkType(ltype.ref())
	});

console.log("SET DATALINK");

	function ndpiPipe(h,p){
	   if(p===undefined) return;
	   try {
	       ndpi.addProtocolHandler(onProto);
	       ndpi.processPacket(h, p);
	   } catch(e) { console.log(e); console.log(h,p); }

	}


pcap_parser.on('packet', function (raw_packet) {
	counter++;
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


