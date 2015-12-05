/*
 * ndpiex.c
 * Copyright (C) 2015 by QXIP BV
 * Copyright (C) 2012 by Gianluca Costa
 * Copyright (C) 2009-2010 by ipoque GmbH
 * 
 * This is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * ndpiex is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 * 
 */



#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <netinet/in.h>

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

/*
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
*/
#include <linux/if_ether.h>

#include <pcap.h>

#include "ndpi_api.h"

#define	MAX_OSDPI_IDS                   100000
#define	MAX_OSDPI_FLOWS                 100000

#ifndef NDPI_PROTOCOL_LONG_STRING
#define NDPI_PROTOCOL_LONG_STRING "Unknown","FTP","POP","SMTP","IMAP","DNS","IPP","HTTP","MDNS","NTP","NETBIOS",\
	"NFS","SSDP","BGP","SNMP","XDMCP","SMB","SYSLOG","DHCP","PostgreSQL","MySQL",\
"TDS","DirectDownloadLink","I23V5","AppleJuice","DirectConnect","Socrates","WinMX","MANOLITO","PANDO","Filetopia",\
"iMESH","Kontiki","OpenFT","Kazaa","Gnutella","eDonkey","Bittorrent","OFF","AVI","Flash",\
"OGG","MPEG","QuickTime","RealMedia","Windowsmedia","MMS","XBOX","QQ","MOVE","RTSP",\
"Feidian","Icecast","PPLive","PPStream","Zattoo","SHOUTCast","SopCast","TVAnts","TVUplayer","VeohTV",\
"QQLive","Thunder","Soulseek","GaduGadu","IRC","Popo","Jabber","MSN","Oscar","Yahoo",\
"Battlefield","Quake","Second_Life","Steam","Halflife2","World_of_Warcraft","Telnet","STUN","IPSEC","GRE",\
"ICMP","IGMP","EGP","SCTP","OSPF","IP_in_IP","RTP","RDP","VNC","PCAnywhere",\
"SSL","SSH","USENET","MGCP","IAX","TFTP","AFP","StealthNet","Aimini","SIP",\
"Truphone","ICMPv6","DHCPv6","Armagetron","CrossFire","Dofus","Fiesta","Florensia","Guildwars","HTTP_Application_Activesync",\
"Kerberos","LDAP","MapleStory","msSQL","PPTP","WARCRAFT3","World_of_Kung_Fu","MEEBO","FaceBook","Twitter",\
"DropBox","Gmail","Google_Maps","YouTube","Skype","Google","DCE_RPC","NetFlow_IPFIX","sFlow","HTTP_Connect_SSL_over_HTTP",\
"HTTP_Proxy","Citrix","Netflix","LastFM","Grooveshark","SkyFile_Prepaid","SkyFile_Rudics","SkyFile_Postpaid","CitrixOnline","Apple_iMessage_FaceTime",\
"Webex","WhatsApp","Apple_iCloud","Viber","Apple_iTunes","Radius","Windows_Update","TeamViewer","Tuenti","Lotus_Notes",\
"SAP","GTP","uPnP","LLMNR","Remote_Scan"
#endif

#ifndef NDPI_PROTOCOL_SHORT_STRING
#define NDPI_PROTOCOL_SHORT_STRING "ukn","ftp","pop","smtp","imap","dns","ipp","http","mdns","ntp","netbios",\
	"nfs","ssdp","bgp","snmp","xdmcp","smb","syslog","dhcp","postgres","mysql",\
"tds","ddl","i23v5","applejuice","directconnect","socrates","winmx","manolito","pando","filetopia",\
"iMESH","kontiki","openft","fasttrack","gnutella","edonkey","bittorrent","off","avi","flash",\
"ogg","mpeg","quicktime","realmedia","windowsmedia","mms","xbox","qq","move","rtsp",\
"feidian","icecast","pplive","ppstream","zattoo","shoutcast","sopcast","tvants","tvuplayer","veohtv",\
"qqlive","thunder","soulseek","gadugadu","irc","popo","jabber","msn","oscar","yahoo",\
"battlefield","quake","secondlife","steam","hl2","worldofwarcraft","telnet","stun","ipsec","gre",\
"icmp","igmp","egp","sctp","ospf","ipip","rtp","rdp","vnc","pcanywhere",\
"ssl","ssh","usenet","mgcp","iax","tftp","afp","stealthnet","aimini","sip",\
"truphone","icmpv6","dhcpv6","armagetron","crossfire","dofus","fiesta","florensia","guildwars","httpactivesync",\
"kerberos","ldap","maplestory","mssql","pptp","warcraft3","wokf","meebo","facebook","twitter",\
"dropbox","gmail","gmaps","youtube","skype","google","dcerpc","netflow","sflow","httpconnect",\
"httpproxy","citrix","netflix","lastfm","grooveshark","skyfileprepaid","skyfilerudics","skyfilepostpaid","citrixonline","apple",\
"webex","wgatsapp","appleicloud","viber","appleitunes","radius","windowsupdate","teamviewer","tuenti","lotusnotes",\
"sap","gtp","upnp","llmnr","remotescan"
#endif

// cli options
static char *_pcap_file = NULL;

// pcap
static char _pcap_error_buffer[PCAP_ERRBUF_SIZE];
static pcap_t *_pcap_handle = NULL;
static int _pcap_datalink_type = 0;

// detection
static struct ndpi_detection_module_struct *ndpi_struct = NULL;
static u_int32_t detection_tick_resolution = 1000;
static char *prot_long_str[] = { NDPI_PROTOCOL_LONG_STRING };

#ifdef NDPI_ENABLE_DEBUG_MESSAGES
static char *prot_short_str[] = { NDPI_PROTOCOL_SHORT_STRING };

static NDPI_PROTOCOL_BITMASK debug_messages_bitmask;
#endif

// results
static u_int64_t raw_packet_count = 0;
static u_int64_t ip_packet_count = 0;
static u_int64_t total_bytes = 0;
static u_int64_t protocol_counter[NDPI_MAX_SUPPORTED_PROTOCOLS + 1];
static u_int64_t protocol_counter_bytes[NDPI_MAX_SUPPORTED_PROTOCOLS + 1];


// id tracking
typedef struct osdpi_id {
    u_int8_t ip[4];
    struct ndpi_id_struct *ndpi_id;
} osdpi_id_t;

static u_int32_t size_id_struct = 0;
static struct osdpi_id *osdpi_ids;
static u_int32_t osdpi_id_count = 0;


// flow tracking
typedef struct osdpi_flow {
    u_int32_t lower_ip;
    u_int32_t upper_ip;
    u_int16_t lower_port;
    u_int16_t upper_port;
    u_int8_t protocol;
    struct ndpi_flow_struct *ndpi_flow;
    char lower_name[48], upper_name[48];
    u_int8_t ip_version;
    u_int64_t last_seen;
    u_int64_t bytes;
    u_int32_t packets;
    
    // result only, not used for flow identification
  //  u_int32_t detected_protocol;
    ndpi_protocol detected_protocol;

} osdpi_flow_t;

// flow tracking
typedef struct ndpi_flow {
  u_int32_t lower_ip;
  u_int32_t upper_ip;
  u_int16_t lower_port;
  u_int16_t upper_port;
  u_int8_t detection_completed, protocol;
  u_int16_t vlan_id;
  struct ndpi_flow_struct *ndpi_flow;
  char lower_name[48], upper_name[48];
  u_int8_t ip_version;
  u_int64_t last_seen;
  u_int64_t bytes;
  u_int32_t packets;

  // result only, not used for flow identification
  ndpi_protocol detected_protocol;

  char host_server_name[256];

  struct {
    char client_certificate[48], server_certificate[48];
  } ssl;

  void *src_id, *dst_id;
} ndpi_flow_t;



static u_int32_t size_flow_struct = 0;
static struct osdpi_flow *osdpi_flows;
static u_int32_t osdpi_flow_count = 0;

#ifdef NDPI_ENABLE_DEBUG_MESSAGES
static int string_to_detection_bitmask(char *str, NDPI_PROTOCOL_BITMASK * dbm)
{
    u_int32_t a;
    u_int32_t oldptr = 0;
    u_int32_t ptr = 0;
    NDPI_BITMASK_RESET(*dbm);
    
    printf("Protocol parameter given: %s\n", str);
    
    if (strcmp(str, "all") == 0) {
        printf("Protocol parameter all parsed\n");
        NDPI_BITMASK_SET_ALL(*dbm);
        printf("Bitmask is: " NDPI_BITMASK_DEBUG_OUTPUT_BITMASK_STRING " \n",
               NDPI_BITMASK_DEBUG_OUTPUT_BITMASK_VALUE(*dbm));
        return 0;
    }
    // parse bitmask
    while (1) {
        if (str[ptr] == 0 || str[ptr] == ' ') {
            printf("Protocol parameter: parsed: %.*s,\n", ptr - oldptr, &str[oldptr]);
            for (a = 1; a <= NDPI_MAX_SUPPORTED_PROTOCOLS; a++) {
                
                if (strlen(prot_short_str[a]) == (ptr - oldptr) &&
                    (memcmp(&str[oldptr], prot_short_str[a], ptr - oldptr) == 0)) {
                    NDPI_ADD_PROTOCOL_TO_BITMASK(*dbm, a);
                    printf("Protocol parameter detected as protocol %s\n", prot_long_str[a]);
                }
            }
            oldptr = ptr + 1;
            if (str[ptr] == 0)
                break;
        }
        ptr++;
    }
    return 0;
}
#endif

static void parseOptions(int argc, char **argv)
{
    int opt;
    
#ifdef NDPI_ENABLE_DEBUG_MESSAGES
    NDPI_BITMASK_SET_ALL(debug_messages_bitmask);
#endif
    
    while ((opt = getopt(argc, argv, "f:e:")) != EOF) {
        switch (opt) {
        case 'f':
            _pcap_file = optarg;
            break;
        case 'e':
#ifdef NDPI_ENABLE_DEBUG_MESSAGES
            // set debug logging bitmask to all protocols
            if (string_to_detection_bitmask(optarg, &debug_messages_bitmask) != 0) {
                printf("ERROR option -e needs a valid list of protocols");
                exit(-1);
            }
            
            printf("debug messages Bitmask is: " NDPI_BITMASK_DEBUG_OUTPUT_BITMASK_STRING "\n",
                   NDPI_BITMASK_DEBUG_OUTPUT_BITMASK_VALUE(debug_messages_bitmask));
            
#else
            printf("ERROR: option -e : DEBUG MESSAGES DEACTIVATED\n");
            exit(-1);
#endif
            break;
        }
    }
    
    // check parameters
    if (_pcap_file == NULL || strcmp(_pcap_file, "") == 0) {
        printf("ERROR: no pcap file path provided; use option -f with the path to a valid pcap file\n");
        exit(-1);
    }
}

static void debug_printf(u_int32_t protocol, void *id_struct, ndpi_log_level_t log_level, const char *format, ...)
{
#ifdef NDPI_ENABLE_DEBUG_MESSAGES
    if (NDPI_COMPARE_PROTOCOL_TO_BITMASK(debug_messages_bitmask, protocol) != 0) {
        const char *protocol_string;
        const char *file;
        const char *func;
        u_int32_t line;
        va_list ap;
        va_start(ap, format);
        
        protocol_string = prot_short_str[protocol.protocol];
        
        ndpi_debug_get_last_log_function_line(ndpi_struct, &file, &func, &line);
        
        printf("\nDEBUG: %s:%s:%u Prot: %s, level: %u packet: %"PRIu64" :", file, func, line, protocol_string,
               log_level, raw_packet_count);
        vprintf(format, ap);
        va_end(ap);
    }
#endif
}

static void *malloc_wrapper(unsigned long size)
{
    return malloc(size);
}

static void free_wrapper(void *freeable)
{
    free(freeable);
}

static void *get_id(const u_int8_t * ip)
{
    u_int32_t i;
    for (i = 0; i < osdpi_id_count; i++) {
        if (memcmp(osdpi_ids[i].ip, ip, sizeof(u_int8_t) * 4) == 0) {
            return osdpi_ids[i].ndpi_id;
        }
    }
    if (osdpi_id_count == MAX_OSDPI_IDS) {
        printf("ERROR: maximum unique id count (%u) has been exceeded\n", MAX_OSDPI_IDS);
        exit(-1);
    }
    else {
        struct ndpi_id_struct *ndpi_id;
        memcpy(osdpi_ids[osdpi_id_count].ip, ip, sizeof(u_int8_t) * 4);
        ndpi_id = osdpi_ids[osdpi_id_count].ndpi_id;
        
        osdpi_id_count += 1;
        return ndpi_id;
    }
}

static struct osdpi_flow *get_osdpi_flow(const struct iphdr *iph, u_int16_t ipsize)
{
    u_int32_t i;
    u_int16_t l4_packet_len;
    struct tcphdr *tcph = NULL;
    struct udphdr *udph = NULL;

    u_int32_t lower_ip;
    u_int32_t upper_ip;
    u_int16_t lower_port;
    u_int16_t upper_port;

    if (ipsize < 20)
        return NULL;

    if ((iph->ihl * 4) > ipsize || ipsize < ntohs(iph->tot_len)
        || (iph->frag_off & htons(0x1FFF)) != 0)
        return NULL;

    l4_packet_len = ntohs(iph->tot_len) - (iph->ihl * 4);

    if (iph->saddr < iph->daddr) {
        lower_ip = iph->saddr;
        upper_ip = iph->daddr;
    }
    else {
        lower_ip = iph->daddr;
        upper_ip = iph->saddr;
    }

    if (iph->protocol == 6 && l4_packet_len >= 20) {
        // tcp
        tcph = (struct tcphdr *) ((u_int8_t *) iph + iph->ihl * 4);
        if (iph->saddr < iph->daddr) {
            lower_port = tcph->source;
            upper_port = tcph->dest;
        }
        else {
            lower_port = tcph->dest;
            upper_port = tcph->source;
        }
    }
    else if (iph->protocol == 17 && l4_packet_len >= 8) {
        // udp
        udph = (struct udphdr *) ((u_int8_t *) iph + iph->ihl * 4);
        if (iph->saddr < iph->daddr) {
            lower_port = udph->source;
            upper_port = udph->dest;
        }
        else {
            lower_port = udph->dest;
            upper_port = udph->source;
        }
    }
    else {
        // non tcp/udp protocols
        lower_port = 0;
        upper_port = 0;
    }

    for (i = 0; i < osdpi_flow_count; i++) {
        if (osdpi_flows[i].protocol == iph->protocol &&
            osdpi_flows[i].lower_ip == lower_ip &&
            osdpi_flows[i].upper_ip == upper_ip &&
            osdpi_flows[i].lower_port == lower_port && osdpi_flows[i].upper_port == upper_port) {
            return &osdpi_flows[i];
        }
    }
    if (osdpi_flow_count == MAX_OSDPI_FLOWS) {
        printf("ERROR: maximum flow count (%u) has been exceeded\n", MAX_OSDPI_FLOWS);
        exit(-1);
    }
    else {
        struct osdpi_flow *flow;
        osdpi_flows[osdpi_flow_count].protocol = iph->protocol;
        osdpi_flows[osdpi_flow_count].lower_ip = lower_ip;
        osdpi_flows[osdpi_flow_count].upper_ip = upper_ip;
        osdpi_flows[osdpi_flow_count].lower_port = lower_port;
        osdpi_flows[osdpi_flow_count].upper_port = upper_port;
        flow = &osdpi_flows[osdpi_flow_count];

        osdpi_flow_count += 1;
        return flow;
    }
}

static void setupDetection(void)
{
    u_int32_t i;
    NDPI_PROTOCOL_BITMASK all;

    // init global detection structure
    ndpi_struct = ndpi_init_detection_module(detection_tick_resolution, malloc_wrapper, free_wrapper, debug_printf);
    if (ndpi_struct == NULL) {
        printf("ERROR: global structure initialization failed\n");
        exit(-1);
    }
    // enable all protocols
    NDPI_BITMASK_SET_ALL(all);
    ndpi_set_protocol_detection_bitmask2(ndpi_struct, &all);

    // allocate memory for id and flow tracking
    size_id_struct = ndpi_detection_get_sizeof_ndpi_id_struct();
    size_flow_struct = ndpi_detection_get_sizeof_ndpi_flow_struct();

    osdpi_ids = malloc(MAX_OSDPI_IDS * sizeof(struct osdpi_id));
    if (osdpi_ids == NULL) {
        printf("ERROR: malloc for osdpi_ids failed\n");
        exit(-1);
    }
    for (i = 0; i < MAX_OSDPI_IDS; i++) {
        memset(&osdpi_ids[i], 0, sizeof(struct osdpi_id));
        osdpi_ids[i].ndpi_id = calloc(1, size_id_struct);
        if (osdpi_ids[i].ndpi_id == NULL) {
            printf("ERROR: malloc for ndpi_id_struct failed\n");
            exit(-1);
        }
    }

    osdpi_flows = malloc(MAX_OSDPI_FLOWS * sizeof(struct osdpi_flow));
    if (osdpi_flows == NULL) {
        printf("ERROR: malloc for osdpi_flows failed\n");
        exit(-1);
    }
    for (i = 0; i < MAX_OSDPI_FLOWS; i++) {
        memset(&osdpi_flows[i], 0, sizeof(struct osdpi_flow));
        osdpi_flows[i].ndpi_flow = calloc(1, size_flow_struct);
        if (osdpi_flows[i].ndpi_flow == NULL) {
            printf("ERROR: malloc for ndpi_flow_struct failed\n");
            exit(-1);
        }
    }

    // clear memory for results
    memset(protocol_counter, 0, (NDPI_MAX_SUPPORTED_PROTOCOLS + 1) * sizeof(u_int64_t));
    memset(protocol_counter_bytes, 0, (NDPI_MAX_SUPPORTED_PROTOCOLS + 1) * sizeof(u_int64_t));
}

static void terminateDetection(void)
{
    u_int32_t i;

    ndpi_exit_detection_module(ndpi_struct, free_wrapper);

    for (i = 0; i < MAX_OSDPI_IDS; i++) {
        free(osdpi_ids[i].ndpi_id);
    }
    free(osdpi_ids);
    for (i = 0; i < MAX_OSDPI_FLOWS; i++) {
        free(osdpi_flows[i].ndpi_flow);
    }
    free(osdpi_flows);
}

static unsigned int packet_processing(const uint64_t time, const struct iphdr *iph, uint16_t ipsize, uint16_t rawsize)
{
    struct ndpi_id_struct *src = NULL;
    struct ndpi_id_struct *dst = NULL;
    struct osdpi_flow *flow = NULL;
    struct ndpi_flow_struct *ipq_flow = NULL;
  //  u_int32_t protocol = 0;
    ndpi_protocol protocol;


    src = get_id((u_int8_t *) & iph->saddr);
    dst = get_id((u_int8_t *) & iph->daddr);

    flow = get_osdpi_flow(iph, ipsize);
    if (flow != NULL) {
        ipq_flow = flow->ndpi_flow;
    }

    ip_packet_count++;
    total_bytes += rawsize;

#ifndef NDPI_ENABLE_DEBUG_MESSAGES
    if (ip_packet_count % 499 == 0) {
        printf("\rip packets scanned: \x1b[33m%-10"PRIu64"\x1b[0m ip bytes scanned: \x1b[34m%-10"PRIu64"\x1b[0m",
               ip_packet_count, total_bytes);
    }
#endif
    
    // only handle unfragmented packets
    if ((iph->frag_off & htons(0x1FFF)) == 0) {
        
        // here the actual detection is performed
        protocol = ndpi_detection_process_packet(ndpi_struct, ipq_flow, (uint8_t *) iph, ipsize, time, src, dst);
    }
    else {
        static u_int8_t frag_warning_used = 0;
        if (frag_warning_used == 0) {
            printf("\n\nWARNING: fragmented ip packets are not supported and will be skipped \n\n");
            sleep(2);
            frag_warning_used = 1;
        }
        return 0;
    }
    
    protocol_counter[protocol.protocol]++;
    protocol_counter_bytes[protocol.protocol] += rawsize;
    
    if (flow != NULL) {
        flow->detected_protocol = protocol;
	///	printf("\nproto: %u %s",protocol.protocol, ndpi_get_proto_name(ndpi_struct, flow->detected_protocol.protocol) );
    }
    
    return 0;
}

static void printResults(void)
{
    u_int32_t i;

    printf("\x1b[2K\n");
    printf("pcap file contains\n");
    printf("\tip packets:   \x1b[33m%-13"PRIu64"\x1b[0m of %"PRIu64" packets total\n", ip_packet_count, raw_packet_count);
    printf("\tip bytes:     \x1b[34m%-13"PRIu64"\x1b[0m\n", total_bytes);
    printf("\tunique ids:   \x1b[35m%-13u\x1b[0m\n", osdpi_id_count);
    printf("\tunique flows: \x1b[36m%-13u\x1b[0m\n", osdpi_flow_count);

    printf("\n\ndetected protocols:\n");
    for (i = 0; i <= NDPI_MAX_SUPPORTED_PROTOCOLS; i++) {
        u_int32_t protocol_flows = 0;
        u_int32_t j;

        // count flows for that protocol
        for (j = 0; j < osdpi_flow_count; j++) {
            if (osdpi_flows[j].detected_protocol.protocol == i) {
                protocol_flows++;
            }
        }

        if (protocol_counter[i] > 0) {
            printf("\t\x1b[31m%-20s\x1b[0m packets: \x1b[33m%-13"PRIu64"\x1b[0m bytes: \x1b[34m%-13"PRIu64"\x1b[0m "
                   "flows: \x1b[36m%-13u\x1b[0m\n",
                   prot_long_str[i], protocol_counter[i], protocol_counter_bytes[i], protocol_flows);
        }
    }
    printf("\n\n");
}

static void openPcapFile(void)
{
    _pcap_handle = pcap_open_offline(_pcap_file, _pcap_error_buffer);

    if (_pcap_handle == NULL) {
        printf("ERROR: could not open pcap file: %s\n", _pcap_error_buffer);
        exit(-1);
    }
    _pcap_datalink_type = pcap_datalink(_pcap_handle);
}

static void closePcapFile(void)
{
    if (_pcap_handle != NULL) {
        pcap_close(_pcap_handle);
    }
}

// executed for each packet in the pcap file
static void pcap_packet_callback(u_char * args, const struct pcap_pkthdr *header, const u_char * packet)
{
    const struct ethhdr *ethernet = (struct ethhdr *) packet;
    struct iphdr *iph = (struct iphdr *) &packet[sizeof(struct ethhdr)];
    u_int64_t time;
    static u_int64_t lasttime = 0;
    u_int16_t type;

    raw_packet_count++;

    time =
        ((uint64_t) header->ts.tv_sec) * detection_tick_resolution +
        header->ts.tv_usec / (1000000 / detection_tick_resolution);
    if (lasttime > time) {
        // printf("\nWARNING: timestamp bug in the pcap file (ts delta: %"PRIu64", repairing)\n", lasttime - time);
        time = lasttime;
    }
    lasttime = time;


    type = ethernet->h_proto;

    // just work on Ethernet packets that contain IP
    if (_pcap_datalink_type == DLT_EN10MB && type == htons(ETH_P_IP)
        && header->caplen >= sizeof(struct ethhdr)) {

        if (header->caplen < header->len) {
            static u_int8_t cap_warning_used = 0;
            if (cap_warning_used == 0) {
                printf
                    ("\n\nWARNING: packet capture size is smaller than packet size, DETECTION MIGHT NOT WORK CORRECTLY OR EVEN CRASH\n\n");
                sleep(2);
                cap_warning_used = 1;
            }
        }

        if (iph->version != 4) {
            static u_int8_t ipv4_warning_used = 0;
            if (ipv4_warning_used == 0) {
                printf("\n\nWARNING: only IPv4 packets are supported, all other packets will be discarded\n\n");
                sleep(2);
                ipv4_warning_used = 1;
            }
            return;
        }
        // process the packet
        packet_processing(time, iph, header->len - sizeof(struct ethhdr), header->len);
    }

}

static void runPcapLoop(void)
{
    if (_pcap_handle != NULL) {
        pcap_loop(_pcap_handle, -1, &pcap_packet_callback, NULL);
    }
}

int main(int argc, char **argv)
{
    parseOptions(argc, argv);

    setupDetection();

    openPcapFile();
    runPcapLoop();
    closePcapFile();

    printResults();

    terminateDetection();

    return 0;
}

/*************************************************/

struct timeval begin, end;
u_int64_t tot_usec;

void init() {
    setupDetection();
    gettimeofday(&begin, NULL);
}

void setDatalinkType(pcap_t *handle) {
    _pcap_datalink_type = pcap_datalink(handle);

}

void processPacket(const struct pcap_pkthdr *header, const u_char *packet) {
    pcap_packet_callback(NULL, header, packet);
}

void finish() {
    gettimeofday(&end, NULL);
    tot_usec = end.tv_sec*1000000 + end.tv_usec - (begin.tv_sec*1000000 + begin.tv_usec);
    terminateDetection();
}
