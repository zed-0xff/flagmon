#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcre.h>

#include "flagmon.h"
#include "hexdump.c"

#define FLAG_REGEXP     "\\W\\w{31}="
#define FLAG_LENGTH     32

#define PCAP_PERIOD 100 // pcap kernel poll period, ms

#define MAX_FILTER_LEN 4096
#define DEFAULT_FILTER "port not 22 and port not 443"

#define MAX_LOCAL_IPS 128

enum {
    VERBOSITY_SILENT = -2,
    VERBOSITY_QUIET,
    VERBOSITY_DEFAULT,
    VERBOSITY_EVERY_PACKET_INFO,
    VERBOSITY_ALL_PAYLOAD_DATA,
    VERBOSITY_ALL_IP_DATA,
    VERBOSITY_ALL_ETHERNET_DATA
};

static int verbosity = 0, promisc = 0, write_all_packets = 0;

static pcap_t *pcap_handle;
static pcap_dumper_t *pcap_dumper = NULL;

static uint32_t local_ips[MAX_LOCAL_IPS] = {0};

pcre *reCompiled;
pcre_extra *pcreExtra;

static unsigned int total_packets = 0, total_matches = 0, total_sessions = 0;

#include "tcp.c"

int process_payload(const u_char* data, int size){
    static char buf[65536];

    if( size < FLAG_LENGTH ) return 0;

    if( size > sizeof(buf)-1) size = sizeof(buf)-1;
    memcpy(buf+1, data, size);
    *buf = ' ';

    int pcreExecRet = pcre_exec(reCompiled,
                            pcreExtra,
                            buf,
                            size,
                            0,                      // Start looking at this point
                            0,                      // OPTIONS
                            NULL,
                            0);                    // Length of subStrVec


    if(pcreExecRet < 0) { // Something bad happened..
      switch(pcreExecRet) {
      case PCRE_ERROR_NOMATCH      : return 0; // no matches
      case PCRE_ERROR_NULL         : printf("Something was null\n");                      break;
      case PCRE_ERROR_BADOPTION    : printf("A bad option was passed\n");                 break;
      case PCRE_ERROR_BADMAGIC     : printf("Magic number bad (compiled re corrupt?)\n"); break;
      case PCRE_ERROR_UNKNOWN_NODE : printf("Something kooky in the compiled re\n");      break;
      case PCRE_ERROR_NOMEMORY     : printf("Ran out of memory\n");                       break;
      default                      : printf("Unknown error\n");                           break;
      }
    } else {
        total_matches++;
        return 1;
    }
    return 0;
}

const char* ip2s(uint32_t ip){
    static char buf[100];
    sprintf(buf, "%d.%d.%d.%d",
            ip&0xff, 
            (ip>>8)&0xff, 
            (ip>>16)&0xff, 
            (ip>>24)&0xff);
    return buf;
}

void show_ip_packet(struct iphdr*ip, int sport, int dport){
    printf("[.] ");

    switch( ip->protocol ){
        case IPPROTO_ICMP:
            printf("ICMP ");
            break;
        case IPPROTO_TCP:
            printf("TCP ");
            break;
        case IPPROTO_UDP:
            printf("UDP ");
            break;
        default:
            printf("ipproto = %x ", ip->protocol);
            break;
    }

    if( sport == -1 && dport == -1 ){
        printf("%-15s -> ", ip2s(ip->saddr) );
        printf("%-15s\n",   ip2s(ip->daddr) );
    } else {
        printf("%-15s:%-5d -> ", ip2s(ip->saddr), ntohs(sport) );
        printf("%-15s:%-5d\n",   ip2s(ip->daddr), ntohs(dport) );
    }
}

int decode_ip(const struct pcap_pkthdr *header, const u_char *packet){
    const u_char* data = packet + ETHER_SIZE;
    int size = header->caplen - ETHER_SIZE;

    struct iphdr* ip = (struct iphdr*) data;
    int size_ip = ip->ihl * 4;
    int sport = -1, dport = -1;
    int matched = 0;

    const u_char *payload;
    int payload_size;

    if( size_ip < 20 ){
        printf("[!] invalid IP hdr len %d\n", size_ip);
        payload = data;
    } else {
        payload = data + size_ip;
    }

    switch( ip->protocol ){
        case IPPROTO_ICMP:
            if( write_all_packets ) write_packet(header, packet, "ICMP");
            payload += 8; // ICMP hdr size = 8
            break;
        case IPPROTO_TCP:
            if( size >= 24 ){
                // ethernet hdr size = 20
                // sport size        =  2
                // dport size        =  2
                struct tcphdr *tcp = (struct tcphdr*)(data+size_ip);
                if( write_all_packets ) write_tcp_packet(header, packet, tcp);
                sport = tcp->source;
                dport = tcp->dest;
                if( size >= (20 + sizeof(struct tcphdr)) ){
                    payload = data + size_ip + tcp->doff*4;
                }
            } else {
                // malformed tcp?
                write_packet(header, packet, NULL);
            }
            break;
        case IPPROTO_UDP:
            if( write_all_packets ) write_packet(header, packet, "UDP");
            if( size >= 24 ){
                // ethernet hdr size = 20
                // sport size        =  2
                // dport size        =  2
                sport = *(uint16_t*)(data+size_ip);
                dport = *(uint16_t*)(data+size_ip+2);

                if( size >= 26 ){ // udp_hdr.length
                    int udp_len = *(uint16_t*)(data+size_ip+4);
                    payload = data+size_ip+8;
                }
            }
            break;

        default:
            // IP, nut not TCP nor UDP
            // payload alredy set to (data+size_ip)
            if( write_all_packets ) write_packet(header, packet, NULL);
            break;
    }
    
    if( !payload ){
        printf("[?] NULL payload\n");
        payload = data;
    }

    payload_size = size-(payload-data);
    if( payload_size < 0 || payload_size > size ){
        printf("[?] invalid payload size: %d\n", payload_size);
        payload = data;
        payload_size = size;
    }

    switch( verbosity ){
        case VERBOSITY_EVERY_PACKET_INFO:
            show_ip_packet(ip, sport, dport);
            break;
        case VERBOSITY_ALL_PAYLOAD_DATA:
            show_ip_packet(ip, sport, dport);
            if( payload_size > 0 ){
                printf("\n%d bytes of payload:\n", payload_size); 
                hexdump(payload,payload_size);
            }
            break;
        case VERBOSITY_ALL_IP_DATA:
            show_ip_packet(ip, sport, dport);
            printf("\nIP packet:\n"); 
            hexdump(data,size);
            break;
    }

    if( payload_size >= FLAG_LENGTH ){
        matched = process_payload(payload, payload_size);
        if( matched ){
            if( verbosity > VERBOSITY_SILENT){ 
                puts("");
                show_ip_packet(ip, sport, dport);
            }
            printf("[*] MATCH!\n");
            if( verbosity > VERBOSITY_QUIET) hexdump(payload, payload_size);
        }
    }
    return matched;
}


// WARNING: must return string w/o spaces or NULL
const char* ethertype2s(int type){
    switch(type){
        case ETHERTYPE_IP:
            return "IP";
        case ETHERTYPE_IPV6:
            return "IPV6";
        case ETHERTYPE_ARP:
            return "ARP";
    }
    return NULL;
}

void show_ether_packet(const u_char *data, int size){
    struct ether_header* eptr = (struct ether_header *) data;
    const char *stype;

    printf("[.] ");
    stype = ethertype2s(ntohs(eptr->ether_type));
    if( stype ){
        printf("%s ", stype);
    } else {
        printf("ethertype=0x%04x ", ntohs(eptr->ether_type));
    }
    puts("");
}

void write_packet(const struct pcap_pkthdr *header, const u_char *packet, const char*pfname){
    char fname[512],*p;
    int i;
    FILE *f;

    strcpy(fname, "out/");
    p = fname+strlen(fname);

    if( pfname ){
        strncpy(p, pfname, sizeof(fname) - (p-fname));
        fname[sizeof(fname)-1] = 0;
    } else {
        for(i=0; i<6; i++,p+=2) sprintf(p, "%02x", packet[i]);
        *p++ = '-';
        for(i=6; i<12; i++,p+=2) sprintf(p, "%02x", packet[i]);
        sprintf(p, "-%02x%02x", packet[12]&0xff, packet[13]&0xff);
    }
    
    f = fopen(fname, "ab");
    if( !f ){
        fprintf(stderr, "[!] cannot append to %s: ", fname);
        perror("");
        return;
    }

    if( 0 == ftell(f)){
        // write first packet with pcap hdr
        pcap_dumper_t* dumper = pcap_dump_fopen(pcap_handle, f);
        if( !dumper ){
            fclose(f);
            fprintf(stderr, "[!] Couldn't open file %s: %s\n", fname, pcap_geterr(pcap_handle));
            return;
        }

        pcap_dump((u_char*)dumper, header, packet);
        pcap_dump_close(dumper);
    } else {
        // append 2nd and further packets manually
        
        pcaprec_hdr_t rec_hdr; // record header
        // we cannot directly write pcap_pkthdr to file b/c it uses 64-bit timeval 
        // on 64-bit platforms, and .PCAP files always use 32-bit timeval
        rec_hdr.ts_sec   = header->ts.tv_sec;
        rec_hdr.ts_usec  = header->ts.tv_usec;
        rec_hdr.incl_len = header->caplen;
        rec_hdr.orig_len = header->len;
        fwrite(&rec_hdr, sizeof(rec_hdr), 1, f);
        fwrite(packet, 1, header->caplen, f);
        fclose(f);
    }
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	int type;
        struct ether_header* eptr = (struct ether_header *) packet;
        int size = header->caplen;
        int matched = 0;

        total_packets++;

        // skip very small packets
	if( size < ETHER_SIZE ) return;

        type = ntohs(eptr->ether_type);
        if( type == ETHERTYPE_IP){
            matched = decode_ip(header, packet);
        } else {
            if( write_all_packets ) write_packet(header, packet, ethertype2s(type));

            if( verbosity == VERBOSITY_EVERY_PACKET_INFO){
                show_ether_packet(packet, size);
            }

            matched = process_payload(packet, size);
            if( matched ){
                if( verbosity <= VERBOSITY_DEFAULT ){
                    puts("");
                    show_ether_packet(packet, size);
                }
                printf("[*] MATCH!\n");
                hexdump(packet, size);
            }
        }

        if( matched && pcap_dumper ){
            pcap_dump((u_char*)pcap_dumper, header, packet);
            pcap_dump_flush(pcap_dumper);
        }

	switch(verbosity){
            case VERBOSITY_DEFAULT:
                if( write_all_packets ){
                    printf("\r[.] %5d packets, %5d sessions, %5d matches", total_packets, total_sessions, total_matches);
                } else {
                    printf("\r[.] %5d packets, %5d matches", total_packets, total_matches);
                }
                fflush(NULL);
                break;
            case VERBOSITY_ALL_ETHERNET_DATA:
                puts("Ethernet packet:");
                hexdump(packet, header->caplen);
                break;
	}
}

void on_interrupt(int v){
    pcap_breakloop(pcap_handle);
}

#if PCAP_ERRBUF_SIZE > LIBNET_ERRBUF_SIZE
#define ERRBUF_SIZE PCAP_ERRBUF_SIZE
#else
#define ERRBUF_SIZE LIBNET_ERRBUF_SIZE
#endif

void init_pcre(){
    const char *pcreErrorStr;
    int pcreErrorOffset;

    reCompiled = pcre_compile(FLAG_REGEXP, 0, &pcreErrorStr, &pcreErrorOffset, NULL);

    // pcre_compile returns NULL on error, and sets pcreErrorOffset & pcreErrorStr
    if(reCompiled == NULL) {
        printf("ERROR: Could not compile '%s': %s\n", FLAG_REGEXP, pcreErrorStr);
        exit(1);
    }

    // Optimize the regex
    pcreExtra = pcre_study(reCompiled, 0, &pcreErrorStr);

    /* pcre_study() returns NULL for both errors and when it can not optimize
    the regex.  The last argument is how one checks for errors (it is NULL
    if everything works, and points to an error string otherwise. */
    if(pcreErrorStr != NULL) {
        printf("ERROR: Could not study '%s': %s\n", FLAG_REGEXP, pcreErrorStr);
        exit(1);
    }
}

void usage(char *name) {
        fprintf(stderr,
                "usage: %s [-i iface] [-r fname] [-w fname] [-vqpa] [expression]\n\n"
		"\t -i : capture interface (default: auto)\n"
		"\t -r : read packets from file (default: live capture)\n"
		"\t -w : write MATCHED packets to a .pcap file (default: no)\n"
		"\t -p : use promiscuous mode (default: no)\n"
		"\t -v : increase verbosity, can be used multiple times\n"
		"\t -q : decrease verbosity, can be used multiple times\n"
		"\t -a : write all packets to ./out/*.pcap files, try to dissect TCP sessions\n"
		"\t last argument is an optional PCAP filter expression.\n",
                name);
}

int main (int argc, char *argv[]){
	char           *dev = NULL;
	char		errbuf    [ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;	/* The compiled filter */
	char	        filter_exp[MAX_FILTER_LEN];
	bpf_u_int32	mask;	/* Our netmask */
	bpf_u_int32	net;	/* Our IP */
	struct pcap_pkthdr header;
	const u_char   *packet;
	int c,i;
	char* pcap_write_fname = NULL, *pcap_read_fname = NULL;

        while ((c = getopt(argc, argv, "i:hvpqw:r:a")) != EOF) {
                switch (c) {
                case 'h': // show usage
                        usage(argv[0]);
                        exit(EXIT_SUCCESS);
                case 'i': // interface
                        dev = optarg;
                        break;
                case 'v': // verbosity
                        verbosity++;
                        break;
                case 'q': // quietness
                        verbosity--;
                        break;
                case 'p': // promisc
                        promisc = 1;
                        break;
                case 'w': // write packets to file
                        pcap_write_fname = optarg;
                        break;
                case 'r': // read packets from file
                        pcap_read_fname = optarg;
                        break;
                case 'a': // write all packets
                        write_all_packets = 1;
                        mkdir("out",0755);
                        break;
                default:
                        exit(EXIT_FAILURE);
                }
        }
	argc -= optind; argv += optind;

        if( argc > 0 ){
            *filter_exp = 0;
            while( argc > 0 && argv && *argv && (strlen(filter_exp)+strlen(*argv)+2) < MAX_FILTER_LEN ){
                if(*filter_exp) strcat(filter_exp, " ");
                strcat(filter_exp, *argv);
                argc--; argv++;
            }
        } else {
            strcpy(filter_exp, DEFAULT_FILTER);
        }

        init_pcre();

	setlinebuf(stdout);

        if( pcap_read_fname ){
            /* Open the session */
            pcap_handle = pcap_open_offline(pcap_read_fname, errbuf);
            if (pcap_handle == NULL) {
                    fprintf(stderr, "Couldn't open file %s: %s\n", pcap_read_fname, errbuf);
                    return (2);
            }

            printf("[.] interface: (FILE) %s\n",pcap_read_fname);
        } else {
            if(!dev) dev = pcap_lookupdev(errbuf);
            if (dev == NULL) {
                    fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
                    return (2);
            }
            printf("[.] interface: %s\n",dev);

            /* Find the properties for the device */
            if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
                    fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
                    net = 0;
                    mask = 0;
            }

            /* Open the session */
            pcap_handle = pcap_open_live(dev, BUFSIZ, promisc, PCAP_PERIOD, errbuf);
            if (pcap_handle == NULL) {
                    fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
                    return (2);
            }
        }

	printf("[.] verbosity: %d\n",verbosity);
	printf("[.]    filter: %s\n",filter_exp);

	/* Compile and apply the filter */
	if (pcap_compile(pcap_handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(pcap_handle));
		return (2);
	}
	if (pcap_setfilter(pcap_handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(pcap_handle));
		return (2);
	}

        if( write_all_packets ){
            // enum devs to get all local ips
            pcap_if_t *alldevs, *d;
            pcap_addr_t *pa;
            int nips = 0;
            if (pcap_findalldevs(&alldevs, errbuf) == -1)
            {
                fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
                exit(1);
            }
            for(d=alldevs; d && nips < MAX_LOCAL_IPS; d=d->next)
            {
                for(pa = d->addresses; pa; pa=pa->next){
                    if( pa->addr && pa->addr->sa_family == AF_INET ){
                        struct sockaddr_in *addr = (struct sockaddr_in*) pa->addr;
                        local_ips[nips++] = *(uint32_t*)&addr->sin_addr;
                        if( nips >= MAX_LOCAL_IPS ){
                            fprintf(stderr, "[?] too many local_ips, using only %d first ones\n", MAX_LOCAL_IPS);
                            break;
                        }
                    }
                }
            }
            pcap_freealldevs(alldevs);
            local_ips[nips >= MAX_LOCAL_IPS ? (MAX_LOCAL_IPS-1) : nips] = 0;

            printf("[.] local ips:");
            for(i=0;local_ips[i];i++){
                if( i>0 ) putchar(',');
                printf(" %s",ip2s(local_ips[i]));
            }
            puts("");
        }

	signal(SIGINT,  on_interrupt);
	signal(SIGTERM, on_interrupt);

        if( pcap_write_fname ){
            pcap_dumper = pcap_dump_open(pcap_handle, pcap_write_fname);
            if( !pcap_dumper ){
		fprintf(stderr, "Couldn't open file %s: %s\n", pcap_write_fname, pcap_geterr(pcap_handle));
                exit(1);
            }
        }

        pcap_loop(pcap_handle, 0, process_packet, NULL);
//
//	// don't know why, but pcap_dispatch does not return control to main after
//	// timeout expires. so, we use nonblocking pcap on linux.
//#ifdef __linux__
//	pcap_setnonblock(pcap_handle, 1, errbuf);
//#endif
//
//	while( !do_stop ){
//		pcap_dispatch(pcap_handle, -1, process_packet, NULL);
//#ifdef __linux__
//		usleep(1000);
//#endif
//	}

        printf("\n[.] terminating.. total %d packets, %d matches\n", total_packets, total_matches);

        if(pcap_dumper) pcap_dump_close(pcap_dumper);
	pcap_close(pcap_handle);

	//i = tv_diff2msec(NULL);

	return (0);
}
