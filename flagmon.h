// http://wiki.wireshark.org/Development/LibpcapFileFormat
typedef struct pcaprec_hdr_s {
        uint32_t ts_sec;         /* timestamp seconds */
        uint32_t ts_usec;        /* timestamp microseconds */
        uint32_t incl_len;       /* number of octets of packet saved in file */
        uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

void write_packet(const struct pcap_pkthdr *header, const u_char *packet, const char*pfname);
void show_ip_packet(struct iphdr*ip, int sport, int dport);

#define ETHER_SIZE sizeof(struct ether_header)
