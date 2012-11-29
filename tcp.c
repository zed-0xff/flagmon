#define MAX_SESSIONS 2048

struct tcp_session {
    uint32_t saddr;
    uint32_t daddr;
    uint16_t sport;
    uint16_t dport;
    int state;
    time_t last_activity;
    char fname[128];
};

typedef struct tcp_session* tcp_session_p;

enum { TCP_FREE_SLOT = 0, TCP_STATE_ESTABLISHED, TCP_STATE_FIN1 };

static struct tcp_session sessions[MAX_SESSIONS] = {0};

tcp_session_p find_free_session(){
    int i, tmin, tmax, imin = 0;
    for(i=0;i<MAX_SESSIONS;i++){
        if( sessions[i].state == TCP_FREE_SLOT ){
            return &sessions[i];
        }
    }

    tmin = tmax = sessions[0].last_activity;
    for(i=1;i<MAX_SESSIONS;i++){
        if( sessions[i].last_activity > tmax ) tmax = sessions[i].last_activity;
        if( sessions[i].last_activity < tmin ){
            tmin = sessions[i].last_activity;
            imin = i;
        }
    }

    if( tmax-tmin > 1 ){
        // mark least recent used slot #imin as free
        sessions[imin].state = TCP_FREE_SLOT;
        return &sessions[imin];
    } else {
        fprintf(stderr, "[?] cannot find free tcp session slot. are we under TCP connection DOS attack?!\n");
    }

    return NULL;
}

tcp_session_p find_session(uint32_t saddr, uint16_t sport, uint32_t daddr, uint16_t dport){
    struct tcp_session ts = {saddr,daddr,sport,dport};
    int i;
    for(i=0;i<MAX_SESSIONS;i++){
        if( !memcmp(&ts, &sessions[i], 4*3) && sessions[i].state != TCP_FREE_SLOT ){
            return &sessions[i];
        }
    }

    struct tcp_session ts2 = {daddr,saddr,dport,sport};
    for(i=0;i<MAX_SESSIONS;i++){
        if( !memcmp(&ts2, &sessions[i], 4*3) && sessions[i].state != TCP_FREE_SLOT ){
            return &sessions[i];
        }
    }

    return NULL;
}

enum { DIR_UNKNOWN=0, DIR_IN=1, DIR_OUT=2 };

void write_tcp_packet(const struct pcap_pkthdr *header, const u_char *packet, struct tcphdr*tcp){
    struct iphdr* ip = (struct iphdr*)(packet + ETHER_SIZE);
    tcp_session_p ps = NULL;
    char fname[1024];
    int i;
    int direction = DIR_UNKNOWN;

    if( tcp->syn && !tcp->ack ){
        // TCP session start
        ps = find_free_session();

        if( !ps ) return; // no free TCP session slot

        total_sessions++;

        ps->saddr = ip->saddr;
        ps->daddr = ip->daddr;
        ps->sport = tcp->source;
        ps->dport = tcp->dest;
        ps->state = TCP_STATE_ESTABLISHED;

        for( i=0; local_ips[i]; i++){
            if( ps->saddr == local_ips[i] ){
                direction |= DIR_OUT; // OR direction to detect local-only packets
                break;
            }
        }
        if( direction == DIR_UNKNOWN ){
            for( i=0; local_ips[i]; i++){
                if( ps->daddr == local_ips[i] ){
                    direction |= DIR_IN; // OR direction to detect local-only packets
                    break;
                }
            }
        }

        switch( direction ){
            case DIR_IN:
                sprintf(ps->fname, "TCP-IN-%d-from-%d.%d.%d.%d",
                    ntohs(ps->dport),
                    (ps->saddr      ) & 0xff,
                    (ps->saddr >>  8) & 0xff,
                    (ps->saddr >> 16) & 0xff,
                    (ps->saddr >> 24) & 0xff
                );
                break;
            case DIR_OUT:
                sprintf(ps->fname, "TCP-OUT-%d.%d.%d.%d:%d",
                    (ps->daddr      ) & 0xff,
                    (ps->daddr >>  8) & 0xff,
                    (ps->daddr >> 16) & 0xff,
                    (ps->daddr >> 24) & 0xff, ntohs(ps->dport)
                );
                break;
            default:
                sprintf(ps->fname, "TCP-%d.%d.%d.%d:%d-%d.%d.%d.%d:%d",
                    (ps->saddr      ) & 0xff,
                    (ps->saddr >>  8) & 0xff,
                    (ps->saddr >> 16) & 0xff,
                    (ps->saddr >> 24) & 0xff, ntohs(ps->sport),
                    (ps->daddr      ) & 0xff,
                    (ps->daddr >>  8) & 0xff,
                    (ps->daddr >> 16) & 0xff,
                    (ps->daddr >> 24) & 0xff, ntohs(ps->dport)
                );
        }

        //show_ip_packet(ip, ps->sport, ps->dport);
    } else {
        // try to find existing session
        ps = find_session(ip->saddr, tcp->source, ip->daddr, tcp->dest);
        if( ps && tcp->fin ){
            if( ps->state == TCP_STATE_FIN1 ){
                // got 2nd FIN -> free the connection
                ps->state = TCP_FREE_SLOT;
            } else {
                // got 1st FIN
                ps->state = TCP_STATE_FIN1;
            }
        }
    }

    if( ps ){
        time( &ps->last_activity );
        write_packet(header, packet, ps->fname);
    } else {
        sprintf(fname, "TCP-%d.%d.%d.%d:%d-%d.%d.%d.%d:%d",
            (ip->saddr      ) & 0xff,
            (ip->saddr >>  8) & 0xff,
            (ip->saddr >> 16) & 0xff,
            (ip->saddr >> 24) & 0xff, ntohs(tcp->source),
            (ip->daddr      ) & 0xff,
            (ip->daddr >>  8) & 0xff,
            (ip->daddr >> 16) & 0xff,
            (ip->daddr >> 24) & 0xff, ntohs(tcp->dest)
        );
        write_packet(header, packet, fname);
    }
}
