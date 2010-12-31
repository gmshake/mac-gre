/*
 *  dump_mbuf.c
 *  gre
 *
 *  Created by Summer Town on 12/2/10.
 *  Copyright 2010 __MyCompanyName__. All rights reserved.
 *
 */

#include <sys/systm.h>
#include <sys/kpi_mbuf.h>
#include <netinet/ip.h>

struct my_struct {
    mbuf_flags_t flags;
    const char *type;
} arr[10] = {
    { 0x0001, "MBUF_EXT" },
    { 0x0002, "MBUF_PKTHDR" },
    { 0x0004, "MBUF_EOR" },
    { 0x0100, "MBUF_BCAST" },
    { 0x0200, "MBUF_MCAST" },
    { 0x0400, "MBUF_FRAG" },
    { 0x0800, "MBUF_FIRSTFRAG" },
    { 0x1000, "MBUF_LASTFRAG" },
    { 0x2000, "MBUF_PROMISC" },
    { 0x0000, "" }
};

void dump_mbuf(const mbuf_t m)
{
    if (m == NULL) {
        printf("%s: warning, get NULL pointer!!!\n", __FUNCTION__);
        return;
    }
	printf("\t****dump mbuf****\n");

    mbuf_flags_t flags = mbuf_flags(m);
    printf("\tmbuf_type: %d  mbuf_pkthdr_len: %d  mbuf_len: %d  mbuf_flag: 0x%04x\n", \
           mbuf_type(m), mbuf_pkthdr_len(m), mbuf_len(m), flags);
    
    int i = 0;
    while (arr[i].flags > 0) {
        if (flags & arr[i].flags) {
            printf("\t%s\n", arr[i].type);
        }
        ++i;
    }
    if (mbuf_next(m))
        printf("\tmbuf_next:%p\t", mbuf_next(m));
    if (mbuf_nextpkt(m))
        printf("mbuf_nextpkt:%p\n", mbuf_nextpkt(m));
    else
        printf("\n");
}

void dump_ip(const struct ip *iph)
{
    if (iph == NULL)
        return;

    printf("version: %d  header_len: %d  proto: %d  total_len: %d  sum: %04x\n", \
           iph->ip_v, iph->ip_hl, iph->ip_p, ntohs(iph->ip_len), ntohs(iph->ip_sum));
}

void print_ip_addr(in_addr_t in)
{
    in = ntohl(in);
    printf("%d.%d.%d.%d", (in >> 24) & 0xff, (in >> 16) & 0xff, (in >> 8) & 0xff, in & 0xff);
}

int chk_mbuf(mbuf_t m)
{
    if (! (mbuf_flags(m) &  MBUF_PKTHDR)) {
        printf("%s: Warning: It is NOT a mbuf pkt header !!!\n", __FUNCTION__);
        return -1;
    }
    size_t len = mbuf_pkthdr_len(m);
    while (len > mbuf_len(m)) {
		if (mbuf_next(m) == NULL) {
            printf("%s: invalid mbuf chain\n", __FUNCTION__);
            return -1;
        }
		len -= mbuf_len(m);
		m = mbuf_next(m);
	}
    return 0;
}
