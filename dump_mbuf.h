/*
 *  dump_mbuf.h
 *  gre
 *
 *  Created by Summer Town on 12/2/10.
 *  Copyright 2010 __MyCompanyName__. All rights reserved.
 *
 */

#ifndef _DUMP_MBUF_H_
#define _DUMP_MBUF_H_

extern void dump_mbuf(const mbuf_t m);
extern int chk_mbuf(const mbuf_t m);
extern void dump_ip(const struct ip *iph);
extern void print_ip_addr(const in_addr_t in);
#endif // _DUMP_MBUF_H_