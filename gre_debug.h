/*
 *  comman_macros.h
 *  gre
 *
 *  Created by Summer Town on 11/26/10.
 *  Copyright 2010 __MyCompanyName__. All rights reserved.
 *
 */

#ifndef _GRE_DEBUG_H
#define _GRE_DEBUG_H

#ifdef DEBUG
#define dprintf(...) printf(__VA_ARGS__)
#define dlog(...) log(__VA_ARGS__)
#define ddump_mbuf(m) dump_mbuf(m)
#define ddump_ip(ip) dump_ip(ip)
#else
#define dprintf(...)
#define dlog(...)
#define ddump_mbuf(m)
#define ddump_ip(ip)
#endif

#endif //_GRE_DEBUG_H
