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


/*
 * Output queues (ifp->if_snd) and slow device input queues (*ifp->if_slowq)
 * are queues of messages stored on ifqueue structures
 * (defined above).  Entries are added to and deleted from these structures
 * by these macros, which should be called with ipl raised to splimp().
 */
#define IF_QFULL(ifq)           ((ifq)->ifq_len >= (ifq)->ifq_maxlen)
#define IF_DROP(ifq)            ((ifq)->ifq_drops++)

#define IF_ENQUEUE IF_ENQUEUE_MBUF
#define IF_PREPEND IF_PREPEND_MBUF
#define IF_DEQUEUE IF_DEQUEUE_MBUF


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