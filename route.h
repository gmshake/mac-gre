/*
 * Copyright (c) 2000-2008 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 * 
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */
/*
 * Copyright (c) 1980, 1986, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)route.h	8.3 (Berkeley) 4/19/94
 * $FreeBSD: src/sys/net/route.h,v 1.36.2.1 2000/08/16 06:14:23 jayanth Exp $
 */

/* this is taken from xnu1228.15.4, modified */

#ifndef _PRIVATE_NET_ROUTE_H_
#define _PRIVATE_NET_ROUTE_H_
#include <sys/appleapiopts.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/route.h>

/*
 * Kernel resident routing tables.
 *
 * The routing tables are initialized when interface addresses
 * are set by making entries for all directly connected interfaces.
 */

/*
 * A route consists of a destination address and a reference
 * to a routing entry.  These are often held by protocols
 * in their control blocks, e.g. inpcb.
 */
struct rtentry;
struct route {
	struct	rtentry *ro_rt;
	struct	sockaddr ro_dst;
	u_int32_t	ro_flags;	/* route flags (see below) */
	u_int32_t	reserved;	/* for future use if needed */
};

#define	ROF_SRCIF_SELECTED	0x1 /* source interface was selected */

/*
 * XXX kernel function pointer `rt_output' is visible to applications.
 */

/*
 * We distinguish between routes to hosts and routes to networks,
 * preferring the former if available.  For each route we infer
 * the interface to use from the gateway address supplied when
 * the route was entered.  Routes that forward packets through
 * gateways are marked so that the output routines know to address the
 * gateway rather than the ultimate destination.
 */
#ifndef RNF_NORMAL
#include "radix.h"
#endif
struct rtentry {
	struct	radix_node rt_nodes[2];	/* tree glue, and other values */
#define	rt_key(r)	((struct sockaddr *)((r)->rt_nodes->rn_key))
#define	rt_mask(r)	((struct sockaddr *)((r)->rt_nodes->rn_mask))
	struct	sockaddr *rt_gateway;	/* value */
	int32_t	rt_refcnt;		/* # held references */
	u_long	rt_flags;		/* up/down?, host/net */
	ifnet_t rt_ifp;		/* the answer: interface to use */
        u_long  rt_dlt;			/* DLIL dl_tag */
	struct	ifaddr *rt_ifa;		/* the answer: interface to use */
	struct	sockaddr *rt_genmask;	/* for generation of cloned routes */
	caddr_t	rt_llinfo;		/* pointer to link level info cache */
	struct	rt_metrics rt_rmx;	/* metrics used by rx'ing protocols */
	struct	rtentry *rt_gwroute;	/* implied entry for gatewayed routes */
	int	(*rt_output)(struct ifnet *, mbuf_t,
			     struct sockaddr *, struct rtentry *);
					/* output routine for this (rt,if) */
	struct	rtentry *rt_parent;	/* cloning parent of this route */
	u_long	generation_id;		/* route generation id */
};

#define rt_use rt_rmx.rmx_pksent

/*
 * For scoped routing; a zero interface scope value means nil/no scope.
 */
#define	IFSCOPE_NONE	0

extern lck_mtx_t *rt_mtx;

extern int rt_setgate(struct rtentry *, struct sockaddr *, struct sockaddr *);
extern struct rtentry *rtalloc1_locked(struct sockaddr *, int, u_long);
extern void rtfree(struct rtentry *);

/*
 * rtunref will decrement the refcount, rtfree will decrement and free if
 * the refcount has reached zero and the route is not up.
 * Unless you have good reason to do otherwise, use rtfree.
 */
extern void rtunref(struct rtentry *);

extern int rtrequest_locked(int, struct sockaddr *, struct sockaddr *, struct sockaddr *, int, struct rtentry **);

#endif //_PRIVATE_NET_ROUTE_H_
