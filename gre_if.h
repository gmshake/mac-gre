/*-
 * Copyright (c) 1998 The NetBSD Foundation, Inc.
 * Copyright (c) 2014 Andrey V. Elsukov <ae@FreeBSD.org>
 * All rights reserved
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Heiko W.Rupp <hwr@pilhuhn.de>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * $NetBSD: if_gre.h,v 1.13 2003/11/10 08:51:52 wiz Exp $
 * $FreeBSD$
 */

#ifndef _NET_IF_GRE_H
#define _NET_IF_GRE_H


#include <libkern/OSTypes.h>
#include <sys/systm.h>
#include <sys/appleapiopts.h>

#include <net/kpi_interface.h>

#include <netinet/in.h>
#include <netinet/ip.h>

#include <netinet/ip6.h>


#include "gre_config.h"


/* GRE header according to RFC 2784 and RFC 2890 */
struct grehdr {
	uint16_t	gre_flags;	/* GRE flags */
#define	GRE_FLAGS_CP	0x8000		/* checksum present */
#define	GRE_FLAGS_KP	0x2000		/* key present */
#define	GRE_FLAGS_SP	0x1000		/* sequence present */
#define	GRE_FLAGS_MASK	(GRE_FLAGS_CP|GRE_FLAGS_KP|GRE_FLAGS_SP)
	uint16_t	gre_proto;	/* protocol type */
	uint32_t	gre_opts[0];	/* optional fields */
} __attribute__((__packed__));

struct greip {
	struct ip	gi_ip;
	struct grehdr	gi_gre;
}__attribute__((__packed__));

struct greip6 {
	struct ip6_hdr	gi6_ip6;
	struct grehdr	gi6_gre;
}__attribute__((__packed__));


/*
 * Version of the WCCP, need to be configured manually since
 * header for version 2 is the same but IP payload is prepended
 * with additional 4-bytes field.
 */
//typedef enum {
//	WCCP_V1 = 0,
//	WCCP_V2
//} wccp_ver_t;

struct gre_softc {
	ifnet_t             gre_ifp;
	struct gre_softc        *pcb_next;
	TAILQ_ENTRY(gre_softc)  gre_list;
	lck_rw_t		*gre_lock;
	volatile SInt32	sc_refcnt;  /* reference count */
	lck_mtx_t           *mtx;	/* interface mutex */

	int		gre_family;	/* AF of delivery header */
	uint32_t	gre_iseq;
	uint32_t	gre_oseq;
	uint32_t	gre_key;	/* key included in outgoing GRE packets */  /* zero means none */
	uint32_t	gre_options;
	uint32_t	gre_mtu;
	u_int		gre_hlen;	/* header size */

	union {
		void		*hdr;
		struct greip	*gihdr;
		struct greip6	*gi6hdr;
	} gre_uhdr;

//	struct sockaddr gre_psrc; /* Physical src addr */
//	struct sockaddr gre_pdst; /* Physical dst addr */

	uint16_t   is_detaching;	/* state of the interface */

	//	uint32_t    called;		/* infinite recursion preventer */

//	wccp_ver_t  wccp_ver;	/* version of the WCCP */

	void *gre_ecookie;
#if USE_IP_OUTPUT
	struct route route;   /* route used for ip_output */
#endif
};

//#define	GRE2IFP(sc)		((sc)->gre_ifp)
#define	GRE_RLOCK(sc)		lck_rw_lock_shared((sc)->gre_lock)
#define	GRE_RUNLOCK(sc)		lck_rw_unlock_shared((sc)->gre_lock)
#define	GRE_WLOCK(sc)		lck_rw_lock_exclusive((sc)->gre_lock)
#define	GRE_WUNLOCK(sc)		lck_rw_unlock_exclusive((sc)->gre_lock)

#define sx_xlock(lck)		lck_rw_lock_exclusive(lck)
#define sx_xunlock(lck)		lck_rw_unlock_exclusive(lck)
#define sx_assert(lck, st)

#define	gre_hdr			gre_uhdr.hdr
#define	gre_gihdr		gre_uhdr.gihdr
#define	gre_gi6hdr		gre_uhdr.gi6hdr
#define	gre_oip			gre_gihdr->gi_ip
#define	gre_oip6		gre_gi6hdr->gi6_ip6

/*
#define gi_ver      gi_i.ip_v
#define gi_hlen     gi_i.ip_hl
#define gi_pr		gi_i.ip_p
#define gi_len		gi_i.ip_len
#define gi_src		gi_i.ip_src
#define gi_dst		gi_i.ip_dst
#define gi_sum      gi_i.ip_sum

#define gi_ptype	gi_g.ptype
#define gi_flags	gi_g.flags
#define gi_options	gi_g.options
*/


/*
 * CISCO uses special type for GRE tunnel created as part of WCCP
 * connection, while in fact those packets are just IPv4 encapsulated
 * into GRE.
 */
#define ETHERTYPE_WCCP		0x883E


#define GRESADDRS	_IOW('i', 101, struct ifreq)
#define GRESADDRD	_IOW('i', 102, struct ifreq)
#define GREGADDRS	_IOWR('i', 103, struct ifreq)
#define GREGADDRD	_IOWR('i', 104, struct ifreq)
#define GRESPROTO	_IOW('i' , 105, struct ifreq)
#define GREGPROTO	_IOWR('i', 106, struct ifreq)

#define	GREGKEY		_IOWR('i', 107, struct ifreq)
#define	GRESKEY		_IOW('i', 108, struct ifreq)
#define	GREGOPTS	_IOWR('i', 109, struct ifreq)
#define	GRESOPTS	_IOW('i', 110, struct ifreq)

#define	GRE_ENABLE_CSUM		0x0001
#define	GRE_ENABLE_SEQ		0x0002
#define	GRE_OPTMASK		(GRE_ENABLE_CSUM|GRE_ENABLE_SEQ)

/*
 * usefull macro
 */
#ifndef in_hosteq
#define in_hosteq(s, t) ((s).s_addr == (t).s_addr)
#endif

#ifndef satosin
#define satosin(sa)     ((struct sockaddr_in *)(sa))
#endif

#ifndef sintosa
#define sintosa(sin)    ((struct sockaddr *)(sin))
#endif

#ifndef SIN6
#define SIN6(s)         ((struct sockaddr_in6 *)(void *)s)
#endif

#ifndef satosin6
#define satosin6(sa)    SIN6(sa)
#endif

#ifndef sin6tosa
#define sin6tosa(sin6)  ((struct sockaddr *)(void *)(sin6))
#endif

#define	GRE_TTL	30
#define GRE_MAXUNIT	0x7fff	/* ifp->if_unit is only 15 bits(short int) */
#define GRE_CONTROL_NAME "org.gmshake.nke.gre_control"


extern void gre_sc_reference(struct gre_softc *sc);
extern void gre_sc_release(struct gre_softc *sc);

extern int gre_proto_register(void);
extern void gre_proto_unregister(void);

extern int gre_if_init(void);
extern int gre_if_dispose(void);
extern int gre_if_attach(void);

//extern uint16_t    gre_in_cksum(uint16_t *p, u_int len);

extern void	gre_input(mbuf_t *mp, int *offp, int proto);


extern struct gre_softc * gre_softc_search4(in_addr_t src, in_addr_t dst);
extern struct gre_softc * gre_softc_search6(struct in6_addr src, struct in6_addr dst);


#endif
