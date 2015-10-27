//
//  ip6_gre.c
//  gre
//
//  Created by Zhenlei Huang on 10/7/15.
//
//
/*-
 * Copyright (c) 2014 Andrey V. Elsukov <ae@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/systm.h>
#include <sys/kpi_mbuf.h>
#include <sys/sysctl.h>
#include <sys/socket.h>

#include <net/bpf.h>
#include <net/kpi_protocol.h>
#include <net/kpi_interface.h>

#include <net/if.h>
#include <net/ethernet.h>

#include <netinet/kpi_ipfilter.h>

#include "kernel_build.h"
#include "gre_ip_encap.h"
#include "if_gre.h"


static int ip6_gre_hlim = IPV6_DEFHLIM;

SYSCTL_DECL(_net_gre);
SYSCTL_INT(_net_gre, OID_AUTO, hlim, CTLTYPE_INT | CTLFLAG_RW, &ip6_gre_hlim, 0, "Default hop limit for encapsulated packets");


static int
in6_gre_encapcheck(const mbuf_t m, int off, int proto, void *arg)
{
	struct gre_softc *sc;
	struct ip6_hdr *ip6;

	sc = (struct gre_softc *)arg;
	if ((ifnet_flags(sc->gre_ifp) & IFF_UP) == 0)
		return 0;

	//M_ASSERTPKTHDR(m);
	/*
	 * We expect that payload contains at least IPv4
	 * or IPv6 packet.
	 */
	if (mbuf_pkthdr_len(m) < sizeof(struct greip6) + sizeof(struct ip))
		return 0;

	GRE_RLOCK(sc);
	if (sc->gre_family == 0)
		goto bad;

	KASSERT(sc->gre_family == AF_INET6,
		("wrong gre_family: %d", sc->gre_family));

	ip6 = mtod(m, struct ip6_hdr *);
	if (!IN6_ARE_ADDR_EQUAL(&sc->gre_oip6.ip6_src, &ip6->ip6_dst) ||
	    !IN6_ARE_ADDR_EQUAL(&sc->gre_oip6.ip6_dst, &ip6->ip6_src))
		goto bad;

	GRE_RUNLOCK(sc);
	return (128 * 2);
bad:
	GRE_RUNLOCK(sc);
	return 0;
}


errno_t
in6_gre_output(mbuf_t m, int af, int hlen)
{
	struct greip6 *gi6;
	errno_t err;

	gi6 = mtod(m, struct greip6 *);

	//gi6->gi6_ip6.ip6_hlim = V_ip6_gre_hlim;
	gi6->gi6_ip6.ip6_hlim = ((unsigned int)ip6_gre_hlim) & 0xff;


	err = ipf_inject_output(m, NULL, NULL);

	return err;
}


errno_t
in6_gre_attach(struct gre_softc *sc)
{
	KASSERT(sc->gre_ecookie == NULL, ("gre_ecookie isn't NULL"));
	sc->gre_ecookie = (void *)gre_encap_attach_func(AF_INET6, IPPROTO_GRE,
					    in6_gre_encapcheck, gre_input, sc);
	if (sc->gre_ecookie == NULL)
		return (EEXIST);
	return (0);
}
