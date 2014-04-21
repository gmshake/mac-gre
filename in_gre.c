/*
 *  in_gre.c
 *  gre
 *
 *  Created by Summer Town on 1/10/11.
 *  Copyright 2011 __MyCompanyName__. All rights reserved.
 *
 */
/*      $NetBSD: ip_gre.c,v 1.29 2003/09/05 23:02:43 itojun Exp $ */

/*-
 * Copyright (c) 1998 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Heiko W.Rupp <hwr@pilhuhn.de>
 *
 * IPv6-over-GRE contributed by Gert Doering <gert@greenie.muc.de>
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
 *        This product includes software developed by the NetBSD
 *        Foundation, Inc. and its contributors.
 * 4. Neither the name of The NetBSD Foundation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
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
 */


#include <sys/systm.h>
#include <sys/kpi_mbuf.h>
#include <sys/socket.h>

#include <net/bpf.h>
#include <net/kpi_protocol.h>
#include <net/if.h>
#include <net/ethernet.h>
//#include <netat/appletalk.h>

#include "gre_if.h"
#include "gre_hash.h"


extern u_int16_t in_cksum(mbuf_t m, int len);


/*
 * Find the gre interface associated with our src/dst/proto set.
 */
static inline struct gre_softc *
gre_lookup(mbuf_t m, u_int8_t proto)
{
    struct ip *ip = mbuf_data(m);
    gre_hash_lock_shared();
    struct gre_softc *sc = gre_hash_find(ip->ip_dst, ip->ip_src, proto);
    gre_hash_unlock_shared();

    // up and running
    if (sc) {
        if ((ifnet_flags(sc->sc_ifp) & (IFF_UP | IFF_RUNNING)) != (IFF_UP | IFF_RUNNING)) {
            gre_sc_release(sc);
            sc = NULL;
#ifdef DEBUG
            printf("%s: found gre_softc but interface is down", __FUNCTION__);
#endif
        }
    }

    return sc;
}

/*
 * Decapsulate. Does the real work and is called from in_gre_input()
 * (above) or ipv4_infilter(), Returns an mbuf back if packet is not
 * yet processed, and NULL if it needs no further processing.
 * proto is the protocol number of the "calling" foo_input() routine.
 */
mbuf_t in_gre_input(mbuf_t m, int hlen)
{
    struct greip *gip;
    struct gre_softc *sc;
    u_int16_t   flags;
    //static u_int32_t   af;
    //u_int8_t    proto;
    
    //proto = ((struct ip *)mbuf_data(m))->ip_p;
    
    if ((sc = gre_lookup(m, IPPROTO_GRE)) == NULL) {
        /* No matching tunnel or tunnel is down. */
        return m;
    }
    
    /* from here on, we increased the sc->sc_refcnt, so do remember to decrease it before return */
    
    if (mbuf_len(m) < sizeof(struct greip)) {
        mbuf_pullup(&m, sizeof(struct greip));
        if (m == NULL)
            goto done;
    }
    gip = mbuf_data(m);
    
    //switch (proto) {
    //    case IPPROTO_GRE:
            hlen += sizeof(struct gre_h);
            
            /* process GRE flags as packet can be of variable len */
            flags = ntohs(gip->gi_flags);
            
            /* Checksum & Offset are present */
            if ((flags & GRE_CP) | (flags & GRE_RP))
                hlen += 4;
            /* We don't support routing fields (variable length) */
            if (flags & GRE_RP)
                goto done;
            if (flags & GRE_KP)
                hlen += 4;
            if (flags & GRE_SP)
                hlen += 4;
            
            switch (ntohs(gip->gi_ptype)) { /* ethertypes */
                case WCCP_PROTOCOL_TYPE:
                    if (sc->wccp_ver == WCCP_V2)
                        hlen += 4;
                    /* FALLTHROUGH */
                case ETHERTYPE_IP:
                    //af = AF_INET;
                    break;
                case ETHERTYPE_IPV6:
                    //af = AF_INET6;
                    break;
                //case ETHERTYPE_AT:
                //    af = AF_APPLETALK;
                //    break;
                default:
                    /* Others not yet supported. */
                    goto done;
            }
    //        break;
    //    default:
            /* Others not yet supported. */
    //        goto done;
    //}
    
    if (hlen > mbuf_pkthdr_len(m)) { /* not a valid GRE packet */
        mbuf_freem(m);
        m = NULL;
        goto done;
    }
    /* Unlike NetBSD, in FreeBSD(as well as Darwin) m_adj() adjusts mbuf_pkthdr_len(m) as well */
    mbuf_adj(m, hlen);
    
    mbuf_pkthdr_setrcvif(m, sc->sc_ifp);
    mbuf_pkthdr_setheader(m, NULL);
    //mbuf_pkthdr_setheader(m, &af); /* it's ugly... */
    
    struct ifnet_stat_increment_param incs;
    bzero(&incs, sizeof(incs));
    incs.packets_in = 1;
	incs.bytes_in = mbuf_pkthdr_len(m);
    
    ifnet_input(sc->sc_ifp, m, &incs);
    
    m = NULL; /* ifnet_input() has freed the mbuf */

done:
    /* since we got sc->sc_refcnt add by one, we decrease it when done */
    gre_sc_release(sc);
    return m;
}

/*
 * input routine for IPPRPOTO_MOBILE
 * This is a little bit diffrent from the other modes, as the
 * encapsulating header was not prepended, but instead inserted
 * between IP header and payload
 */
mbuf_t in_mobile_input(mbuf_t m, int hlen)
{
#ifdef DEBUG
    printf("%s: got packet\n", __FUNCTION__);
#endif
    struct ip *ip;
    struct mobip_h *mip;
    struct gre_softc *sc;
    int msiz;
    
    if ((sc = gre_lookup(m, IPPROTO_MOBILE)) == NULL) {
        /* No matching tunnel or tunnel is down. */
        return m;
    }
    
    /* from here on, we increased the sc->sc_refcnt, so do remember to decrease it before return */
    
    if (mbuf_len(m) < sizeof(*mip)) {
        mbuf_pullup(&m, sizeof(*mip));
        if (m == NULL)
            goto done;
    }
    ip = mbuf_data(m);
    mip = mbuf_data(m);
    
    if (ntohs(mip->mh.proto) & MOB_H_SBIT) {
        msiz = MOB_H_SIZ_L;
        mip->mi.ip_src.s_addr = mip->mh.osrc;
    } else
        msiz = MOB_H_SIZ_S;
    
    if (mbuf_len(m) < (ip->ip_hl << 2) + msiz) {
        mbuf_pullup(&m, (ip->ip_hl << 2) + msiz);
        if (m == NULL)
            goto done;
        ip = mbuf_data(m);
        mip = mbuf_data(m);
    }
    
    mip->mi.ip_dst.s_addr = mip->mh.odst;
    mip->mi.ip_p = (ntohs(mip->mh.proto) >> 8);
    
    if (gre_in_cksum((u_int16_t *)&mip->mh, msiz) != 0) {
        mbuf_freem(m);
        m = NULL;
        goto done;
    }
    
    bcopy((caddr_t)(ip) + (ip->ip_hl << 2) + msiz, (caddr_t)(ip) +
          (ip->ip_hl << 2), mbuf_len(m) - msiz - (ip->ip_hl << 2));
    mbuf_setdata(m, mbuf_data(m), mbuf_len(m) - msiz);
    mbuf_pkthdr_adjustlen(m, - msiz);
    
    /*
     * On FreeBSD, rip_input() supplies us with ip->ip_len
     * already converted into host byteorder and also decreases
     * it by the lengh of IP header, however, ip_input() expects
     * that this field is in the original format (network byteorder
     * and full size of IP packet), so that adjust accordingly.
     */
    ip->ip_len = htons(ip->ip_len + sizeof(struct ip) - msiz);
    
    ip->ip_sum = 0;
    ip->ip_sum = in_cksum(m, (ip->ip_hl << 2));
    
    mbuf_pkthdr_setrcvif(m, sc->sc_ifp);
    mbuf_pkthdr_setheader(m, NULL);
    
    struct ifnet_stat_increment_param incs;
    bzero(&incs, sizeof(incs));
    incs.packets_in = 1;
	incs.bytes_in = mbuf_pkthdr_len(m);

    ifnet_input(sc->sc_ifp, m, &incs);

    m = NULL; /* ifnet_input() has freed the mbuf */

done:
    /* since we got sc->sc_refcnt add by one, we decrease it when done */
    gre_sc_release(sc);
    return m;
}


