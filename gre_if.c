/*	$NetBSD: if_gre.c,v 1.49 2003/12/11 00:22:29 itojun Exp $ */
/*	 $FreeBSD: src/sys/net/if_gre.c,v 1.46.2.5.4.1 2009/04/15 03:14:26 kensmith Exp $ */

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

/*
 * Encapsulate L3 protocols into IP
 * See RFC 2784 (successor of RFC 1701 and 1702) for more details.
 * If_gre is compatible with Cisco GRE tunnels, so you can
 * have a NetBSD box as the other end of a tunnel interface of a Cisco
 * router. See gre(4) for more details.
 * Also supported:  IP in IP encaps (proto 55) as of RFC 2004
 */

#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/kpi_mbuf.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/bpf.h>
#include <net/kpi_protocol.h>
#include <net/ethernet.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/kpi_ipfilter.h>

#if CONFIG_MACF_NET
#include <security/mac_framework.h>
#endif

#include "gre_if.h"
#include "gre_ipfilter.h"

#include "gre_debug.h"

#ifdef DEBUG
#include "gre_seq.h"
#include "dump_mbuf.h"
#endif

/*
 * It is not easy to calculate the right value for a GRE MTU.
 * We leave this task to the admin and use the same default that
 * other vendors use.
 */
#define GREMTU	1476
#define GRE_MIN_MTU 576

#define GRENAME	"gre"
#define GRE_MAXUNIT	0x7fff	/* ifp->if_unit is only 15 bits(short int) */

static const int max_linkhdr = ETHER_HDR_LEN + 2; /* link layer header, ETHER_HDR_LEN + overhead, default is 16 in xnu1228 */

TAILQ_HEAD(gre_softc_head, gre_softc) gre_softc_list;
int ngre = 0;       /* number of interfaces */

extern ipfilter_t gre_ipfilter;
extern lck_grp_t *gre_lck_grp;
lck_rw_t *gre_domain_lck; // protect gre_softc_list and ngre


int gre_init();
int gre_dispose();
int gre_attach();
static errno_t gre_detach(ifnet_t ifp);

errno_t     gre_attach_proto_family(ifnet_t ifp, protocol_family_t protocol);
void        gre_detach_proto_family(ifnet_t ifp, protocol_family_t protocol);

static errno_t  gre_add_proto(ifnet_t ifp, protocol_family_t protocol, const struct ifnet_demux_desc *demux_array, u_int32_t demux_count);
static errno_t  gre_del_proto(ifnet_t ifp, protocol_family_t	protocol);

static errno_t  gre_ioctl(ifnet_t ifp, u_int32_t cmd, void *data);
static errno_t  gre_set_bpf_tap(ifnet_t ifp, bpf_tap_mode mode, bpf_packet_func func);
static void     gre_if_free(ifnet_t ifp);

static int      gre_demux(ifnet_t ifp, mbuf_t m, char *frame_header, protocol_family_t *protocol);
static errno_t  gre_input(ifnet_t ifp, protocol_family_t	protocol, mbuf_t m, char *frame_header);

static errno_t  gre_pre_output(ifnet_t ifp, protocol_family_t protocol, mbuf_t *packet,
                                 const struct sockaddr *dest, void *route, char *frame_type, char *link_layer_dest);
static errno_t  gre_framer(ifnet_t ifp, mbuf_t *m, const struct sockaddr *dest, const char *dest_linkaddr, const char *frame_type);
static errno_t  gre_output(ifnet_t ifp, mbuf_t m);
static errno_t  in_gre_output(ifnet_t ifp, protocol_family_t proto, mbuf_t m, route_t rt);

//static errno_t      gre_compute_route(struct gre_softc *sc);
static u_int16_t    gre_in_cksum(u_int16_t *, u_int);

/*
 * This macro controls the default upper limitation on nesting of gre tunnels.
 * Since, setting a large value to this macro with a careless configuration
 * may introduce system crash, we don't allow any nestings by default.
 * If you need to configure nested gre tunnels, you can define this macro
 * in your kernel configuration file.  However, if you do so, please be
 * careful to configure the tunnels so that it won't make a loop.
 */
#ifndef MAX_GRE_NEST
#define MAX_GRE_NEST 1
#endif
static int max_gre_nesting = MAX_GRE_NEST;
/*
 * todo later, sigh...
 *
SYSCTL_DECL(_net);
SYSCTL_NODE(_net, IFT_OTHER, gre, CTLFLAG_RW, 0, "Generic Routing Encapsulation");
SYSCTL_UINT(_net_gre, OID_AUTO, maxnesting, CTLTYPE_INT | CTLFLAG_RW, &max_gre_nesting, 0, "Max nested tunnels");
*/
 
int gre_init()
{
    if (gre_domain_lck != NULL)
        return 0;

    gre_domain_lck = lck_rw_alloc_init(gre_lck_grp, NULL);
    if (gre_domain_lck == NULL)
        return -1;

    TAILQ_INIT(&gre_softc_list);

/*
 * there seems to be some bug here, that is anoying
 *
 * sysctl_register_oid(&sysctl__net_gre);
 * sysctl_register_oid(&sysctl__net_gre_maxnesting);
 */
    return 0;
}


int gre_dispose()
{
    struct gre_softc *sc;
    lck_rw_lock_exclusive(gre_domain_lck);
    TAILQ_FOREACH(sc, &gre_softc_list, sc_list) {
        if (sc->sc_ifp) {
            gre_detach(sc->sc_ifp);
            sc->sc_ifp = NULL;
        }
    }
    
    // can't dispose if interface are in use
    if (!TAILQ_EMPTY(&gre_softc_list)) {
        lck_rw_unlock_exclusive(gre_domain_lck);
        return EBUSY;
    }
    lck_rw_unlock_exclusive(gre_domain_lck);

    lck_rw_free(gre_domain_lck, gre_lck_grp);
    gre_domain_lck = NULL;

/*
 * sysctl_unregister_oid(&sysctl__net_gre_maxnesting);
 * sysctl_unregister_oid(&sysctl__net_gre);
 */
    return 0;
}


int gre_attach()
{
    errno_t result = 0;
	struct gre_softc *sc;
    struct ifnet_init_params init;
    
    lck_rw_lock_shared(gre_domain_lck);
    /* Check for unused gre interface */
	TAILQ_FOREACH(sc, &gre_softc_list, sc_list) {
		/* If unused, return, no need to create a new interface */
		if (sc->sc_ifp && (ifnet_flags(sc->sc_ifp) & IFF_RUNNING) == 0) {
            lck_rw_unlock_shared(gre_domain_lck);
            return 0;
        }
	}
    
    if (ngre == GRE_MAXUNIT) {
        lck_rw_unlock_shared(gre_domain_lck);
        return EMFILE; // any better Error code?
    }
    lck_rw_unlock_shared(gre_domain_lck);

    MALLOC(sc, struct gre_softc *, sizeof(struct gre_softc), M_TEMP, M_WAITOK | M_ZERO);
    if (sc == NULL)
		return ENOMEM;

    sc->mtx = lck_mtx_alloc_init(gre_lck_grp, NULL);
	if (sc->mtx == NULL) {
        result = ENOMEM;
		goto error;
	}

    bzero(&init, sizeof(init));
	init.name = GRENAME;
	init.unit = ngre;
	init.type = IFT_OTHER;
	init.family = IFNET_FAMILY_TUN;
	init.output = gre_output;
	init.demux = gre_demux;
	init.add_proto = gre_add_proto;
	init.del_proto = gre_del_proto;
    init.framer = gre_framer;
	init.softc = sc;
	init.ioctl = gre_ioctl;
	init.set_bpf_tap = gre_set_bpf_tap;
    init.detach = gre_if_free;
    
	result = ifnet_allocate(&init, &sc->sc_ifp);
	if (result != 0) {
		printf("%s: ifnet_allocate() failed - %d\n", __FUNCTION__, result);
		result = ENOMEM;
		goto error;
	}
    
    sc->called = 0;
    sc->gre_pdst = sc->gre_psrc = NULL;
    sc->encap_proto = IPPROTO_GRE;
    ifnet_set_addrlen(sc->sc_ifp, 0);
    ifnet_set_mtu(sc->sc_ifp, GREMTU);
    ifnet_set_hdrlen(sc->sc_ifp, 24); // IP + GRE
	ifnet_set_flags(sc->sc_ifp, IFF_POINTOPOINT | IFF_MULTICAST | IFF_LINK0, 0xffff);
    sc->wccp_ver = WCCP_V1;
    sc->key = 0;
    
	ifnet_touch_lastchange(sc->sc_ifp);
    
    result = ifnet_attach(sc->sc_ifp, NULL);
	if (result != 0) {
		printf("%s: ifnet_attach() failed - %d\n", __FUNCTION__, result);
		goto error;
	}
#if CONFIG_MACF_NET
	mac_ifnet_label_init(&sc->sc_ifp);
#endif
    
	bpfattach(sc->sc_ifp, DLT_NULL, sizeof(u_int32_t));
    
    lck_rw_lock_exclusive(gre_domain_lck);
    TAILQ_INSERT_TAIL(&gre_softc_list, sc, sc_list);
    ++ngre;
    lck_rw_unlock_exclusive(gre_domain_lck);
    
	return 0;
    
error:
    if (sc->sc_ifp)
        ifnet_release(sc->sc_ifp);
	if (sc->mtx)
		lck_mtx_free(sc->mtx, gre_lck_grp);

	FREE(sc, M_TEMP);
    return result;
}


static errno_t gre_detach(ifnet_t ifp)
{
    dprintf("%s: remove gre%d, \tseq: %llu\n", __FUNCTION__, ifnet_unit(ifp), get_seq());
    
    struct gre_softc *sc = ifnet_softc(ifp);
    errno_t ret;
    
    if (ifnet_flags(ifp) & IFF_UP || ifnet_flags(ifp) & IFF_RUNNING)
        ifnet_set_flags(ifp, 0, IFF_UP | IFF_RUNNING);
    
    if (sc->gre_psrc != NULL) {
        FREE((caddr_t)sc->gre_psrc, M_IFADDR);
        sc->gre_psrc = NULL;
    }
    if (sc->gre_pdst != NULL) {
        FREE((caddr_t)sc->gre_pdst, M_IFADDR);
        sc->gre_pdst = NULL;
    }

    // detach protocols when detaching interface, just in case not done ... 
    if (sc->proto_flag & AF_INET6_PRESENT) {
        gre_detach_proto_family(ifp, AF_INET6);
    }
    if (sc->proto_flag & AF_INET_PRESENT) {
        gre_detach_proto_family(ifp, AF_INET);
    }
    
    sc->is_detaching = 1;
    ret = ifnet_detach(ifp);
	if (ret != 0) { // maybe it has already been detached
		sc->is_detaching = 0;
        dprintf("%s: gre%d: ifnet_detach() faild, err=0x%x.\n", __FUNCTION__, ifnet_unit(ifp), ret);
	} else {
        lck_mtx_lock(sc->mtx);
        if (sc->is_detaching) {
            /* interface release is in progress, wait for callback */
            msleep(ifp, sc->mtx, PDROP, NULL, NULL);  // sc->mtx will be unlocked by msleep
        } else {
            lck_mtx_unlock(sc->mtx);
        }
    }
    
    ret = ifnet_release(ifp);
    if (ret)
        dprintf("%s: ifnet_release() faild, errno:%d.\n", __FUNCTION__, ret);

    /*
     * here, in this version of GRE, the only caller calls gre_detach() is gre_dispose()
     * so, other caller is respose to obtain the lock gre_domain_lck first
     */
    
    --ngre;
    TAILQ_REMOVE(&gre_softc_list, sc, sc_list);

	lck_mtx_free(sc->mtx, gre_lck_grp);
	FREE(sc, M_TEMP);

    return 0;
}


/* attach inet/inet6 to a GRE interface through DLIL */
errno_t gre_attach_proto_family(ifnet_t ifp, protocol_family_t protocol_family)
{
    dprintf("%s: attach_proto_family: fam=0x%x, \tseq: %llu\n", __FUNCTION__, protocol_family, get_seq());
    struct ifnet_attach_proto_param	proto;
    errno_t err;
    
	bzero(&proto, sizeof(proto));
    proto.input = gre_input;
    proto.pre_output = gre_pre_output;
    
    err = ifnet_attach_protocol(ifp, protocol_family, &proto);
    if (err && err != EEXIST)
        printf("%s: ifnet_attach_protocol can't attach interface fam=%d\n", __FUNCTION__, protocol_family);
    
    return err;
}


void gre_detach_proto_family(ifnet_t ifp, protocol_family_t protocol)
{
    dprintf("%s: detach_proto_family: fam=0x%x, \tseq: %llu\n", __FUNCTION__, protocol, get_seq());
    errno_t err;
        
    struct gre_softc *sc = ifnet_softc(ifp);
    switch (protocol) {
        case AF_INET:
            if (! sc->proto_flag & AF_INET_PRESENT)
                return;
            if ((err = ifnet_detach_protocol(ifp, AF_INET)) == 0)
                return;
            break;
        case AF_INET6:
            if (! sc->proto_flag & AF_INET6_PRESENT)
                return;
            if ((err = ifnet_detach_protocol(ifp, AF_INET6)) == 0)
                return;
            break;
        default:
            dprintf("%s: unkown proto fam = 0x%x\n", __FUNCTION__, protocol); // should never happen
            return;
    }
    // error occur when detach protocol
    if (err && err != ENOENT)
        printf("%s: ifnet_detach_protocol() error = 0x%x\n", __FUNCTION__, err);
}

/*
 * is called by the stack when a protocol is attached to gre interface.
 */
static errno_t
gre_add_proto(ifnet_t ifp, protocol_family_t protocol, const struct ifnet_demux_desc *demux_array,
              u_int32_t demux_count)
{
    dprintf("%s: add proto 0x%x for gre%d, \tseq: %llu\n", __FUNCTION__, protocol, ifnet_unit(ifp), get_seq());
    
    struct gre_softc *sc = ifnet_softc(ifp);
    switch (protocol) {
        case AF_INET:
            if (sc->proto_flag & AF_INET_PRESENT)
                return EEXIST;
            sc->proto_flag |= AF_INET_PRESENT;
            break;
        case AF_INET6:
            if (sc->proto_flag & AF_INET6_PRESENT)
                return EEXIST;
            sc->proto_flag |= AF_INET6_PRESENT;
            break;
        default:
            return EINVAL;	// happen for unknown protocol, or for empty descriptor
    }
	return 0;
}


/*
 * is called by the stack when a protocol is being detached from gre interface.
 */
static errno_t
gre_del_proto(ifnet_t ifp, protocol_family_t protocol)
{
    dprintf("%s: del_proto for gre%d, \tseq: %llu\n", __FUNCTION__, ifnet_unit(ifp), get_seq());
	switch (protocol) {
        case AF_INET:
            ((struct gre_softc*)ifnet_softc(ifp))->proto_flag &= ~AF_INET_PRESENT;
            break;
        case AF_INET6:
            ((struct gre_softc*)ifnet_softc(ifp))->proto_flag &= ~AF_INET6_PRESENT;
            break;
        default:
            return EINVAL;	// happen for unknown protocol, or for empty descriptor
    }
	return 0;
}


/*
 * communicate ioctls from the stack to the driver.
 */
static errno_t
gre_ioctl(ifnet_t ifp, u_int32_t cmd, void *data)
{
	struct ifreq *ifr = (struct ifreq *)data;
	struct gre_softc *sc = ifnet_softc(ifp);
	struct sockaddr *sa = NULL;
    struct sockaddr *src = NULL, *dst = NULL;
    int size = 0;
    int adj = 0;
	errno_t error = 0;
	uint32_t key;
    
	switch (cmd) {
        case SIOCSIFADDR: /* set ifnet address */
        case SIOCAIFADDR: /* add/chg IF alias */
        case SIOCALIFADDR: /* add IF addr */
            break;
        case SIOCADDMULTI:
            if (ifr == NULL) {
                error = EAFNOSUPPORT;
                break;
            }
            switch (ifr->ifr_addr.sa_family) {
                case AF_INET:
                case AF_INET6:
                    break;
                default:
                    error = EAFNOSUPPORT;
                    break;
            }
            break;
        case SIOCGIFADDR: /* get ifnet address */
        case SIOCGLIFADDR: /* get IF addr */
            break;
        case SIOCDIFADDR: /* delete IF addr */
        case SIOCDLIFADDR: /* delete IF addr */
            break;
        case SIOCDELMULTI:
            if (ifr == NULL) {
                error = EAFNOSUPPORT;
                break;
            }
            switch (ifr->ifr_addr.sa_family) {
                case AF_INET:
                case AF_INET6:
                    break;
                default:
                    error = EAFNOSUPPORT;
                    break;
            }
            break;
        case SIOCSIFDSTADDR:  /* set p-p address */
            break;
        case SIOCGIFDSTADDR: /* get p-p address */
            break;
        case GRESPROTO:
        case SIOCSIFFLAGS:
            if ((ifr->ifr_flags & IFF_LINK0) != 0) {
                sc->encap_proto = IPPROTO_GRE;
                ifnet_set_flags(ifp, IFF_LINK0, IFF_LINK0);
            }
            else {
                sc->encap_proto = IPPROTO_MOBILE;
                ifnet_set_flags(ifp, 0, IFF_LINK0);
            }
                
            if ((ifr->ifr_flags & IFF_LINK2) != 0)
                sc->wccp_ver = WCCP_V2;
            else
                sc->wccp_ver = WCCP_V1;
            break;
        case GREGPROTO:
            ifr->ifr_flags = sc->encap_proto;
            break;
        case SIOCGIFFLAGS:
            break;
        case SIOCSIFNETMASK:
            break;
        case SIOCGIFNETMASK:
            break;
        case SIOCSIFMTU:
            if (ifr->ifr_mtu < GRE_MIN_MTU) {
                error = EINVAL;
                break;
            }
            ifnet_set_mtu(ifp, ifr->ifr_mtu);
            break;
        case SIOCGIFMTU:
            ifr->ifr_mtu = ifnet_mtu(ifp);
            break;
        case GRESADDRS: // tunnel src address
        case SIOCSIFPHYADDR:
        case SIOCSIFPHYADDR_IN6:
        case SIOCSLIFPHYADDR:
            switch (cmd) {
                case SIOCSIFPHYADDR:
                    src = (struct sockaddr *) &(((struct in_aliasreq *)data)->ifra_addr);
                    dst = (struct sockaddr *) &(((struct in_aliasreq *)data)->ifra_dstaddr);
                    if (src->sa_family != AF_INET || dst->sa_family != AF_INET)
                        return EAFNOSUPPORT;
                    if (src->sa_len != sizeof(struct sockaddr_in) || dst->sa_len != sizeof(struct sockaddr_in))
                        return EINVAL;
                    break;
                case SIOCSIFPHYADDR_IN6:
                    src = (struct sockaddr *) &(((struct in6_aliasreq *)data)->ifra_addr);
                    dst = (struct sockaddr *) &(((struct in6_aliasreq *)data)->ifra_dstaddr);
                    if (src->sa_family != AF_INET6 || dst->sa_family != AF_INET6)
                        return EAFNOSUPPORT;
                    if (src->sa_len != sizeof(struct sockaddr_in6) || dst->sa_len != sizeof(struct sockaddr_in6))
                        return EINVAL;
                    break;
                case SIOCSLIFPHYADDR:
                    src = (struct sockaddr *) &(((struct if_laddrreq *)data)->addr);
                    dst = (struct sockaddr *) &(((struct if_laddrreq *)data)->dstaddr);
                    if (src->sa_family != dst->sa_family)
                        return EINVAL;
                default:
                    return EAFNOSUPPORT;
            }
            if (sc->gre_psrc)
                FREE((caddr_t)sc->gre_psrc, M_IFADDR);
            MALLOC(sa, struct sockaddr *, src->sa_len, M_IFADDR, M_WAITOK | M_ZERO);
            bcopy((caddr_t)src, (caddr_t)sa, src->sa_len);
            sc->gre_psrc = sa;
            
            if (sc->gre_pdst)
                FREE((caddr_t)sc->gre_pdst, M_IFADDR);
            MALLOC(sa, struct sockaddr *, dst->sa_len, M_IFADDR, M_WAITOK | M_ZERO);
            bcopy((caddr_t)dst, (caddr_t)sa, dst->sa_len);
            sc->gre_pdst = sa;
            
            ifnet_set_flags(ifp, IFF_RUNNING, IFF_RUNNING);
            
            /* here we ensure there is always one GRE interface not used available */
            gre_attach();
            
            gre_ipfilter_attach(); // attach ip filter
            break;
        case SIOCDIFPHYADDR:
            if (sc->gre_psrc) {
                FREE((caddr_t)sc->gre_psrc, M_IFADDR);
                sc->gre_psrc = NULL;
            }
            if (sc->gre_pdst) {
                FREE((caddr_t)sc->gre_pdst, M_IFADDR);
                sc->gre_pdst = NULL;
            }

            ifnet_set_flags(ifp, 0, IFF_RUNNING);
            
            /* count the running GRE interfaces */
            adj = 0;
            lck_rw_lock_shared(gre_domain_lck);
            TAILQ_FOREACH(sc, &gre_softc_list, sc_list) {
                if (sc->sc_ifp && (ifnet_flags(sc->sc_ifp) & IFF_RUNNING) && sc->gre_psrc && sc->gre_pdst) {
                    adj++;
                    break;
                }
            }
            lck_rw_unlock_shared(gre_domain_lck);
            
            /* if none of the GRE interfaces is running(without gre src addr or gre_dst addr), then remove gre_ipfilter */
            if (adj == 0)
                gre_ipfilter_detach();
            break;
        case GREGADDRS:
        case SIOCGIFPSRCADDR:
        case SIOCGIFPSRCADDR_IN6:
            if (sc->gre_psrc == NULL) {
                return EADDRNOTAVAIL;
            }
            src = sc->gre_psrc;
            switch (cmd) {
                case SIOCGIFPSRCADDR:
                    dst = &ifr->ifr_addr;
                    size = sizeof(ifr->ifr_addr);
                    break;
                case SIOCGIFPSRCADDR_IN6:
                    dst = (struct sockaddr *) &(((struct in6_ifreq *)data)->ifr_addr);
                    size = sizeof(((struct in6_ifreq *)data)->ifr_addr);
                    break;
                default:
                    return EADDRNOTAVAIL;
            }
            if (src->sa_len > size)
                return EINVAL;
            bcopy((caddr_t)src, (caddr_t)dst, src->sa_len);
            break;
        case GREGADDRD:
        case SIOCGIFPDSTADDR:
        case SIOCGIFPDSTADDR_IN6:
            if (sc->gre_pdst == NULL) {
                return EADDRNOTAVAIL;
            }
            src = sc->gre_pdst;
            switch (cmd) {
                case SIOCGIFPDSTADDR:
                    dst = &ifr->ifr_addr;
                    size = sizeof(ifr->ifr_addr);
                    break;
                case SIOCGIFPDSTADDR_IN6:
                    dst = (struct sockaddr *) &(((struct in6_ifreq *)data)->ifr_addr);
                    size = sizeof(((struct in6_ifreq *)data)->ifr_addr);
                    break;
                default:
                    return EADDRNOTAVAIL;
            }
            if (src->sa_len > size)
                return EINVAL;
            bcopy((caddr_t)src, (caddr_t)dst, src->sa_len);
            break;
        case SIOCGLIFPHYADDR:
            if (sc->gre_psrc == NULL || sc->gre_pdst == NULL) {
                return EADDRNOTAVAIL;
            }
            
            /* copy src */
            src = sc->gre_psrc;
            dst = (struct sockaddr *) &(((struct if_laddrreq *)data)->addr);
            size = sizeof(((struct if_laddrreq *)data)->addr);
            if (src->sa_len > size)
                return EINVAL;
            bcopy((caddr_t)src, (caddr_t)dst, src->sa_len);
            
            /* copy dst */
            src = sc->gre_pdst;
            dst = (struct sockaddr *) &(((struct if_laddrreq *)data)->dstaddr);
            size = sizeof(((struct if_laddrreq *)data)->dstaddr);
            if (src->sa_len > size)
                return EINVAL;
            bcopy((caddr_t)src, (caddr_t)dst, src->sa_len);
            break;
        case GRESKEY:
            dprintf("\t GRESKEY\n");  // not supported on xnu1228 yet
            /*
             int	copyin(const user_addr_t uaddr, void *kaddr, size_t len);
             int	copyout(const void *kaddr, user_addr_t udaddr, size_t len);
             
             Copying data between user space and kernel space is done using copyin
             and copyout. A process may be running in 64bit mode. In such a case,
             the pointer will be a 64bit pointer, not a 32bit pointer. The following
             sample is a safe way to copy the data in to the kernel from either a
             32bit or 64bit process:
             
             user_addr_t tmp_ptr;
             if (IS_64BIT_PROCESS(current_proc())) {
             tmp_ptr = CAST_USER_ADDR_T(ifkpi.ifk_data.ifk_ptr64);
             }
             else {
             tmp_ptr = CAST_USER_ADDR_T(ifkpi.ifk_data.ifk_ptr);
             }
             error = copyin(tmp_ptr, allocated_dst_buffer, size of allocated_dst_buffer);
             */
            
            error = copyin(CAST_USER_ADDR_T(ifr->ifr_data), &key, sizeof(key));
            if (error)
                break;
            /* adjust MTU for option header */
            if (key == 0 && sc->key != 0)		/* clear */
                adj += sizeof(key);
            else if (key != 0 && sc->key == 0)	/* set */
                adj -= sizeof(key);
            
            if (ifnet_mtu(ifp) + adj < GRE_MIN_MTU) {
                error = EINVAL;
                break;
            }
            ifnet_set_mtu(ifp, ifnet_mtu(ifp) + adj);
            sc->key = key;
            break;
        case GREGKEY:
            error = copyout(&sc->key, CAST_USER_ADDR_T(ifr->ifr_data), sizeof(sc->key));
            break;
        case SIOCIFCREATE: // not supported on darwin
        case SIOCIFDESTROY:
            error = ENOTSUP;
            break;
        case SIOCGIFSTATUS:
            break;
        case SIOCSIFMEDIA:
        case SIOCGIFMEDIA:
        case SIOCSIFBOND:
        case SIOCGIFBOND:
        case SIOCSIFVLAN:
        case SIOCGIFVLAN:
            error = ENOTSUP;
            break;
        default:
            dprintf("\t Unkown ioctl flag:IN_OUT: 0x%x \t num: %d \n", cmd & (IOC_INOUT | IOC_VOID), cmd & 0xff);
            error = EINVAL;
            break;
	}
	return error;
}

/*
 * Why deprecated ???  Call bpf_tap_in/bpf_tap_out
 */
static errno_t
gre_set_bpf_tap(ifnet_t ifp, bpf_tap_mode mode, bpf_packet_func func)
{
    dprintf("%s: set_bpf_tap, \tseq: %llu\n", __FUNCTION__, get_seq());
	struct gre_softc *sc = ifnet_softc(ifp);
        
    switch (mode) {
        case BPF_MODE_DISABLED:
            sc->bpf_input = sc->bpf_output = NULL;
            break;
        case BPF_MODE_INPUT:
            sc->bpf_input = func;
            break;
        case BPF_MODE_OUTPUT:
			sc->bpf_output = func;
            break;
        case BPF_MODE_INPUT_OUTPUT:
            sc->bpf_input = sc->bpf_output = func;
            break;
        default:
            break;
    }
	return 0;
}

/*
 * gre_if_free() is called when ifp detaching is done,
 * then it is safe to call ifnet_release()
 */
static void gre_if_free(ifnet_t ifp)
{
    struct gre_softc* sc = ifnet_softc(ifp);
	lck_mtx_lock(sc->mtx);
    if (sc->is_detaching) {
        sc->is_detaching = 0;
        lck_mtx_unlock(sc->mtx);
        wakeup(ifp);
    } else {
        lck_mtx_unlock(sc->mtx);
    }
}

/*
 * return EJUSTRETURN if mbuf is freed in this function since our caller dlil_input_packet_list()
 * will free the mbuf if any error code returned
 */
static errno_t
gre_demux(ifnet_t ifp, mbuf_t m, char *frame_header, protocol_family_t *protocol)
{
    dprintf("%s: demux, \tseq: %llu\n", __FUNCTION__, get_seq());
	errno_t err = 0;
    // size check
    if (mbuf_len(m) < sizeof(struct ip)) { // since we accept ip packets, it should be at least sizeof(struct ip) long
		ddump_mbuf(m);
        mbuf_pullup(&m, sizeof(struct ip));
        if (m == NULL) {
            err = EJUSTRETURN;
            goto end;
        }
	}
    
    struct ip *iphdr = mbuf_data(m);
    
    switch (iphdr->ip_v) {
        case 4: // AF_INET
            if (((struct gre_softc *)ifnet_softc(ifp))->proto_flag & AF_INET_PRESENT)
                *protocol = AF_INET;
            else
                err = ENOENT;
            break;
        case 6: // AF_INET6
            if (((struct gre_softc *)ifnet_softc(ifp))->proto_flag & AF_INET6_PRESENT)
                *protocol = AF_INET6;
            else
                err = ENOENT;
            break;
        default:
            dprintf("%s: unsupported IP version %d\n", __FUNCTION__, iphdr->ip_v);
            err = ENOENT; //should never happen
    }
    
end:
    return err;
}

/*
 * gre_input is the input handler for IP and IPv6 attached to gre, 
 * our caller dlil_ifproto_input() will free the mbuf chain if any
 * error except EJUSTRETURN is returned
 */
static errno_t
gre_input(ifnet_t ifp, protocol_family_t protocol, mbuf_t m, __unused char *frame_header)
{
    dprintf("%s: inet_input, \tseq: %llu\n", __FUNCTION__, get_seq());
	errno_t err = 0;
    
    if (((struct gre_softc *)ifnet_softc(ifp))->bpf_input) {
        protocol_family_t bfp_header = ((struct gre_softc *)ifnet_softc(ifp))->gre_psrc->sa_family;
        bpf_tap_in(ifp, 0, m, &bfp_header, sizeof(bfp_header));
    }
	
    size_t len = mbuf_pkthdr_len(m);
	if ((err = proto_input(protocol, m)) != 0) {
        ifnet_stat_increment_in(ifp, 0, 0, 1);
        dprintf("%s: warnning: proto_input() error: 0x%x\n", __FUNCTION__, err); 
    } else
        ifnet_stat_increment_in(ifp, 1, len, 0);
    
	return err;
}

/*
 * is called just before the packet is transmitted. Specify the media specific frame type and destination here.
 */
static errno_t
gre_pre_output(ifnet_t ifp, protocol_family_t protocol, mbuf_t *m,
                  const struct sockaddr *dest, void *route, char *frame_type, char *link_layer_dest)
{
    dprintf("%s:\tseq: %llu\n", __FUNCTION__, get_seq());
	/* check wether the destination address is an inet address */
    struct gre_softc *sc = ifnet_softc(ifp);
 
    if (protocol != dest->sa_family)
        printf("%s: warnning: protocol:%d, dest->sa_family:%d\n", __FUNCTION__, protocol, dest->sa_family);
    
    switch (dest->sa_family) {
        case AF_INET:
            if (! sc->proto_flag & AF_INET_PRESENT)
                return EAFNOSUPPORT;
            *(protocol_family_t *)frame_type = htonl(AF_INET);
            break;
        case AF_INET6:
            if (! sc->proto_flag & AF_INET6_PRESENT)
                return EAFNOSUPPORT;
            *(protocol_family_t *)frame_type = htonl(AF_INET6);
            break;
        default:
            //*(protocol_family_t*)frame_type = protocol_family;
            return EAFNOSUPPORT;
    }
    
    if ((mbuf_flags(*m) & MBUF_PKTHDR) == 0) {
        printf("%s: Warning: It is NOT a mbuf pkt header !!!\n", __FUNCTION__);
        return EINVAL;
    }

	return 0;
}

/*
 * Prepend gre headers.
 */
static errno_t
gre_framer(ifnet_t ifp, mbuf_t *m, const struct sockaddr *dest, const char *dest_linkaddr, const char *frame_type)
{
    dprintf("%s:\tseq: %llu\n", __FUNCTION__, get_seq());
#ifdef DEBUG
    printf("frame_type: %d, dest->sa_family: %d, dest_address:", ntohl(*(protocol_family_t *)frame_type), dest->sa_family);
    switch (dest->sa_family) {
        case AF_INET: // 2
            print_ip_addr(((struct sockaddr_in *)dest)->sin_addr.s_addr);
            printf("\n");
            break;
        default:
            printf("unkown ip address, ipv6 ???\n");
            break;
    }
#endif
    return 0;
}

/*
 * The output routine. Takes a packet and encapsulates it in the protocol
 * given by sc->encap_proto. See also RFC 1701 and RFC 2004
 */
static errno_t gre_output(ifnet_t ifp, mbuf_t m) //, struct sockaddr *dst)
{
    dprintf("%s:\tseq: %llu\n", __FUNCTION__, get_seq());
	errno_t ret = 0;
    size_t pkthdr_len = mbuf_pkthdr_len(m);
	struct gre_softc *sc = ifnet_softc(ifp);
    
    if ( ifnet_flags(ifp) & (IFF_UP | IFF_RUNNING) != (IFF_UP | IFF_RUNNING) || \
        sc->gre_psrc == NULL || \
        sc->gre_pdst == NULL)
    {
        mbuf_freem(m);
        ifnet_touch_lastchange(ifp);
        ret = ENETDOWN;
        goto end;
	}
    
	/*
	 * gre may cause infinite recursion calls when misconfigured.
	 * We'll prevent this by introducing upper limit.
	 */
	if (++(sc->called) > max_gre_nesting) {
		printf("%s%d: recursively called too many times(%d)\n", ifnet_name(ifp), ifnet_unit(ifp), sc->called);
		mbuf_freem(m);
		ret = EIO;    /* is there better errno? */
		goto end;
	}
    /*
    dprintf("---->Ori ip header:\n");
    ddump_ip(mbuf_data(m));
     */
    
    if (((struct gre_softc *)ifnet_softc(ifp))->bpf_output) {
        /* Need to prepend the address family as a four byte field. */
        protocol_family_t bfp_header = sc->gre_psrc->sa_family;
        bpf_tap_out(ifp, 0, m, &bfp_header, sizeof(bfp_header));
    }
    
    mbuf_setflags(m, mbuf_flags(m) & ~(MBUF_BCAST | MBUF_MCAST));
    
    switch (sc->gre_psrc->sa_family) {
        case AF_INET:
            ret = in_gre_output(ifp, AF_INET, m, NULL);
            break;
/*        case AF_INET6:
             ret = in6_gre_output(ifp, AF_INET6, m, NULL); // todo later...
             break;
*/        default:
            ret = ENETDOWN;
            goto end;
	}
    
end:
	if (ret)
		ifnet_stat_increment_out(ifp, 0, 0, 1);
	else
        ifnet_stat_increment_out(ifp, 1, pkthdr_len, 0);

	return ret;
}    

static errno_t in_gre_output(ifnet_t ifp, protocol_family_t proto, mbuf_t m, route_t rt)
{
    dprintf("%s:\tseq: %llu\n", __FUNCTION__, get_seq());
	errno_t ret = 0;
	struct gre_softc *sc = ifnet_softc(ifp);
	struct greip *gh = NULL;
	struct ip *ip = NULL;
	u_short gre_ip_id = 0;
	uint8_t gre_ip_tos = 0;
	u_int16_t etype = 0;
	struct mobile_h mob_h;
	int extra = 0;
    
	if (sc->encap_proto == IPPROTO_MOBILE) {
		if (proto == AF_INET) 
        {
			mbuf_t m0;
			size_t msiz;
            
            ip = mbuf_data(m);
            
			/*
			 * RFC2004 specifies that fragmented diagrams shouldn't
			 * be encapsulated.
			 */
			if (ip->ip_off & (IP_MF | IP_OFFMASK)) {
                dprintf("%s: drop fragmented diagram..\n", __FUNCTION__);
				mbuf_freem(m);
				ret = EINVAL;    /* is there better errno? */
				goto end;
			}
            bzero(&mob_h, MOB_H_SIZ_L);
			mob_h.proto = (ip->ip_p) << 8;
			mob_h.odst = ip->ip_dst.s_addr;
			ip->ip_dst.s_addr = ((struct sockaddr_in *)sc->gre_pdst)->sin_addr.s_addr; //sc->g_dst.s_addr;
            
			/*
			 * If the packet comes from our host, we only change
			 * the destination address in the IP header.
			 * Else we also need to save and change the source
			 */
            if (in_hosteq(ip->ip_src, ((struct sockaddr_in *)sc->gre_psrc)->sin_addr))
            {
				msiz = MOB_H_SIZ_S;
			} else {
				mob_h.proto |= MOB_H_SBIT;
				mob_h.osrc = ip->ip_src.s_addr;
                ip->ip_src.s_addr = ((struct sockaddr_in *)sc->gre_psrc)->sin_addr.s_addr;
				msiz = MOB_H_SIZ_L;
			}
			mob_h.proto = htons(mob_h.proto);
			mob_h.hcrc = gre_in_cksum((u_int16_t *)&mob_h, msiz);
            
            if (mbuf_leadingspace(m) < msiz)
            {
				/* need new mbuf */
                mbuf_gethdr(MBUF_DONTWAIT, MBUF_TYPE_DATA, &m0);
				if (m0 == NULL) {
					mbuf_freem(m);
					ret = ENOBUFS;
					goto end;
				}
                mbuf_setnext(m0, m);
                mbuf_setdata(m, mbuf_data(m) + sizeof(struct ip), mbuf_len(m) - sizeof(struct ip));
                mbuf_pkthdr_adjustlen(m0, msiz);
                mbuf_setdata(m0, mbuf_data(m0) + max_linkhdr, msiz + sizeof(struct ip));
                bcopy((caddr_t)ip, mbuf_data(m0), sizeof(struct ip));
				m = m0;
			} else {  /* we have some space left in the old one */
                mbuf_setdata(m, mbuf_data(m), mbuf_len(m) + msiz);
                mbuf_pkthdr_adjustlen(m, msiz);
                bcopy(ip, mbuf_data(m), sizeof(struct ip));
			}
            ip = mbuf_data(m);
            bcopy(&mob_h, (caddr_t)(ip + 1), msiz);
			ip->ip_len = ntohs(ip->ip_len) + msiz;
		} else {  /* AF_INET */
			mbuf_freem(m);
			ret = EINVAL;
			goto end;
		}
	} else if (sc->encap_proto == IPPROTO_GRE) {
        switch (proto)
        {
            case AF_INET:
                ip = mbuf_data(m);
                gre_ip_tos = ip->ip_tos;
                gre_ip_id = ip->ip_id;
                if (sc->wccp_ver == WCCP_V2) {
                    extra = sizeof(uint32_t);
                    etype =  WCCP_PROTOCOL_TYPE;
                } else {
                    etype = ETHERTYPE_IP;
                }
                break;
/*
            case AF_INET6: // todo later
                 gre_ip_id = ip_newid();
                 etype = ETHERTYPE_IPV6;
                 break;
            case AF_APPLETALK:
                 etype = ETHERTYPE_ATALK;
                 break;
*/
            default:
                mbuf_freem(m);
                ret = EAFNOSUPPORT;
                goto end;
		}
        
		/* Reserve space for GRE header + optional GRE key */
		int hdrlen = sizeof(struct greip) + extra;
		if (sc->key)
			hdrlen += sizeof(uint32_t);
        ret = mbuf_prepend(&m, hdrlen, MBUF_DONTWAIT);
        if (ret) {
			printf("%s: could not prepend data to mbuf: 0x%x\n", __FUNCTION__, ret);
			return ret;
		}
	} else {
		mbuf_freem(m);
		ret = EINVAL;
		goto end;
	}
    
	if (m == NULL) {	/* mbuf allocation failed */
		ret = ENOBUFS;
		goto end;
	}
    
    gh = mbuf_data(m);
	if (sc->encap_proto == IPPROTO_GRE) {
		uint32_t *options = gh->gi_options;
        
        bzero(gh, sizeof(struct greip) + extra);
		gh->gi_ptype = htons(etype);
		gh->gi_flags = 0;
        
		/* Add key option */
		if (sc->key)
		{
			gh->gi_flags |= htons(GRE_KP);
			*(options++) = htonl(sc->key);
		}
	}
    
	gh->gi_pr = sc->encap_proto;
	if (sc->encap_proto != IPPROTO_MOBILE) {
		gh->gi_src = ((struct sockaddr_in *)sc->gre_psrc)->sin_addr;
		gh->gi_dst = ((struct sockaddr_in *)sc->gre_pdst)->sin_addr;
		((struct ip*)gh)->ip_v = IPPROTO_IPV4;
		((struct ip*)gh)->ip_hl = (sizeof(struct ip)) >> 2;
		((struct ip*)gh)->ip_ttl = GRE_TTL;
		((struct ip*)gh)->ip_tos = gre_ip_tos;
		((struct ip*)gh)->ip_id = gre_ip_id;
        gh->gi_sum = gre_in_cksum((u_int16_t *)gh, sizeof(struct ip));
        /* Put ip_len and ip_off in network byte order, ipf_inject_output expects that */
        gh->gi_len = htons(mbuf_pkthdr_len(m));
		((struct ip*)gh)->ip_off = htons(((struct ip*)gh)->ip_off);
	}
    
    mbuf_set_csum_performed(m, MBUF_CSUM_DID_IP | MBUF_CSUM_IP_GOOD, 0xffff);
    /*
#ifdef DEBUG
    printf("---->ip header after add GRE ip header:\n");
    dump_ip(mbuf_data(m));
    if (chk_mbuf(m) != 0) {
        mbuf_freem(m);
        ret = EINVAL;
        goto end;
    }
#endif
     */
    
    ret = ipf_inject_output(m, NULL, NULL);
    
	if (ret)
		dprintf("%s: ipf_inject_output() error: 0x%x\n", __FUNCTION__, ret);

end:
	sc->called = 0;
	return ret;
}

/*
 * computes a route to our destination that is not the one
 * which would be taken by ip_output(), as this one will loop back to
 * us. If the interface is p2p as  a--->b, then a routing entry exists
 * If we now send a packet to b (e.g. ping b), this will come down here
 * gets src=a, dst=b tacked on and would from ip_output() sent back to
 * if_gre.
 * Goal here is to compute a route to b that is less specific than
 * a-->b. We know that this one exists as in normal operation we have
 * at least a default route which matches.
 */
/*
static errno_t gre_compute_route(struct gre_softc *sc)
{
    errno_t err = 0;
    ifnet_t rt = NULL;
    
    if (sc->gre_psrc == NULL) {
        dprintf("%s: ifaddr_withaddr() error\n", __FUNCTION__);
        return -2;
    }
        
	ifaddr_t add = ifaddr_withaddr(sc->gre_psrc);
    if (add == NULL) {
        return -1;
    }
    
    rt = ifaddr_ifnet(add);
    if ((err = ifaddr_release(add))) {
        dprintf("%s: ifaddr_release error: 0x%x\n", __FUNCTION__, err);
        return err;
    }
    
    if (rt == NULL) {
        dprintf("%s: no route found!\n", __FUNCTION__);
        err = -1;
    } else if (rt == sc->sc_ifp) {
        dprintf("%s: route loops back to ourself gre%d !\n", __FUNCTION__, ifnet_unit(sc->sc_ifp));
        err = -1;
    } else {
//        sc->sc_ifp_out = rt; // find one
        sc->called = 0;
        dprintf("%s: find out interface: %s%d\n", __FUNCTION__, ifnet_name(rt), ifnet_unit(rt));
    }

    return err;
}*/
    /*


    


	((struct sockaddr_in *)&ro->ro_dst)->sin_addr = ((struct sockaddr_in *)sc->gre_pdst)->sin_addr;
	ro->ro_dst.sa_family = AF_INET;
	ro->ro_dst.sa_len = sizeof(ro->ro_dst);
    
	/*
	 * toggle last bit, so our interface is not found, but a less
	 * specific route. I'd rather like to specify a shorter mask,
	 * but this is not possible. Should work though. XXX
	 */
/*
	if ((GRE2IFP(sc)->if_flags & IFF_LINK1) == 0) {
		((struct sockaddr_in *)&ro->ro_dst)->sin_addr.s_addr ^=
        htonl(0x01);
	}
    
#ifdef DIAGNOSTIC
	printf("%s: searching for a route to %s", if_name(GRE2IFP(sc)),
           inet_ntoa(((struct sockaddr_in *)&ro->ro_dst)->sin_addr));
#endif
    
	rtalloc_fib(ro, sc->gre_fibnum);
    
	/*
	 * check if this returned a route at all and this route is no
	 * recursion to ourself
	 */
/*	if (ro->ro_rt == NULL || ro->ro_rt->rt_ifp->if_softc == sc) {
#ifdef DIAGNOSTIC
		if (ro->ro_rt == NULL)
			printf(" - no route found!\n");
		else
			printf(" - route loops back to ourself!\n");
#endif
		return EADDRNOTAVAIL;
	}
    
	/*
	 * now change it back - else ip_output will just drop
	 * the route and search one to this interface ...
	 */
/*	if ((GRE2IFP(sc)->if_flags & IFF_LINK1) == 0)
		((struct sockaddr_in *)&ro->ro_dst)->sin_addr = ((struct sockaddr_in *)sc->gre_pdst)->sin_addr;
    
#ifdef DIAGNOSTIC
	printf(", choosing %s with gateway %s", if_name(ro->ro_rt->rt_ifp),
           inet_ntoa(((struct sockaddr_in *)(ro->ro_rt->rt_gateway))->sin_addr));
	printf("\n");
#endif
    
	return 0;
}
*/

/*
 * do a checksum of a buffer - much like in_cksum, which operates on
 * mbufs.
 */
u_int16_t
gre_in_cksum(u_int16_t *p, u_int len)
{
	u_int32_t sum = 0;
	int nwords = len >> 1;
    
	while (nwords-- != 0)
		sum += *p++;
    
	if (len & 1) {
		union {
			u_short w;
			u_char c[2];
		} u;
		u.c[0] = *(u_char *)p;
		u.c[1] = 0;
		sum += u.w;
	}
    
	/* end-around-carry */
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return (~sum);
}

