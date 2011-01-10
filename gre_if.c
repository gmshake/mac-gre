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
#include <netat/appletalk.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/kpi_ipfilter.h>

#if CONFIG_MACF_NET
#include <security/mac_framework.h>
#endif

#include "gre_if.h"
#include "gre_ipfilter.h"
#include "gre_pcb.h"
#include "gre_debug.h"


/*
 * It is not easy to calculate the right value for a GRE MTU.
 * We leave this task to the admin and use the same default that
 * other vendors use.
 */
#define GREMTU	1476
#define GRE_MIN_MTU 576

#define GRENAME	"gre"


static const int max_linkhdr = ETHER_HDR_LEN + 2; /* link layer header, ETHER_HDR_LEN + overhead, default is 16 in xnu1228 */

TAILQ_HEAD(gre_softc_head, gre_softc) gre_softc_list;
unsigned int ngre = 0;       /* number of interfaces */

extern ipfilter_t gre_ipfilter;
extern lck_grp_t *gre_lck_grp;
lck_rw_t *gre_domain_lck = NULL; // protect gre_softc_list and ngre

int gre_init();
int gre_dispose();
int gre_attach();
static errno_t gre_detach(ifnet_t ifp);

errno_t     gre_attach_proto_family(ifnet_t ifp, protocol_family_t protocol);
void        gre_detach_proto_family(ifnet_t ifp, protocol_family_t protocol);

static errno_t  gre_add_proto(ifnet_t ifp, protocol_family_t protocol, const struct ifnet_demux_desc *demux_array, u_int32_t demux_count);
static errno_t  gre_del_proto(ifnet_t ifp, protocol_family_t protocol);

static errno_t  gre_ioctl(ifnet_t ifp, u_int32_t cmd, void *data);
static errno_t  gre_set_bpf_tap(ifnet_t ifp, bpf_tap_mode mode, bpf_packet_func func);
static void     gre_if_free(ifnet_t ifp);

static int      gre_demux(ifnet_t ifp, mbuf_t m, char *frame_header, protocol_family_t *protocol);
static errno_t  gre_input(ifnet_t ifp, protocol_family_t protocol, mbuf_t m, char *frame_header);

static errno_t  gre_pre_output(ifnet_t ifp, protocol_family_t protocol, mbuf_t *packet,
                                 const struct sockaddr *dest, void *route, char *frame_type, char *link_layer_dest);
static errno_t  gre_framer(ifnet_t ifp, mbuf_t *m, const struct sockaddr *dest, const char *dest_linkaddr, const char *frame_type);
static errno_t  gre_output(ifnet_t ifp, mbuf_t m);

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
#ifdef DEBUG
    if (gre_domain_lck != NULL) {
        printf("%s: warnning: has inited...\n", __FUNCTION__);
        return 0;
    }
#endif

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
            //sc->sc_ifp = NULL;
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
    errno_t err = 0;
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
    
    if (ngre >= GRE_MAXUNIT) {
        lck_rw_unlock_shared(gre_domain_lck);
        return EMFILE; // any better Error code?
    }
    lck_rw_unlock_shared(gre_domain_lck);

    sc = (struct gre_softc *) _MALLOC(sizeof(struct gre_softc), M_TEMP, M_WAITOK | M_ZERO);
    if (sc == NULL)
		return ENOMEM;

    sc->mtx = lck_mtx_alloc_init(gre_lck_grp, NULL);
	if (sc->mtx == NULL) {
        err = ENOMEM;
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
    
	err = ifnet_allocate(&init, &sc->sc_ifp);
	if (err) {
		printf("%s: ifnet_allocate() failed - %d\n", __FUNCTION__, err);
		goto error;
	}
    
    sc->called = 0;
    sc->encap_proto = IPPROTO_GRE;
    ifnet_set_addrlen(sc->sc_ifp, 0);
    ifnet_set_mtu(sc->sc_ifp, GREMTU);
    ifnet_set_hdrlen(sc->sc_ifp, sizeof(struct greip)); // IP + GRE
	ifnet_set_flags(sc->sc_ifp, IFF_POINTOPOINT | IFF_MULTICAST | IFF_LINK0, 0xffff);
    sc->wccp_ver = WCCP_V1;
    sc->key = 0;
    
	ifnet_touch_lastchange(sc->sc_ifp);
    
    err = ifnet_attach(sc->sc_ifp, NULL);
	if (err) {
		printf("%s: ifnet_attach() failed - %d\n", __FUNCTION__, err);
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

	_FREE(sc, M_TEMP);
    return err;
}


static errno_t gre_detach(ifnet_t ifp)
{
#ifdef DEBUG
    printf("%s: detach %s%d\n", __FUNCTION__, ifnet_name(ifp), ifnet_unit(ifp));
#endif
    struct gre_softc *sc = ifnet_softc(ifp);
    errno_t ret;
    
    gre_hash_delete(sc);
    
    if (ifnet_flags(ifp) & IFF_UP || ifnet_flags(ifp) & IFF_RUNNING)
        ifnet_set_flags(ifp, 0, IFF_UP | IFF_RUNNING);
    
    lck_rw_unlock_exclusive(gre_domain_lck);
    // detach protocols when detaching interface, just in case not done ... 
    if (sc->proto_flag & AF_APPLETALK_PRESENT)
        gre_detach_proto_family(ifp, AF_APPLETALK);
    if (sc->proto_flag & AF_INET6_PRESENT)
        gre_detach_proto_family(ifp, AF_INET6);
    if (sc->proto_flag & AF_INET_PRESENT)
        gre_detach_proto_family(ifp, AF_INET);
    
    lck_mtx_lock(sc->mtx);
    sc->is_detaching = 1;
    lck_mtx_unlock(sc->mtx);
    ret = ifnet_detach(ifp);
	if (ret != 0) { // maybe it has already been detached
        lck_mtx_lock(sc->mtx);
		sc->is_detaching = 0;
        lck_mtx_unlock(sc->mtx);
	} else {
        lck_mtx_lock(sc->mtx);
        if (sc->is_detaching) {
            /* interface release is in progress, wait for callback */
#ifdef DEBUG
            printf("%s: detaching is in progress...\n", __FUNCTION__);
#endif
            msleep(ifp, sc->mtx, PDROP, NULL, NULL);  // sc->mtx will be unlocked by msleep
        } else {
            lck_mtx_unlock(sc->mtx);
        }
    }
    
    ret = ifnet_release(ifp);
    if (ret)
        printf("%s: ifnet_release() faild: %d\n", __FUNCTION__, ret);
    
    lck_mtx_free(sc->mtx, gre_lck_grp);
    
    /*
     * here, in this version of GRE, the only caller calls gre_detach() is gre_dispose()
     * so, other caller is respose to obtain the lock gre_domain_lck first
     */
    lck_rw_lock_exclusive(gre_domain_lck);
    --ngre;
    
    TAILQ_REMOVE(&gre_softc_list, sc, sc_list);
	_FREE(sc, M_TEMP);
    
#ifdef DEBUG
    printf("%s: done\n", __FUNCTION__);
#endif
    return 0;
}


/* attach inet/inet6 to a GRE interface through DLIL */
errno_t gre_attach_proto_family(ifnet_t ifp, protocol_family_t protocol_family)
{
    dprintf("%s: fam=0x%x\n", __FUNCTION__, protocol_family);
    struct ifnet_attach_proto_param	proto;
    errno_t err;
    
	bzero(&proto, sizeof(proto));
    proto.input = gre_input;
    proto.pre_output = gre_pre_output;
    
    err = ifnet_attach_protocol(ifp, protocol_family, &proto);
    if (err && err != EEXIST)
        printf("%s: ifnet_attach_protocol can't attach interface %s%d fam=0x%x\n", \
               __FUNCTION__, ifnet_name(ifp), ifnet_unit(ifp),  protocol_family);
    
    return err;
}


void gre_detach_proto_family(ifnet_t ifp, protocol_family_t protocol)
{
    dprintf("%s: fam=0x%x\n", __FUNCTION__, protocol);
    errno_t err;
        
    struct gre_softc *sc = ifnet_softc(ifp);
    switch (protocol) {
        case AF_INET:
            if (! sc->proto_flag & AF_INET_PRESENT)
                return;
            break;
        case AF_INET6:
            if (! sc->proto_flag & AF_INET6_PRESENT)
                return;
            break;
        case AF_APPLETALK:
            if (! sc->proto_flag & AF_APPLETALK_PRESENT)
                return;
            break;
        default:
            dprintf("%s: unkown proto family 0x%x\n", __FUNCTION__, protocol); // should never happen
            return;
    }
    
    err = ifnet_detach_protocol(ifp, protocol);
    // error occur when detach protocol
    if (err && err != ENOENT)
        printf("%s: ifnet_detach_protocol() %s%d error = 0x%x\n", \
               __FUNCTION__, ifnet_name(ifp), ifnet_unit(ifp), err);
}

/*
 * is called by the stack when a protocol is attached to gre interface.
 */
static errno_t
gre_add_proto(ifnet_t ifp, protocol_family_t protocol, const struct ifnet_demux_desc *demux_array,
              u_int32_t demux_count)
{
    dprintf("%s: add proto 0x%x for %s%d\n", __FUNCTION__, protocol, ifnet_name(ifp), ifnet_unit(ifp));
    
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
        case AF_APPLETALK:
            if (sc->proto_flag & AF_APPLETALK_PRESENT)
                return EEXIST;
            sc->proto_flag |= AF_APPLETALK_PRESENT;
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
    dprintf("%s: del proto for %s%d\n", __FUNCTION__, ifnet_name(ifp), ifnet_unit(ifp));
	switch (protocol) {
        case AF_INET:
            ((struct gre_softc*)ifnet_softc(ifp))->proto_flag &= ~AF_INET_PRESENT;
            break;
        case AF_INET6:
            ((struct gre_softc*)ifnet_softc(ifp))->proto_flag &= ~AF_INET6_PRESENT;
            break;
        case AF_APPLETALK:
            ((struct gre_softc*)ifnet_softc(ifp))->proto_flag &= ~AF_APPLETALK_PRESENT;
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
        {
            u_int8_t newproto = ifr->ifr_flags;
            switch (newproto) {
                case IPPROTO_GRE:
                    ifnet_set_flags(ifp, IFF_LINK0, IFF_LINK0);
                    break;
                case IPPROTO_MOBILE:
                    ifnet_set_flags(ifp, 0, IFF_LINK0);
                    break;
                default:
                    error = EPROTONOSUPPORT;
                    break;
            }
            /* hack, if proto changed, then change hash value */
            if (newproto == sc->encap_proto)
                break;
            if (gre_hash_delete(sc) == 0) {
                sc->encap_proto = newproto;
                gre_hash_add(sc);
            } else {
                sc->encap_proto = newproto;
            }
            break;
        }
        case SIOCSIFFLAGS:
        {
            u_int8_t newproto;
            if ((ifr->ifr_flags & IFF_LINK0)) {
                newproto = IPPROTO_GRE;
                ifnet_set_flags(ifp, IFF_LINK0, IFF_LINK0);
            } else {
                newproto = IPPROTO_MOBILE;
                ifnet_set_flags(ifp, 0, IFF_LINK0);
            }
            
            if ((ifr->ifr_flags & IFF_LINK2))
                sc->wccp_ver = WCCP_V2;
            else
                sc->wccp_ver = WCCP_V1;
            
            /* hack, if proto changed, then change hash value */
            if (newproto == sc->encap_proto)
                break;
            if (gre_hash_delete(sc) == 0) {
                sc->encap_proto = newproto;
                gre_hash_add(sc);
            } else {
                sc->encap_proto = newproto;
            }
            break;
        }
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
#ifdef DEPLOY
            if (ifr->ifr_mtu < IPV6_MMTU) {
                error = EINVAL;
                break;
            }
#else
            if (ifr->ifr_mtu < GRE_MIN_MTU) {
                error = EINVAL;
                break;
            }
#endif
            else if (ifr->ifr_mtu > IF_MAXMTU) {
                error = EINVAL;
                break;
            }
            
            ifnet_set_mtu(ifp, ifr->ifr_mtu);
            break;
        case SIOCGIFMTU:
            ifr->ifr_mtu = ifnet_mtu(ifp);
            break;
        case GRESADDRS: // set tunnel src address
            bcopy((caddr_t)&ifr->ifr_addr, (caddr_t)&sc->gre_psrc, ifr->ifr_addr.sa_len);
            break;
        case GRESADDRD: // set tunnel dst address
            bcopy((caddr_t)&ifr->ifr_addr, (caddr_t)&sc->gre_pdst, ifr->ifr_addr.sa_len);
            break;
        case SIOCSIFPHYADDR:
        case SIOCSIFPHYADDR_IN6:
        case SIOCSLIFPHYADDR:
            switch (cmd) {
                case SIOCSIFPHYADDR:
                    src = (struct sockaddr *) \
                            &(((struct in_aliasreq *)data)->ifra_addr);
                    dst = (struct sockaddr *) \
                            &(((struct in_aliasreq *)data)->ifra_dstaddr);
                    if (src->sa_family != AF_INET || dst->sa_family != AF_INET)
                        return EINVAL;
                    if (src->sa_len != sizeof(struct sockaddr_in) || dst->sa_len != sizeof(struct sockaddr_in))
                        return EINVAL;
                    break;
#ifdef DEPLOY
                case SIOCSIFPHYADDR_IN6:
                    src = (struct sockaddr *) \
                            &(((struct in6_aliasreq *)data)->ifra_addr);
                    dst = (struct sockaddr *) \
                            &(((struct in6_aliasreq *)data)->ifra_dstaddr);
                    if (src->sa_family != AF_INET6 || dst->sa_family != AF_INET6)
                        return EINVAL;
                    if (src->sa_len != sizeof(struct sockaddr_in6) || dst->sa_len != sizeof(struct sockaddr_in6))
                        return EINVAL;
                    break;
#endif
                case SIOCSLIFPHYADDR:
                    src = (struct sockaddr *) \
                            &(((struct if_laddrreq *)data)->addr);
                    dst = (struct sockaddr *) \
                            &(((struct if_laddrreq *)data)->dstaddr);
                    if (src->sa_family != dst->sa_family || src->sa_len != dst->sa_len)
                        return EINVAL;
#ifndef DEPLOY
                    if (src->sa_family == AF_INET6)
                        return EINVAL;
#endif
                default:
                    return EAFNOSUPPORT;
            }
            
            lck_rw_lock_shared(gre_domain_lck);
            TAILQ_FOREACH(sc, &gre_softc_list, sc_list) {
                if (sc == ifnet_softc(ifp))
                    continue;
                if (sc->gre_pdst.sa_family == AF_UNSPEC || \
                    sc->gre_psrc.sa_family == AF_UNSPEC)
                    continue;
                if (sc->gre_pdst.sa_family != dst->sa_family || \
                    sc->gre_pdst.sa_len != dst->sa_len || \
                    sc->gre_psrc.sa_family != src->sa_family || \
                    sc->gre_psrc.sa_len != src->sa_len )
                    continue;
                
                /* can't configure same pair of address onto two GREs */
                if (bcmp(&sc->gre_pdst, dst, dst->sa_len) == 0 &&
                    bcmp(&sc->gre_psrc, src, src->sa_len) == 0) {
                    lck_rw_unlock_shared(gre_domain_lck);
                    return EADDRNOTAVAIL;
                }
                
                /* can't configure multiple multi-dest interfaces */
#define multidest(x) \
(((struct sockaddr_in *)(x))->sin_addr.s_addr == INADDR_ANY)

#ifdef DEPLOY
#define multidest6(x) \
(IN6_IS_ADDR_UNSPECIFIED(&((struct sockaddr_in6 *)(x))->sin6_addr))
#endif

                if (dst->sa_family == AF_INET &&
                    multidest(dst) && multidest(&sc->gre_pdst)) {
                    lck_rw_unlock_shared(gre_domain_lck);
                    return EADDRNOTAVAIL;
                }
#ifdef DEPLOY
                if (dst->sa_family == AF_INET6 &&
                    multidest6(dst) && multidest6(&sc->gre_pdst)) {
                    lck_rw_unlock_shared(gre_domain_lck);
                    return EADDRNOTAVAIL;
                }
#endif
            }
            lck_rw_unlock_shared(gre_domain_lck);
            
            sc = ifnet_softc(ifp);
            gre_hash_delete(sc);
            
            bcopy((caddr_t)src, (caddr_t)&sc->gre_psrc, src->sa_len);
            bcopy((caddr_t)dst, (caddr_t)&sc->gre_pdst, dst->sa_len);
            
            ifnet_set_flags(ifp, IFF_RUNNING, IFF_RUNNING);
            
            gre_hash_add(sc);
            
            /* here we ensure there is always one GRE interface not used available */
            gre_attach();
            break;
        case SIOCDIFPHYADDR:
            ifnet_set_flags(ifp, 0, IFF_RUNNING);
            
            sc->gre_pdst.sa_family = AF_UNSPEC;
            sc->gre_psrc.sa_family = AF_UNSPEC;
            
            gre_hash_delete(sc);
            break;
        case GREGADDRS: // get gre tunnel src address
            bcopy((caddr_t)&sc->gre_psrc, (caddr_t)&ifr->ifr_addr, sc->gre_psrc.sa_len);
            break;
        case SIOCGIFPSRCADDR:
        case SIOCGIFPSRCADDR_IN6:
            if (sc->gre_psrc.sa_family == AF_UNSPEC) {
                return EADDRNOTAVAIL;
            }
            src = &sc->gre_psrc;
            switch (cmd) {
                case SIOCGIFPSRCADDR:
                    dst = &ifr->ifr_addr;
                    size = sizeof(ifr->ifr_addr);
                    break;
                case SIOCGIFPSRCADDR_IN6:
                    dst = (struct sockaddr *) \
                            &(((struct in6_ifreq *)data)->ifr_addr);
                    size = sizeof(((struct in6_ifreq *)data)->ifr_addr);
                    break;
                default:
                    return EADDRNOTAVAIL;
            }
            if (src->sa_len > size)
                return EINVAL;
            bcopy((caddr_t)src, (caddr_t)dst, src->sa_len);
            break;
        case GREGADDRD: // get gre tunnel dst address
            bcopy((caddr_t)&sc->gre_pdst, (caddr_t)&ifr->ifr_addr, sc->gre_pdst.sa_len);
            break;
        case SIOCGIFPDSTADDR:
        case SIOCGIFPDSTADDR_IN6:
            if (sc->gre_pdst.sa_family == AF_UNSPEC) {
                return EADDRNOTAVAIL;
            }
            src = &sc->gre_pdst;
            switch (cmd) {
                case SIOCGIFPDSTADDR:
                    dst = &ifr->ifr_addr;
                    size = sizeof(ifr->ifr_addr);
                    break;
                case SIOCGIFPDSTADDR_IN6:
                    dst = (struct sockaddr *) \
                            &(((struct in6_ifreq *)data)->ifr_addr);
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
            if (sc->gre_psrc.sa_family == AF_UNSPEC || \
                sc->gre_pdst.sa_family == AF_UNSPEC) {
                return EADDRNOTAVAIL;
            }
            
            /* copy src */
            src = &sc->gre_psrc;
            dst = (struct sockaddr *) &(((struct if_laddrreq *)data)->addr);
            size = sizeof(((struct if_laddrreq *)data)->addr);
            if (src->sa_len > size)
                return EINVAL;
            bcopy((caddr_t)src, (caddr_t)dst, src->sa_len);
            
            /* copy dst */
            src = &sc->gre_pdst;
            dst = (struct sockaddr *) &(((struct if_laddrreq *)data)->dstaddr);
            size = sizeof(((struct if_laddrreq *)data)->dstaddr);
            if (src->sa_len > size)
                return EINVAL;
            bcopy((caddr_t)src, (caddr_t)dst, src->sa_len);
            break;
        case GRESKEY:
            dprintf("\t GRESKEY\n");  // not supported on xnu1228 yet
            
            error = copyin(CAST_USER_ADDR_T(ifr->ifr_data), &key, sizeof(key));
            if (error)
                break;
            if (sc->key == key)
                break;
            
            /* adjust MTU for option header */
            if (key == 0 && sc->key != 0)		/* clear */
                adj += sizeof(key);
            else if (key != 0 && sc->key == 0)	/* set */
                adj -= sizeof(key);
            
#ifdef DEPLOY
            if (ifnet_mtu(ifp) + adj < IPV6_MMTU) {
                ifnet_set_mtu(ifp, IPV6_MMTU);
                break;
            }
#else
            if (ifnet_mtu(ifp) + adj < GRE_MIN_MTU) {
                ifnet_set_mtu(ifp, GRE_MIN_MTU);
                break;
            }
#endif
            else if (ifnet_mtu(ifp) + adj > IF_MAXMTU) {
                ifnet_set_mtu(ifp, IF_MAXMTU);
                break;
            }
            ifnet_set_mtu(ifp, ifnet_mtu(ifp) + adj);
            /* hack, if key changed, then change hash value */
            if (gre_hash_delete(sc) == 0) {
                sc->key = key;
                gre_hash_add(sc);
            } else {
                sc->key = key;
            }
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
#ifdef DEBUG
    printf("%s: done\n", __FUNCTION__);
#endif
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
#ifdef DEBUG
    printf("%s: detach done\n", __FUNCTION__);
#endif
}

/*
 * return EJUSTRETURN if mbuf is freed in this function since our caller dlil_input_packet_list()
 * will free the mbuf if any error code returned
 */
static errno_t
gre_demux(ifnet_t ifp, mbuf_t m, char *frame_header, protocol_family_t *protocol)
{
    dprintf("%s\n", __FUNCTION__);
    struct gre_softc *sc = ifnet_softc(ifp);
    /* the data in ip header in mbuf that is passed into ip filters always use network byte order */
    switch (((struct gre_h *)frame_header)->ptype) {
        case htons(WCCP_PROTOCOL_TYPE):
            if (! (sc->proto_flag & AF_INET_PRESENT))
                return ENOENT;
            *protocol = AF_INET;
            break;
        case htons(ETHERTYPE_IP):
            if (! (sc->proto_flag & AF_INET_PRESENT))
                return ENOENT;
            *protocol = AF_INET;
            break;
        case htons(ETHERTYPE_IPV6):
            if (! (sc->proto_flag & AF_INET6_PRESENT))
                return ENOENT;
            *protocol = AF_INET6;
            break;
        case htons(ETHERTYPE_AT):
            if (! (sc->proto_flag & AF_APPLETALK_PRESENT))
                return ENOENT;
            *protocol = AF_APPLETALK;
            break;
        default:
            dprintf("Proto type %d is not supported yet.\n", ntohs(((struct gre_h *)frame_header)->ptype));
            return ENOENT;
    }
    
#ifdef DEBUG
    struct ip *iphdr = mbuf_data(m);
    switch (iphdr->ip_v) {
        case 4: // AF_INET
            if (*protocol != AF_INET)
                printf("%s: invalid ip header, protocol = %d, should be %d\n", __FUNCTION__, *protocol, AF_INET);
            break;
        case 6: // AF_INET6
            if (*protocol != AF_INET6)
                printf("%s: invalid ipv6 header, protocol = %d, should be %d\n", __FUNCTION__, *protocol, AF_INET6);
            break;
        default:
            dprintf("%s: unsupported IP version %d\n", __FUNCTION__, iphdr->ip_v);
            break;
    }
#endif
    return 0;
}

/*
 * gre_input is the input handler for IP and IPv6 attached to gre, 
 * our caller dlil_ifproto_input() will free the mbuf chain if any
 * error except EJUSTRETURN is returned
 */
static errno_t
gre_input(ifnet_t ifp, protocol_family_t protocol, mbuf_t m, __unused char *frame_header)
{
    dprintf("%s: protocol: %d\n", __FUNCTION__, protocol);
    
    if (((struct gre_softc *)ifnet_softc(ifp))->bpf_input) {
        protocol_family_t bpf_header = protocol;
        bpf_tap_in(ifp, 0, m, &bpf_header, sizeof(bpf_header));
    }
	
    size_t len = mbuf_pkthdr_len(m);
    errno_t err = proto_input(protocol, m);
	if (err) {
        ifnet_stat_increment_in(ifp, 0, 0, 1);
        printf("%s: warnning: proto_input() error: 0x%x\n", __FUNCTION__, err);
    } else
        ifnet_stat_increment_in(ifp, 1, len, 0);
    
	return err;
}

/*
 * is called just before the packet is transmitted. Specify the media specific frame type and destination here.
 * return EJUSTRETURN when mbuf is freed here, other error code except 0 indicates that the caller dlil_output()
 * will free the mbuf.
 */
static errno_t
gre_pre_output(ifnet_t ifp, protocol_family_t protocol, mbuf_t *m,
                  const struct sockaddr *dest, __unused void *route, __unused char *frame_type, __unused char *link_layer_dest)
{
    /* our caller dlil_output() will check if protocal exist on ifp by find_attached_proto() */
#ifdef DEBUG
    struct gre_softc *sc = ifnet_softc(ifp);
    if (protocol != dest->sa_family)
        printf("%s: warnning: protocol:%d, dest->sa_family:%d\n", __FUNCTION__, protocol, dest->sa_family);

    switch (protocol) {
        case AF_INET:
            if (! sc->proto_flag & AF_INET_PRESENT)
                return EAFNOSUPPORT;
            break;
        case AF_INET6:
            if (! sc->proto_flag & AF_INET6_PRESENT)
                return EAFNOSUPPORT;
            break;
        case AF_APPLETALK:
            if (! sc->proto_flag & AF_APPLETALK_PRESENT)
                return EAFNOSUPPORT;
            break;
        default:
            return EAFNOSUPPORT;
    }
#endif
    if ((mbuf_flags(*m) & MBUF_PKTHDR) == 0) {
        printf("%s: Warning: It is NOT a valid mbuf packet !!!\n", __FUNCTION__);
        return EINVAL;
    }
    
    if (((struct gre_softc *)ifnet_softc(ifp))->bpf_output) {
        /* Need to prepend the address family as a four byte field. */
        //protocol_family_t bpf_header = sc->gre_psrc.sa_family;
        protocol_family_t bpf_header = protocol;
        bpf_tap_out(ifp, 0, *m, &bpf_header, sizeof(bpf_header));
    }

#ifdef DEBUG
    printf("%s: done\n", __FUNCTION__);
#endif
	return 0;
}

/*
 * Prepend gre headers. called by dlil_output()
 */
static errno_t
gre_framer(ifnet_t ifp, mbuf_t *mr, const struct sockaddr *dest, __unused const char *dest_linkaddr, __unused const char *frame_type)
{
    mbuf_t      m = *mr;
	struct gre_softc    *sc = ifnet_softc(ifp);
	struct greip    *gh = NULL;
	struct ip       *ip = NULL;
	u_int16_t   gre_ip_id = 0;
	uint8_t     gre_ip_tos = 0;
	u_int16_t   etype = 0;
	struct mobile_h mob_h;
	size_t      extra = 0;
    
    mbuf_setflags(m, mbuf_flags(m) & ~(MBUF_BCAST | MBUF_MCAST));
    
    switch (sc->encap_proto) {
        case IPPROTO_MOBILE:
            if (dest->sa_family == AF_INET) {
                mbuf_t m0;
                size_t msiz;
                
                ip = mbuf_data(m);
                
                /*
                 * RFC2004 specifies that fragmented diagrams shouldn't
                 * be encapsulated.
                 */
                if (ip->ip_off & (IP_MF | IP_OFFMASK)) {
                    dprintf("%s: drop fragmented diagram..\n", __FUNCTION__);
                    return EINVAL;    /* is there better errno? */
                }
                bzero(&mob_h, MOB_H_SIZ_L);
                mob_h.proto = (ip->ip_p) << 8;
                mob_h.odst = ip->ip_dst.s_addr;
                ip->ip_dst.s_addr = ((struct sockaddr_in *)&sc->gre_pdst)->sin_addr.s_addr; //sc->g_dst.s_addr;
                
                /*
                 * If the packet comes from our host, we only change
                 * the destination address in the IP header.
                 * Else we also need to save and change the source
                 */
                if (in_hosteq(ip->ip_src, ((struct sockaddr_in *)&sc->gre_psrc)->sin_addr))
                {
                    msiz = MOB_H_SIZ_S;
                } else {
                    mob_h.proto |= MOB_H_SBIT;
                    mob_h.osrc = ip->ip_src.s_addr;
                    ip->ip_src.s_addr = ((struct sockaddr_in *)&sc->gre_psrc)->sin_addr.s_addr;
                    msiz = MOB_H_SIZ_L;
                }
                mob_h.proto = htons(mob_h.proto);
                mob_h.hcrc = gre_in_cksum((u_int16_t *)&mob_h, msiz);
                
                if (mbuf_leadingspace(m) < msiz)
                {
                    /* need new mbuf */
                    mbuf_gethdr(MBUF_DONTWAIT, MBUF_TYPE_DATA, &m0);
                    if (m0 == NULL) {
                        //mbuf_freem(m);
                        return ENOBUFS;
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
                ip->ip_p = sc->encap_proto;
            } else {  /* AF_INET */
                return EINVAL;
            }
            break;
        case IPPROTO_GRE:
        {
            switch (dest->sa_family) {
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
                case AF_INET6:
                    gre_ip_id = htons((u_int16_t)(random() & 0xffff));
                    etype = ETHERTYPE_IPV6;
                    break;
                case AF_APPLETALK:
                    gre_ip_id = htons((u_int16_t)(random() & 0xffff));
                    etype = ETHERTYPE_AT;
                    break;
                default:
                    return EAFNOSUPPORT;
            }
            
            /* Reserve space for GRE header + optional GRE key */
            int hdrlen = sizeof(struct greip) + extra;
            if (sc->key)
                hdrlen += sizeof(uint32_t);
            if (mbuf_prepend(&m, hdrlen, MBUF_DONTWAIT)) {
                printf("%s: error - Not enough memory\n", __FUNCTION__);
                return EJUSTRETURN; // mbuf has been freed by mbuf_prepend()
            }
            ip = mbuf_data(m);
            
            ip->ip_v    = 4;
            ip->ip_hl   = (sizeof(struct ip)) >> 2;
            ip->ip_tos  = gre_ip_tos;
            ip->ip_len  = htons(mbuf_pkthdr_len(m));    /* Put ip_len and ip_off in network byte order, ipf_inject_output expects that */
            ip->ip_id   = gre_ip_id;
            ip->ip_off  = 0;                /* gre has no MORE fragment */
            ip->ip_ttl  = GRE_TTL;
            ip->ip_p    = sc->encap_proto;
            ip->ip_src  = ((struct sockaddr_in *)&sc->gre_psrc)->sin_addr;
            ip->ip_dst  = ((struct sockaddr_in *)&sc->gre_pdst)->sin_addr;
            ip->ip_sum  = gre_in_cksum((u_int16_t *)ip, sizeof(struct ip));
            
            gh = (struct greip *)ip;
            gh->gi_ptype = htons(etype);
            gh->gi_flags = 0;
            /* Add key option. As gre chsum is at much high cost, we do NOT support it */
            if (sc->key) {
                gh->gi_flags |= htons(GRE_KP);
                gh->gi_options[0] = htonl(sc->key);
            }
            break;
        }
        default:
            return EINVAL;
    }
    
    mbuf_set_csum_performed(m, MBUF_CSUM_DID_IP | MBUF_CSUM_IP_GOOD, 0xffff);
    
    if (m != *mr) {
        dprintf("%s: mbuf mr changed.\n", __FUNCTION__);
        *mr = m;
    }
#ifdef DEBUG
    printf("%s: done\n", __FUNCTION__);
#endif
	return 0;
}

/*
 * The output routine. Takes a packet and encapsulates it in the protocol
 * given by sc->encap_proto. See also RFC 1701 and RFC 2004
 */
static errno_t gre_output(ifnet_t ifp, mbuf_t m) //, struct sockaddr *dst)
{
    errno_t err;
    struct gre_softc *sc = ifnet_softc(ifp);
    if (ifnet_flags(ifp) & (IFF_UP | IFF_RUNNING) != (IFF_UP | IFF_RUNNING) || \
        sc->gre_psrc.sa_family == AF_UNSPEC || \
        sc->gre_pdst.sa_family == AF_UNSPEC) {
        mbuf_freem(m);
        ifnet_touch_lastchange(ifp);
        err = ENETDOWN;
        goto error;
	}
    
    /*
	 * infinite recursion calls may occurs when it's misconfigured.
	 * We'll prevent this by introducing upper limit.
	 */
	if (++(sc->called) > max_gre_nesting) {
        mbuf_freem(m);
		printf("%s%d: recursively called too many times(%u)\n", ifnet_name(ifp), ifnet_unit(ifp), sc->called);
        err = ENETUNREACH;
		goto error;
	}
    
    size_t pkthdr_len = mbuf_pkthdr_len(m);
    /* ipf_inject_output() will always free the mbuf */
    err = ipf_inject_output(m, NULL, NULL);
	if (err)
        ifnet_stat_increment_out(ifp, 0, 0, 1);
    else
        ifnet_stat_increment_out(ifp, 1, pkthdr_len, 0);
    
error:
    sc->called = 0;
	return err;
}

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
