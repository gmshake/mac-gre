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

#include <libkern/OSAtomic.h>

#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/kpi_mbuf.h>
#include <sys/sysctl.h>
#include <sys/socket.h>
#include <sys/sockio.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/bpf.h>
#include <net/kpi_protocol.h>
#include <net/ethernet.h>
#ifdef OSX_10_5
#include <netat/appletalk.h>
#endif
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/kpi_ipfilter.h>

#if CONFIG_MACF_NET
#include <security/mac_framework.h>
#endif

#include "gre_if.h"
#include "gre_hash.h"
#include "gre_config.h"

/*
 * It is not easy to calculate the right value for a GRE MTU.
 * We leave this task to the admin and use the same default that
 * other vendors use.
 */
#define GREMTU	1476
#define GRE_MIN_MTU 576

#define GRENAME	"gre"

/* link layer header, ETHER_HDR_LEN + overhead, default is 16 in xnu1228 */
#define MAX_LINKHDR (ETHER_HDR_LEN + 2)


extern lck_grp_t *gre_lck_grp;


static errno_t  gre_add_proto(ifnet_t ifp, protocol_family_t protocol, const struct ifnet_demux_desc *demux_array, u_int32_t demux_count);
static errno_t  gre_del_proto(ifnet_t ifp, protocol_family_t protocol);

static errno_t  gre_ioctl(ifnet_t ifp, unsigned long cmd, void *data);
static errno_t  gre_set_bpf_tap(ifnet_t ifp, bpf_tap_mode mode, bpf_packet_func func);
static void     gre_if_detached(ifnet_t ifp);

static int      gre_demux(ifnet_t ifp, mbuf_t m, char *frame_header, protocol_family_t *protocol);
static errno_t  gre_input(ifnet_t ifp, protocol_family_t protocol, mbuf_t m, char *frame_header);

static errno_t  gre_pre_output(ifnet_t ifp, protocol_family_t protocol, mbuf_t *packet, const struct sockaddr *dest, void *route, char *frame_type, char *link_layer_dest);
static errno_t  gre_framer(ifnet_t ifp, mbuf_t *m, const struct sockaddr *dest, const char *dest_linkaddr, const char *frame_type);
static errno_t  gre_output(ifnet_t ifp, mbuf_t m);

static u_int16_t ip_randomid();

// vars
static lck_rw_t *gre_lck = NULL; // protect gre_softc_list

static TAILQ_HEAD(gre_softc_head, gre_softc) gre_softc_list;
static unsigned int ngre = 0;       /* number of interfaces */

// hack: default gre_if_family
static ifnet_family_t gre_if_family = IFNET_FAMILY_TUN;

/*
 * This var controls the default upper limitation on nesting of gre tunnels.
 * Since, setting a large value to this macro with a careless configuration
 * may introduce system crash, we don't allow any nestings by default.
 * If you need to configure nested gre tunnels, you can define this macro
 * in your kernel configuration file.  However, if you do so, please be
 * careful to configure the tunnels so that it won't make a loop.
 */

static unsigned int max_gre_nesting = 1;

SYSCTL_NODE(_net, OID_AUTO, gre, CTLFLAG_RW | CTLFLAG_LOCKED, 0, "Generic Routing Encapsulation");
SYSCTL_UINT(_net_gre, OID_AUTO, maxnesting, CTLTYPE_INT | CTLFLAG_RW, &max_gre_nesting, 0, "Max nested tunnels");

//SYSCTL_DECL(_net_link);
//SYSCTL_NODE(_net_link, OID_AUTO, gre, CTLFLAG_RW | CTLFLAG_LOCKED, 0, "Generic Routing Encapsulation");
//SYSCTL_UINT(_net_link_gre, OID_AUTO, maxnesting, CTLTYPE_INT | CTLFLAG_RW, &max_gre_nesting, 0, "Max nested tunnels");


/* register INET, INET6 adn APPLETALK protocol families */
int gre_proto_register() {
#ifdef DEBUG
    printf("%s ...\n", __FUNCTION__);
#endif

    int err;

    err = mbuf_tag_id_find(GRE_CONTROL_NAME, &gre_if_family);
	if (err != 0) {
		printf("%s: mbuf_tag_id_find failed: %d\n", __FUNCTION__, err);
		return err;
	} else if ((gre_if_family & 0xffff) != gre_if_family) {
        printf("%s: gre_if_family overflow: %d\n", __FUNCTION__, gre_if_family);
        return ENOENT;
    }


    err = proto_register_plumber(PF_INET, gre_if_family, gre_attach_proto_family, gre_detach_proto_family);
    if (err) {
        printf("%s: could not register PF_INET protocol family: %d\n", __FUNCTION__, err);
#ifdef DEBUG
    if (err == EEXIST)
        printf("%s proto(PF_INET, %d) plumber exist\n", __FUNCTION__, gre_if_family);
#endif
        goto fail;
    }
    
#ifdef DEBUG
    printf("%s proto_register_plumber(PF_INET, %d) ok\n", __FUNCTION__, gre_if_family);
#endif

    err = proto_register_plumber(PF_INET6, gre_if_family, gre_attach_proto_family, gre_detach_proto_family);
    if (err) {
        proto_unregister_plumber(PF_INET, gre_if_family);
        
        printf("%s: could not register PF_INET6 protocol family: %d\n", __FUNCTION__, err);
#ifdef DEBUG
    if (err == EEXIST)
        printf("%s proto(PF_INET6, %d) plumber exist\n", __FUNCTION__, gre_if_family);
#endif
        goto fail;
    }
    
#ifdef DEBUG
    printf("%s proto_register_plumber(PF_INET6, %d) ok\n", __FUNCTION__, gre_if_family);
#endif


#if ENABLE_APPLETALK
    err = proto_register_plumber(PF_APPLETALK, gre_if_family, gre_attach_proto_family, gre_detach_proto_family);
    if (err) {
        proto_unregister_plumber(PF_INET6, gre_if_family);
        proto_unregister_plumber(PF_INET, gre_if_family);
        
        printf("%s: could not register PF_APPLETALK protocol family: %d\n", __FUNCTION__, err);
#ifdef DEBUG
    if (err == EEXIST)
        printf("%s proto(PF_APPLETALK, %d) plumber exist\n", __FUNCTION__, gre_if_family);
#endif
    }
    
#ifdef DEBUG
    printf("%s proto_register_plumber(PF_APPLETALK, %d) ok\n", __FUNCTION__, gre_if_family);
#endif

#endif

#ifdef DEBUG
    printf("%s: done\n", __FUNCTION__);
#endif

    return 0;

fail:
    return -1;
}

/* unregister INET, INET6 adn APPLETALK protocol families */
void gre_proto_unregister() {
#ifdef DEBUG
    printf("%s ...\n", __FUNCTION__);
#endif

#if ENABLE_APPLETALK
    proto_unregister_plumber(PF_APPLETALK, gre_if_family);
#ifdef DEBUG
    printf("%s proto_unregister_plumber(PF_APPLETALK, %d) ok\n", __FUNCTION__, gre_if_family);
#endif
#endif

    proto_unregister_plumber(PF_INET6, gre_if_family);
#ifdef DEBUG
    printf("%s proto_unregister_plumber(PF_INET6, %d) ok\n", __FUNCTION__, gre_if_family);
#endif

    proto_unregister_plumber(PF_INET, gre_if_family);
#ifdef DEBUG
    printf("%s proto_unregister_plumber(PF_INET, %d) ok\n", __FUNCTION__, gre_if_family);
#endif

#ifdef DEBUG
    printf("%s: done\n", __FUNCTION__);
#endif
}

int gre_if_init()
{
#ifdef DEBUG
    printf("%s ...\n", __FUNCTION__);
#endif

    if (gre_lck != NULL) {
#ifdef DEBUG
        printf("%s: warnning: has inited...\n", __FUNCTION__);
#endif
        goto success;
    }

    gre_lck = lck_rw_alloc_init(gre_lck_grp, NULL);
    if (gre_lck == NULL) {
#ifdef DEBUG
        printf("%s: faild, not enough mem???\n", __FUNCTION__);
#endif
        goto failed;
    }

    lck_rw_lock_exclusive(gre_lck);
    TAILQ_INIT(&gre_softc_list);
    lck_rw_unlock_exclusive(gre_lck);

    sysctl_register_oid(&sysctl__net_gre);
    sysctl_register_oid(&sysctl__net_gre_maxnesting);

success:
#ifdef DEBUG
    printf("%s: done\n", __FUNCTION__);
#endif
    return 0;

failed:
#ifdef DEBUG
    printf("%s: fail\n", __FUNCTION__);
#endif
    return -1;
}


int gre_if_dispose()
{
#ifdef DEBUG
    printf("%s ...\n", __FUNCTION__);
#endif

    if (gre_lck == NULL) {
#ifdef DEBUG
        printf("%s: gre_lck has already been freed...\n", __FUNCTION__);
#endif
        goto success;
    }

    sysctl_unregister_oid(&sysctl__net_gre_maxnesting);
    sysctl_unregister_oid(&sysctl__net_gre);

    struct gre_softc *sc, *tp_sc;

    lck_rw_lock_exclusive(gre_lck);
    
    TAILQ_FOREACH_SAFE(sc, &gre_softc_list, sc_list, tp_sc) {
        TAILQ_REMOVE(&gre_softc_list, sc, sc_list);
        gre_sc_release(sc);
    }
    
    lck_rw_unlock_exclusive(gre_lck);
    lck_rw_lock_shared(gre_lck);
    
    //lck_rw_lock_exclusive_to_shared(gre_lck);
    
    /* can't dispose if any interface are in use or any resources has not been freed */
    if (!TAILQ_EMPTY(&gre_softc_list)) {
#ifdef DEBUG
        printf("%s: resouces busy, please try later\n", __FUNCTION__);
#endif
        lck_rw_unlock_shared(gre_lck);
        goto busy;
    }
    lck_rw_unlock_shared(gre_lck);

    lck_rw_free(gre_lck, gre_lck_grp);
    gre_lck = NULL;

#ifdef DEBUG
    printf("%s: current ngre = %d\n", __FUNCTION__, ngre);
#endif

success:
#ifdef DEBUG
    printf("%s: done\n", __FUNCTION__);
#endif
    return 0;

busy:
#ifdef DEBUG
    printf("%s: fail\n", __FUNCTION__);
#endif
    return EBUSY;
}


static inline void gre_sc_lock(struct gre_softc *sc)
{
#ifdef DEBUG
    if (sc == NULL) {
        printf("%s: invalid parameters: sc = %p, should panic!!!\n", __FUNCTION__, sc);
        return;
    }
#endif
    lck_mtx_lock(sc->mtx);
}

static inline void gre_sc_unlock(struct gre_softc *sc)
{
#ifdef DEBUG
    if (sc == NULL) {
        printf("%s: invalid parameters: sc = %p, should panic!!!\n", __FUNCTION__, sc);
        return;
    }
#endif
    lck_mtx_unlock(sc->mtx);
}


static errno_t gre_remove_address(ifnet_t interface, protocol_family_t protocol, ifaddr_t address, socket_t socket)
{
	errno_t result = EPROTONOSUPPORT;

	/* Attempt a detach */
    if (protocol == PF_INET) {
        struct ifreq ifr;

        bzero(&ifr, sizeof(ifr));
        snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s%d", ifnet_name(interface), ifnet_unit(interface));

        result = ifaddr_address(address, &ifr.ifr_addr, sizeof(ifr.ifr_addr));
        if (result == 0) {
            result = sock_ioctl(socket, SIOCDIFADDR, &ifr);
            if (result != 0) {
                printf("%s - SIOCDIFADDR failed: %d", __FUNCTION__, result);
            }
        } else {
            printf("%s - ifaddr_address failed: %d", __FUNCTION__, result);
        }

	} else if (protocol == PF_INET6) {
        struct in6_ifreq ifr6;

        bzero(&ifr6, sizeof(ifr6));
        snprintf(ifr6.ifr_name, sizeof(ifr6.ifr_name), "%s%d", ifnet_name(interface), ifnet_unit(interface));

        result = ifaddr_address(address, (struct sockaddr*)&ifr6.ifr_addr, sizeof(ifr6.ifr_addr));
        if (result == 0) {
            result = sock_ioctl(socket, SIOCDIFADDR_IN6, &ifr6);
            if (result != 0) {
                printf("%s - SIOCDIFADDR_IN6 failed: %d", __FUNCTION__, result);
            }
        } else {
            printf("%s - ifaddr_address failed: %d", __FUNCTION__, result);
        }

	}

	return result;
}


static void gre_cleanup_family(ifnet_t ifp, protocol_family_t protocol) {
#ifdef DEBUG
    printf("%s (%s%d, %d) ...\n", __FUNCTION__, ifnet_name(ifp), ifnet_unit(ifp), protocol);
#endif
    errno_t err = 0;
    socket_t sock;
    ifaddr_t *addrs;

    if (protocol != PF_INET && protocol != PF_INET6) {
        printf("%s: invalid protocol family %d\n", __FUNCTION__, protocol);
		return;
    }

    /* Create a socket for removing addresses and detaching the protocol */
	err = sock_socket(protocol, SOCK_DGRAM, 0, NULL, NULL, &sock);
	if (err != 0) {
		if (err != EAFNOSUPPORT)
			printf("%s: failed to create %s socket: %d\n", __FUNCTION__,
                   protocol == PF_INET ? "IP" : "IPv6", err);
		goto cleanup;
	}

    err = ifnet_get_address_list_family(ifp, &addrs, protocol);
    if (err != 0) {
        printf("%s: ifnet_get_address_list_family(%s%d, %p, %s) - failed: %d\n", __FUNCTION__,
               ifnet_name(ifp), ifnet_unit(ifp), &addrs,
               protocol == PF_INET ? "PF_INET" : "PF_INET6", err);
        goto cleanup;
    }

    for (int i = 0; addrs[i] != NULL; i++) {
        gre_remove_address(ifp, protocol, addrs[i], sock);
    }
    ifnet_free_address_list(addrs);
    addrs = NULL;

cleanup:
    if (sock != NULL)
		sock_close(sock);

	if (addrs != NULL)
		ifnet_free_address_list(addrs);
#ifdef DEBUG
    printf("%s (%s%d, %d) done\n", __FUNCTION__, ifnet_name(ifp), ifnet_unit(ifp), protocol);
#endif
}

static void gre_sc_free(struct gre_softc *sc) {
#ifdef DEBUG
    printf("%s ...\n", __FUNCTION__);

    if (sc == NULL || sc->sc_ifp == NULL) {
        // Should panic
        printf("%s: invalid parameters: sc = %p, sc->sc_ifp = %p, should panic!!!\n", __FUNCTION__, sc, sc == NULL ? NULL : sc->sc_ifp);
        return;
    }
#endif

    ifnet_t ifp = sc->sc_ifp;

    // mark interface down
    ifnet_set_flags(ifp, 0, IFF_UP | IFF_RUNNING);

    // clean up
    gre_cleanup_family(ifp, PF_INET6);
    gre_cleanup_family(ifp, PF_INET);
    
    //ifnet_detach_protocol(ifp, PF_INET6);
    //ifnet_detach_protocol(ifp, PF_INET);
    
#if ENABLE_APPLETALK
    gre_detach_proto_family(ifp, PF_APPLETALK);
#endif
    gre_detach_proto_family(ifp, PF_INET6);
    gre_detach_proto_family(ifp, PF_INET);

    gre_sc_lock(sc);
    sc->is_detaching = 1;
    gre_sc_unlock(sc);

#ifdef DEBUG
    printf("%s: ifnet_detach(%s%d) ...\n", __FUNCTION__, ifnet_name(ifp), ifnet_unit(ifp));
#endif
    errno_t err = ifnet_detach(ifp);
#ifdef DEBUG
    printf("%s: ifnet_detach(%s%d) ret -> %d\n", __FUNCTION__, ifnet_name(ifp), ifnet_unit(ifp), err);
#endif
	if (err) { // maybe it has already been detached
        printf("%s: ifnet_detach %s%d error: %d\n", __FUNCTION__, ifnet_name(ifp), ifnet_unit(ifp), err);
        gre_sc_lock(sc);
		sc->is_detaching = 0;
        gre_sc_unlock(sc);
	} else { // err == 0
        int max_cnt = 10;
        do {
            gre_sc_lock(sc);
            if (sc->is_detaching) {
                /* interface release is in progress, wait for callback */
#ifdef DEBUG
                printf("%s: detaching is in progress...\n", __FUNCTION__);
#endif
                struct timespec tv;
                bzero(&tv, sizeof(tv));
                tv.tv_sec = 0;
                tv.tv_nsec = NSEC_PER_SEC / 5; // 200ms

                msleep(&sc->is_detaching, sc->mtx, PDROP, "gre_sc_free", &tv);  // sc->mtx will be unlocked by msleep
            } else {
                gre_sc_unlock(sc);
                break;
            }
        } while (--max_cnt > 0);
    }

    if (sc->is_detaching) {
        printf("%s: detach %s%d failed, continue, mem leaks\n", __FUNCTION__, ifnet_name(ifp), ifnet_unit(ifp));
#ifdef DEBUG
        printf("%s: error\n", __FUNCTION__);
#endif
        return;
    }

    // detach protocols when detaching interface, just in case not done ...
#if ENABLE_APPLETALK
    if (sc->proto_flag & AF_APPLETALK_PRESENT) {
        printf("%s: WARN %s%d AF_APPLETALK_PRESENT\n", __FUNCTION__, ifnet_name(ifp), ifnet_unit(ifp));
    }
#endif
    if (sc->proto_flag & AF_INET6_PRESENT) {
        printf("%s: WARN %s%d AF_INET6_PRESENT\n", __FUNCTION__, ifnet_name(ifp), ifnet_unit(ifp));
    }
    if (sc->proto_flag & AF_INET_PRESENT) {
        printf("%s: WARN %s%d AF_INET_PRESENT\n", __FUNCTION__, ifnet_name(ifp), ifnet_unit(ifp));
    }

    // now it's safe to release
    err = ifnet_release(ifp);
    if (err) {
        printf("%s: ERROR ifnet_release failed: %d, continue, may cause memory leak\n", __FUNCTION__, err);
    }

    lck_mtx_free(sc->mtx, gre_lck_grp);

	_FREE(sc, M_TEMP);

    OSDecrementAtomic(&ngre);

#ifdef DEBUG
    printf("%s: done\n", __FUNCTION__);
#endif
}

inline void gre_sc_reference(struct gre_softc *sc)
{
#ifdef DEBUG
    if (sc == NULL) {
        printf("%s: invalid sc(NULL)\n", __FUNCTION__);
        return;
    }
#endif
    OSIncrementAtomic((SInt32 *)&sc->sc_refcnt);
}

inline void gre_sc_release(struct gre_softc *sc)
{
#ifdef DEBUG
    if (sc == NULL) {
        printf("%s: invalid sc(NULL)\n", __FUNCTION__);
        return;
    }
#endif
    int oldval = OSDecrementAtomic((SInt32*)&sc->sc_refcnt);
    if (oldval == 1) { // now refcnt reach 0, free safely
        gre_sc_free(sc);
    }

}


// allocate an empty gre_softc with an initial sc_refcnt of 1
static struct gre_softc * gre_sc_allocate() {
    // if reach max unit number
    unsigned int unit;
    if ((unit = OSIncrementAtomic(&ngre)) >= GRE_MAXUNIT) {
        OSDecrementAtomic(&ngre);
        return NULL;
    }

    struct gre_softc * sc = (struct gre_softc *) _MALLOC(sizeof(struct gre_softc), M_TEMP, M_WAITOK | M_ZERO);
    if (sc == NULL)
		return NULL;

    sc->mtx = lck_mtx_alloc_init(gre_lck_grp, NULL);
	if (sc->mtx == NULL) {
        _FREE(sc, M_TEMP);
		return NULL;
	}

    struct ifnet_init_params init;
    bzero(&init, sizeof(init));
	init.name = GRENAME;
	init.unit = unit;
	init.type = IFT_OTHER;
	init.family = gre_if_family;
	init.output = gre_output;
	init.demux = gre_demux;
	init.add_proto = gre_add_proto;
	init.del_proto = gre_del_proto;
    init.framer = gre_framer;
	init.softc = sc;
	init.ioctl = gre_ioctl;
	//init.set_bpf_tap = gre_set_bpf_tap; // deprecated
    init.detach = gre_if_detached;

	errno_t err = ifnet_allocate(&init, &sc->sc_ifp);
	if (err) {
        lck_mtx_free(sc->mtx, gre_lck_grp);
        _FREE(sc, M_TEMP);

		printf("%s: ifnet_allocate() failed - %d\n", __FUNCTION__, err);
		return NULL;
	}

    sc->sc_refcnt = 1;
    sc->called = 0;
    sc->encap_proto = IPPROTO_GRE;
    sc->wccp_ver = WCCP_V1;
    sc->key = 0;

    ifnet_t ifp = sc->sc_ifp;

    ifnet_set_addrlen(ifp, 0);
    ifnet_set_mtu(ifp, GREMTU);
    ifnet_set_hdrlen(ifp, sizeof(struct greip)); // IP + GRE
	ifnet_set_flags(ifp, IFF_POINTOPOINT | IFF_MULTICAST | IFF_LINK0, 0xffff);
    
    // reset the status in case as the interface may has been recycled
    struct ifnet_stats_param param;
    bzero(&param, sizeof(param));
    ifnet_set_stat(ifp, &param);

    ifnet_touch_lastchange(ifp);

    err = ifnet_attach(ifp, NULL);
	if (err) {
        err = ifnet_release(ifp);
        if (err) 
            printf("%s: ifnet_release failed: %d, continue, may cause memory leak\n", __FUNCTION__, err);
        
        lck_mtx_free(sc->mtx, gre_lck_grp);
        _FREE(sc, M_TEMP);

		printf("%s: ifnet_attach() failed - %d\n", __FUNCTION__, err);
		return NULL;
	}

#if CONFIG_MACF_NET
	mac_ifnet_label_init(&sc->sc_ifp);
#endif

	bpfattach(ifp, DLT_NULL, sizeof(u_int32_t));

    return sc;
}



/*
 * gre_attach(), attach a new interface
 * sc->sc_refcnt is increase by 1
 */
int gre_if_attach()
{
	struct gre_softc *sc;

    lck_rw_lock_shared(gre_lck);
    /* Check for unused gre interface */
	TAILQ_FOREACH(sc, &gre_softc_list, sc_list) {
		/* If unused, return, no need to create a new interface */
		if (sc->sc_ifp && (ifnet_flags(sc->sc_ifp) & IFF_RUNNING) == 0) {
            lck_rw_unlock_shared(gre_lck);
            return 0;
        }
	}

    lck_rw_unlock_shared(gre_lck);

    sc = gre_sc_allocate();
    if (sc == NULL)
		return ENOMEM;

    lck_rw_lock_exclusive(gre_lck);
    TAILQ_INSERT_TAIL(&gre_softc_list, sc, sc_list);
    lck_rw_unlock_exclusive(gre_lck);

	return 0;
}


/* attach inet/inet6 to a GRE interface through DLIL */
errno_t gre_attach_proto_family(ifnet_t ifp, protocol_family_t protocol_family)
{
#ifdef DEBUG
    printf("%s: fam=0x%x\n", __FUNCTION__, protocol_family);
#endif
    struct ifnet_attach_proto_param	proto;
    errno_t err;

	bzero(&proto, sizeof(proto));
    proto.input = gre_input;
    proto.pre_output = gre_pre_output;

    err = ifnet_attach_protocol(ifp, protocol_family, &proto);
    if (err && err != EEXIST)
        printf("%s: ifnet_attach_protocol can't attach interface %s%d fam=0x%x\n", \
               __FUNCTION__, ifnet_name(ifp), ifnet_unit(ifp),  protocol_family);
#ifdef DEBUG
    if (err == EEXIST)
        printf("%s: ifnet_attach_protocol(), %s%d with proto: 0x%x, error = EEXIST\n", __FUNCTION__, ifnet_name(ifp), ifnet_unit(ifp), protocol_family);
    
    printf("%s: fam=0x%x done\n", __FUNCTION__, protocol_family);
#endif
    return err;
}


void gre_detach_proto_family(ifnet_t ifp, protocol_family_t protocol)
{
#ifdef DEBUG
    printf("%s: fam=0x%x\n", __FUNCTION__, protocol);
#endif

    errno_t err = ifnet_detach_protocol(ifp, protocol);
    if (err && err != ENOENT && err != ENXIO)
        printf("%s: ifnet_detach_protocol() %s%d error = 0x%x\n", \
               __FUNCTION__, ifnet_name(ifp), ifnet_unit(ifp), err);

#ifdef DEBUG
    if (err == ENOENT || err == ENXIO)
        printf("%s: ifnet_attach_protocol(), %s%d with proto: 0x%x, error = %s\n", __FUNCTION__, ifnet_name(ifp), ifnet_unit(ifp), protocol, err == ENOENT ? "ENOENT" : "ENXIO");

    printf("%s: fam=0x%x done\n", __FUNCTION__, protocol);
#endif
}


/*
 * is called by the stack when a protocol is attached to gre interface.
 */
static errno_t
gre_add_proto(ifnet_t ifp, protocol_family_t protocol, const struct ifnet_demux_desc *demux_array,
              u_int32_t demux_count)
{
    struct gre_softc *sc = ifnet_softc(ifp);
#ifdef DEBUG
    printf("%s: add proto 0x%x for %s%d, current status: %x\n", __FUNCTION__, protocol, ifnet_name(ifp), ifnet_unit(ifp), sc->proto_flag);
#endif
    switch (protocol) {
        case AF_INET:
            sc->proto_flag |= AF_INET_PRESENT;
            break;
        case AF_INET6:
            sc->proto_flag |= AF_INET6_PRESENT;
            break;
#if ENABLE_APPLETALK
        case AF_APPLETALK:
            sc->proto_flag |= AF_APPLETALK_PRESENT;
            break;
#endif
        default:
            return ENOPROTOOPT;	// happen for unknown protocol, or for empty descriptor
    }
#ifdef DEBUG
    printf("%s: add proto 0x%x for %s%d\n", __FUNCTION__, protocol, ifnet_name(ifp), ifnet_unit(ifp));
#endif
	return 0;
}


/*
 * is called by the stack when a protocol is being detached from gre interface.
 */
static errno_t
gre_del_proto(ifnet_t ifp, protocol_family_t protocol)
{
#ifdef DEBUG
    printf("%s: del proto for %s%d, current status: %x\n", __FUNCTION__, ifnet_name(ifp), ifnet_unit(ifp), ((struct gre_softc*)ifnet_softc(ifp))->proto_flag);
#endif
	switch (protocol) {
        case AF_INET:
            ((struct gre_softc*)ifnet_softc(ifp))->proto_flag &= ~AF_INET_PRESENT;
            break;
        case AF_INET6:
            ((struct gre_softc*)ifnet_softc(ifp))->proto_flag &= ~AF_INET6_PRESENT;
            break;
#if ENABLE_APPLETALK
        case AF_APPLETALK:
            ((struct gre_softc*)ifnet_softc(ifp))->proto_flag &= ~AF_APPLETALK_PRESENT;
            break;
#endif
        default:
            return EINVAL;	// happen for unknown protocol, or for empty descriptor
    }
	return 0;
}


/*
 * communicate ioctls from the stack to the driver.
 */
static errno_t
gre_ioctl(ifnet_t ifp, unsigned long cmd, void *data)
{
	struct ifreq *ifr = (struct ifreq *)data;
	struct gre_softc *sc = ifnet_softc(ifp);
    struct sockaddr *src = NULL, *dst = NULL;
    int size = 0;
    int adj = 0;
	errno_t error = 0;
	uint32_t key;

#ifdef DEBUG
    printf("%s: %s%d cmd -> %lu, data -> %p\n", __FUNCTION__, ifnet_name(ifp), ifnet_unit(ifp), cmd & 0xff, data);
#endif

	switch (cmd) {
/*
        case SIOCSIFADDR:
        case SIOCAIFADDR:
#ifdef DEBUG
            printf("%s: SIOCSIFADDR %lu \n", __FUNCTION__, cmd & 0xff);
#endif
//            ifnet_set_flags(ifp, IFF_UP, IFF_UP);
            break;
*/
        case SIOCSIFFLAGS:
        {
#ifdef DEBUG
            printf("%s: SIOCSIFFLAGS %lu \n", __FUNCTION__, cmd & 0xff);
#endif
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
            if (newproto != sc->encap_proto) {
                gre_sc_reference(sc);
                
                gre_hash_lock_exclusive();
                
                int err = gre_hash_delete(sc);
                sc->encap_proto = newproto;
                if (err == 0) // sc is in hash table
                    gre_hash_add(sc);
                
                gre_hash_unlock_exclusive();
                
                gre_sc_release(sc);
                
            }
            goto recompute;
        }
        case SIOCSIFMTU:
#ifdef DEBUG
            printf("%s: SIOCSIFMTU %lu \n", __FUNCTION__, cmd & 0xff);
#endif
            
            if (ifr->ifr_mtu < GRE_MIN_MTU || ifr->ifr_mtu > IF_MAXMTU) {
                error = EINVAL;
                break;
            }
            
            ifnet_set_mtu(ifp, ifr->ifr_mtu);
            break;
        case SIOCGIFMTU:
            ifr->ifr_mtu = ifnet_mtu(ifp);
            break;
        case SIOCADDMULTI:
#ifdef DEBUG
            printf("%s: SIOCADDMULTI %lu \n", __FUNCTION__, cmd & 0xff);
#endif
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
        case SIOCDELMULTI:
#ifdef DEBUG
            printf("%s: SIOCDELMULTI %lu \n", __FUNCTION__, cmd & 0xff);
#endif
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
        case GRESPROTO: /* set new proto */
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
            if (newproto != sc->encap_proto) {
                gre_sc_reference(sc);
                
                gre_hash_lock_exclusive();
                
                int err = gre_hash_delete(sc);
                sc->encap_proto = newproto;
                if (err == 0) // sc is in hash table
                    gre_hash_add(sc);
                
                gre_hash_unlock_exclusive();
                
                gre_sc_release(sc);
            }
            goto recompute;
        }
        case GREGPROTO:
            ifr->ifr_flags = sc->encap_proto;
            break;
        case GRESADDRS: // set tunnel src address
            //bcopy((caddr_t)&ifr->ifr_addr, (caddr_t)&sc->gre_psrc, ifr->ifr_addr.sa_len);
            error = EINVAL;
            break;
        case GRESADDRD: // set tunnel dst address
            //bcopy((caddr_t)&ifr->ifr_addr, (caddr_t)&sc->gre_pdst, ifr->ifr_addr.sa_len);
            error = EINVAL;
            break;
        case GREGADDRS: // get gre tunnel src address
            bcopy((caddr_t)&sc->gre_psrc, (caddr_t)&ifr->ifr_addr, sc->gre_psrc.sa_len);
            break;
        case GREGADDRD: // get gre tunnel dst address
            bcopy((caddr_t)&sc->gre_pdst, (caddr_t)&ifr->ifr_addr, sc->gre_pdst.sa_len);
            break;
        case SIOCSIFPHYADDR:
        case SIOCSLIFPHYADDR:
#ifdef DEBUG
            printf("%s: SIOCSIFPHYADDR, SIOCSIFPHYADDR_IN6, SIOCSLIFPHYADDR %lu \n", __FUNCTION__, cmd & 0xff);
#endif
            switch (cmd) {
                case SIOCSIFPHYADDR:
                    src = (struct sockaddr *) \
                            &(((struct in_aliasreq *)data)->ifra_addr);
                    dst = (struct sockaddr *) \
                            &(((struct in_aliasreq *)data)->ifra_dstaddr);
                    if (src->sa_family != AF_INET || dst->sa_family != AF_INET)
                        return EAFNOSUPPORT;
                    if (src->sa_len != sizeof(struct sockaddr_in) || dst->sa_len != sizeof(struct sockaddr_in))
                        return EINVAL;
                    break;
                case SIOCSLIFPHYADDR:
                    src = (struct sockaddr *) \
                            &(((struct if_laddrreq *)data)->addr);
                    dst = (struct sockaddr *) \
                            &(((struct if_laddrreq *)data)->dstaddr);
                    if (src->sa_family != AF_INET || dst->sa_family != AF_INET)
                        return EAFNOSUPPORT;
                    if (src->sa_family != dst->sa_family || src->sa_len != dst->sa_len)
                        return EINVAL;
                    break;
                default:
                    return EAFNOSUPPORT;
            }
            
            {
            lck_rw_lock_shared(gre_lck);
            struct gre_softc *tsc;
            TAILQ_FOREACH(tsc, &gre_softc_list, sc_list) {
                if (tsc == sc)
                    continue;
                if (tsc->gre_pdst.sa_family != dst->sa_family || \
                    tsc->gre_pdst.sa_len != dst->sa_len || \
                    tsc->gre_psrc.sa_family != src->sa_family || \
                    tsc->gre_psrc.sa_len != src->sa_len )
                    continue;
                
                /* can't configure same pair of address onto two GREs */
                if (bcmp(&tsc->gre_pdst, dst, dst->sa_len) == 0 &&
                    bcmp(&tsc->gre_psrc, src, src->sa_len) == 0) {
                    lck_rw_unlock_shared(gre_lck);
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
                    multidest(dst) && multidest(&tsc->gre_pdst)) {
                    lck_rw_unlock_shared(gre_lck);
                    return EADDRNOTAVAIL;
                }
#ifdef DEPLOY
                if (dst->sa_family == AF_INET6 &&
                    multidest6(dst) && multidest6(&tsc->gre_pdst)) {
                    lck_rw_unlock_shared(gre_lck);
                    return EADDRNOTAVAIL;
                }
#endif
            }
            lck_rw_unlock_shared(gre_lck);
            }

            ifnet_set_flags(ifp, 0, IFF_RUNNING);

            gre_sc_reference(sc);
            gre_hash_lock_exclusive();
            
            gre_hash_delete(sc);
            
            bcopy((caddr_t)src, (caddr_t)&sc->gre_psrc, src->sa_len);
            bcopy((caddr_t)dst, (caddr_t)&sc->gre_pdst, dst->sa_len);
            
            gre_hash_add(sc);
            
            gre_hash_unlock_exclusive();
            gre_sc_release(sc);
            
            ifnet_set_flags(ifp, IFF_RUNNING, IFF_RUNNING);
            
            /* here we ensure there is always one more GRE interface that is available */
            gre_if_attach();

recompute:
#if USE_IP_OUTPUT
            if ((((struct sockaddr_in *)&sc->gre_psrc)->sin_addr.s_addr != INADDR_ANY) &&
                (((struct sockaddr_in *)&sc->gre_pdst)->sin_addr.s_addr != INADDR_ANY)) {
                gre_compute_route(sc);
            }
#endif
            break;
        case SIOCDIFPHYADDR:
#ifdef DEBUG
            printf("%s: SIOCDIFPHYADDR\n", __FUNCTION__);
#endif
            ifnet_set_flags(ifp, 0, IFF_RUNNING);
            /* hack: do remember delete sc from hash first, or gre_hash_delete()
             * can NOT get original information to find it in hash_table
             */
            gre_hash_lock_exclusive();
            gre_hash_delete(sc);
            gre_hash_unlock_exclusive();
            
            bzero(&sc->gre_pdst, sizeof(sc->gre_pdst));
            bzero(&sc->gre_psrc, sizeof(sc->gre_psrc));
            break;
        case SIOCGLIFPHYADDR:
#ifdef DEBUG
            printf("%s: SIOCGLIFPHYADDR\n", __FUNCTION__);
#endif
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
        case SIOCGIFPSRCADDR:
        case SIOCGIFPSRCADDR_IN6:
#ifdef DEBUG
            printf("%s: SIOCGIFPSRCADDR, SIOCGIFPSRCADDR_IN6\n", __FUNCTION__);
#endif
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
        case SIOCGIFPDSTADDR:
        case SIOCGIFPDSTADDR_IN6:
#ifdef DEBUG
            printf("%s: SIOCGIFPDSTADDR, SIOCGIFPDSTADDR_IN6\n", __FUNCTION__);
#endif
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
        case GRESKEY:            
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

            if (ifnet_mtu(ifp) + adj < GRE_MIN_MTU)
                ifnet_set_mtu(ifp, GRE_MIN_MTU);
            else if (ifnet_mtu(ifp) + adj > IF_MAXMTU)
                ifnet_set_mtu(ifp, IF_MAXMTU);
            else
                ifnet_set_mtu(ifp, ifnet_mtu(ifp) + adj);

            sc->key = key;
            break;
        case GREGKEY:
            error = copyout(&sc->key, CAST_USER_ADDR_T(ifr->ifr_data), sizeof(sc->key));
            break;
/*
        case SIOCIFCREATE: // not supported on darwin
        case SIOCIFDESTROY:
            error = ENOTSUP;
            break;
*/
        default:
#ifdef DEBUG
            printf("\t Unkown ioctl flag:IN_OUT: 0x%lx \t num: %ld \n", cmd & (IOC_INOUT | IOC_VOID), cmd & 0xff);
#endif
            error = EOPNOTSUPP;
            break;
	}
	return error;
}

#if 0
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
#endif

/*
 * gre_if_free() is called when ifp detaching is done,
 * then it is safe to call ifnet_release()
 */
static void gre_if_detached(ifnet_t ifp)
{
#ifdef DEBUG
    printf("%s: %s%d ...\n", __FUNCTION__, ifnet_name(ifp), ifnet_unit(ifp));
#endif
    struct gre_softc* sc = ifnet_softc(ifp);
	gre_sc_lock(sc);
    if (sc->is_detaching) {
        sc->is_detaching = 0;
        wakeup(&sc->is_detaching);
    }
    gre_sc_unlock(sc);

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
#ifdef DEBUG
    printf("%s: %s%d, %p, %p, %p\n", __FUNCTION__, ifnet_name(ifp), ifnet_unit(ifp), m, frame_header, protocol);
#endif
    if (frame_header) {
        /*
        switch (*(u_int32_t *)frame_header) {
            case WCCP_PROTOCOL_TYPE:
                *protocol = AF_INET;
                break;
            case ETHERTYPE_IP:
                *protocol = AF_INET;
                break;
            case ETHERTYPE_IPV6:
                *protocol = AF_INET6;
                break;
            case ETHERTYPE_AT:
                *protocol = AF_APPLETALK;
                break;
            default:
                printf("Proto type %d is not supported yet.\n", *(u_int32_t *)frame_header);
                return ENOENT;
        } */
        *protocol = *(u_int32_t *)frame_header; /* is this safe ??? */


    } else {/* we check ip header by ourselves */
        struct ip *iphdr = mbuf_data(m);
        switch (iphdr->ip_v) {
            case 4: // AF_INET
                *protocol = AF_INET;
                break;
            case 6: // AF_INET6
                *protocol = AF_INET6;
                break;
            default:
#ifdef DEBUG
                printf("%s: unsupported IP version %d\n", __FUNCTION__, iphdr->ip_v);
#endif
                return ENOENT;
        }
    }

#ifdef DEBUG
    printf("%s: protocol -> %d\n", __FUNCTION__, *protocol);
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
#ifdef DEBUG
    printf("%s: protocol: %d\n", __FUNCTION__, protocol);
#endif    
//    if (((struct gre_softc *)ifnet_softc(ifp))->bpf_input) {
        protocol_family_t bpf_header = protocol;
        bpf_tap_in(ifp, 0, m, &bpf_header, sizeof(bpf_header));
//    }

    errno_t err = proto_input(protocol, m);
	if (err) {
        printf("%s: warnning: proto_input() error: 0x%x\n", __FUNCTION__, err);
    }
    
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
#if ENABLE_APPLETALK
        case AF_APPLETALK:
            if (! sc->proto_flag & AF_APPLETALK_PRESENT)
                return EAFNOSUPPORT;
            break;
#endif
        default:
            return EAFNOSUPPORT;
    }
//    if ((mbuf_flags(*m) & MBUF_PKTHDR) == 0) {
//        printf("%s: Warning: It is NOT a valid mbuf packet !!!\n", __FUNCTION__); /* should never happen */
//        return EINVAL;
//    }
#endif
    
//    if (((struct gre_softc *)ifnet_softc(ifp))->bpf_output) {
        /* Need to prepend the address family as a four byte field. */
        protocol_family_t bpf_header = protocol;
        bpf_tap_out(ifp, 0, *m, &bpf_header, sizeof(bpf_header));
//    }

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
                    printf("%s: drop fragmented diagram..\n", __FUNCTION__);
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
                    mbuf_setdata(m0, mbuf_data(m0) + MAX_LINKHDR, msiz + sizeof(struct ip));
                    bcopy((caddr_t)ip, mbuf_data(m0), sizeof(struct ip));
                    m = m0;
                } else {  /* we have some space left in the old one */
                    mbuf_setdata(m, mbuf_data(m), mbuf_len(m) + msiz);
                    mbuf_pkthdr_adjustlen(m, msiz);
                    bcopy(ip, mbuf_data(m), sizeof(struct ip));
                }
                ip = mbuf_data(m);
                bcopy(&mob_h, (caddr_t)(ip + 1), msiz);
                ip->ip_len = ntohs(ip->ip_len) + msiz; /* Put ip_len in host byte order, ip_output expects that */
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
                    gre_ip_id = ip_randomid();
                    etype = ETHERTYPE_IPV6;
                    break;
#if ENABLE_APPLETALK
                case AF_APPLETALK:
                    gre_ip_id = ip_randomid();
                    //etype = ETHERTYPE_AT;
                    break;
#endif
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
            ip->ip_len  = mbuf_pkthdr_len(m); /* Put ip_len and ip_off in host byte order, ip_output expects that */
            ip->ip_id   = gre_ip_id;
            ip->ip_off  = 0;                /* gre has no MORE fragment */
            ip->ip_ttl  = GRE_TTL;
            ip->ip_p    = sc->encap_proto;
            ip->ip_src  = ((struct sockaddr_in *)&sc->gre_psrc)->sin_addr;
            ip->ip_dst  = ((struct sockaddr_in *)&sc->gre_pdst)->sin_addr;
            ip->ip_sum  = 0;
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
    
    if (m != *mr)
        *mr = m;

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
    if ((ifnet_flags(ifp) & (IFF_UP | IFF_RUNNING)) != (IFF_UP | IFF_RUNNING) || \
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
    
#if USE_IP_OUTPUT
    if (sc->route.ro_rt == NULL || sc->route.ro_rt->rt_ifp == sc->sc_ifp) {
        if (gre_compute_route(sc) != 0) {
            mbuf_freem(m);
            err = ENETUNREACH;
            goto error;
        }
    }
    
    ifnet_stat_increment_out(ifp, 1, mbuf_pkthdr_len(m), 0);
    err = ip_output(m, NULL, &sc->route, IP_FORWARDING, (struct ip_moptions *)NULL, (struct ip_out_args *)NULL);
    
#else
    ifnet_stat_increment_out(ifp, 1, mbuf_pkthdr_len(m), 0);

    /* ipf_inject_output() will always free the mbuf */
    /* Put ip_len and ip_off in network byte order, ipf_inject_output expects that */
    // FIXME
#if BYTE_ORDER != BIG_ENDIAN
    struct ip *ip = mbuf_data(m);
    HTONS(ip->ip_len);
    HTONS(ip->ip_off);
#endif

    err = ipf_inject_output(m, NULL, NULL);
#endif
    if (err)
        ifnet_stat_increment_out(ifp, 0, 0, 1);
    
error:
    sc->called = 0;
	return err;
}

#ifdef DEBUG
static char *ip_print(const struct in_addr *in)
{
    static char buff[32];
    uint32_t addr = ntohl(in->s_addr);
    snprintf(buff, sizeof(buff), "%u.%u.%u.%u", addr >> 24, (addr >> 16) & 0xff, (addr >> 8) & 0xff, (addr) & 0xff);
    return buff;
}
#endif



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

/*
 * generate a random ip id
 * FIXME random is not RANDOM
 */
static inline u_int16_t ip_randomid()
{
    return (u_int16_t)(random() & 0xffff);
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
#if USE_IP_OUTPUT
static int gre_compute_route(struct gre_softc *sc)
{
    struct route *ro = &sc->route;
    
    if (ro->ro_rt)  /* free old route */
        rtfree(ro->ro_rt);
    
	bzero(ro, sizeof(struct route));
    bcopy(&sc->gre_pdst, &ro->ro_dst, sizeof(struct sockaddr_in));
    
#ifdef DEBUG
	printf("%s%d: searching for a route to %s\n", ifnet_name(sc->sc_ifp), ifnet_unit(sc->sc_ifp),
           ip_print(&((struct sockaddr_in *)&ro->ro_dst)->sin_addr));
#endif
    
#if MACOSX_10_9
    ro->ro_rt = rtalloc1(&ro->ro_dst, 1, 0);
#else
    lck_mtx_lock(rt_mtx);
    ro->ro_rt = rtalloc1_locked(&ro->ro_dst, 1, 0);
    lck_mtx_unlock(rt_mtx);
#endif
    if (ro->ro_rt == NULL) {
#ifdef DEBUG
        printf(" - no route found!\n");
#endif
        return EADDRNOTAVAIL;
    }
    
    if (ro->ro_rt->rt_ifp != sc->sc_ifp || \
        (ifnet_flags(sc->sc_ifp) & IFF_LINK1)) /* it does not route back, or IFF_LINK1 is set, use it */
        return 0;
    
	/*
	 * toggle last bit(1), so our interface is not found, but a less
	 * specific route. I'd rather like to specify a shorter mask,
	 * but this is not possible. Should work though. XXX
	 */
    
    rtfree(ro->ro_rt);
    ro->ro_rt = NULL;  /* we will find a less specified route later */
    
    struct sockaddr addr;
    bcopy(&sc->gre_pdst, &addr, sizeof(struct sockaddr));
    in_addr_t ia = ntohl(((struct sockaddr_in *)&addr)->sin_addr.s_addr);
    if (ia != INADDR_ANY) {
        int i = 0;
        while ((ia & 0x01) == 0) {
            ia >>= 1;
            i++;
        }
        ia ^= 0x01; /* toggle last None-Zero bit */
        ia <<= i;
    }
    
    ((struct sockaddr_in *)&addr)->sin_addr.s_addr = htonl(ia);
    
    lck_mtx_lock(rt_mtx);
    ro->ro_rt = rtalloc1_locked(&addr, 1, 0);
    lck_mtx_unlock(rt_mtx);
    
    int err = 0;
	/*
	 * check if this returned a route at all and this route is no
	 * recursion to ourself
	 */
	if (ro->ro_rt == NULL) {
#ifdef DEBUG
        printf(" - no route found!\n");
#endif
		err = EADDRNOTAVAIL;
	} else if (ro->ro_rt->rt_ifp == sc->sc_ifp) {
#ifdef DEBUG
        printf(" - route loops back to ourself!\n"); /* should we free the wrong route??? */
#endif
        rtfree(ro->ro_rt);
        ro->ro_rt = NULL;
        err = EADDRNOTAVAIL;
    }
    
#ifdef DEBUG
	printf("%s%d: searching for a route to %s", ifnet_name(sc->sc_ifp), ifnet_unit(sc->sc_ifp),
           ip_print(&((struct sockaddr_in *)&ro->ro_dst)->sin_addr));
    
	printf(", choosing %s%d with gateway %s\n", ifnet_name(ro->ro_rt->rt_ifp), ifnet_unit(ro->ro_rt->rt_ifp),
           ip_print(&((struct sockaddr_in *)&ro->ro_rt->rt_gateway)->sin_addr));
#endif
    
	return err;
}

static int gre_rtdel(ifnet_t ifp, struct rtentry *rt)
{
	int err;
    
	if (rt && rt->rt_ifp == ifp) {
		/*
		 * Protect (sorta) against walktree recursion problems
		 * with cloned routes
		 */
		if ((rt->rt_flags & RTF_UP) == 0)
			return 0;
        
		err = rtrequest_locked(RTM_DELETE, rt_key(rt), rt->rt_gateway,
                               rt_mask(rt), rt->rt_flags,
                               (struct rtentry **) NULL);
		if (err) {
			printf("%s: error %d\n", __FUNCTION__, err);
		}
	}
    
	return (0);
}
#endif

#ifdef DEBUG
unsigned int get_ngre() {
    return ngre;
}
#endif
