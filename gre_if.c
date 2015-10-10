/*-
 * Copyright (c) 1998 The NetBSD Foundation, Inc.
 * Copyright (c) 2014 Andrey V. Elsukov <ae@FreeBSD.org>
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
 * $NetBSD: if_gre.c,v 1.49 2003/12/11 00:22:29 itojun Exp $
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

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/kpi_ipfilter.h>

#include "kernel_build.h"
#include "gre_locks.h"
#include "gre_ip_encap.h"
#include "gre_if.h"


/*
 * It is not easy to calculate the right value for a GRE MTU.
 * We leave this task to the admin and use the same default that
 * other vendors use.
 */
#define GREMTU      1500
#define GRE_MIN_MTU 576
#define GRENAME     "gre"
#define GRE_MAXUNIT	0x7fff	/* ifp->if_unit is only 15 bits(short int) */
#define GRE_CONTROL_NAME "org.gmshake.nke.gre_control"


// FIXME:
#if defined(M_DEVBUF)
#define M_GRE M_DEVBUF
#else
#define M_GRE M_TEMP
#endif

static struct   gre_softc * gre_sc_allocate(u_int32_t);
static void     gre_sc_free(struct gre_softc *);
static errno_t  gre_attach_proto_family(ifnet_t, protocol_family_t);
static void     gre_detach_proto_family(ifnet_t, protocol_family_t);
static errno_t  gre_add_proto(ifnet_t, protocol_family_t,
			      const struct ifnet_demux_desc *, u_int32_t);
static errno_t  gre_del_proto(ifnet_t, protocol_family_t);

static errno_t  gre_ioctl(ifnet_t, unsigned long, void *);
static int      gre_set_tunnel(ifnet_t, struct sockaddr *, struct sockaddr *);
static void     gre_delete_tunnel(ifnet_t);

static void     gre_if_detached(ifnet_t);

static int      gre_demux(ifnet_t, mbuf_t, char *, protocol_family_t *);
static errno_t  gre_media_input(ifnet_t, protocol_family_t, mbuf_t, char *);

static errno_t  gre_pre_output(ifnet_t, protocol_family_t, mbuf_t *,
			       const struct sockaddr *, void *, char *, char *);
static errno_t  gre_output(ifnet_t, mbuf_t);

static int      gre_check_nesting(ifnet_t, mbuf_t);


// sysctl
extern struct sysctl_oid sysctl__net_gre_ttl;
extern struct sysctl_oid sysctl__net_gre_hlim;

// vars
static lck_rw_t *gre_lck = NULL; // protect gre_softc_list
static lck_rw_t *gre_ioctl_sx = NULL; // protect gre_ioctl

static LIST_HEAD(, gre_softc) gre_softc_list;
static volatile SInt32 ngre = 0;       /* number of interfaces */

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

static int max_gre_nesting = 1;


SYSCTL_NODE(_net, OID_AUTO, gre, CTLFLAG_RW | CTLFLAG_LOCKED, 0, "Generic Routing Encapsulation");
SYSCTL_INT(_net_gre, OID_AUTO, max_nesting, CTLTYPE_INT | CTLFLAG_RW, &max_gre_nesting, 0, "Max nested tunnels");


inline void
gre_sc_reference(struct gre_softc *sc)
{
#ifdef DEBUG
	if (sc == NULL) {
		printf("%s: invalid sc(NULL)\n", __FUNCTION__);
		return;
	}
#endif
	OSIncrementAtomic(&sc->sc_refcnt);
}

inline SInt32
gre_sc_release(struct gre_softc *sc)
{
#ifdef DEBUG
	if (sc == NULL) {
		printf("%s: invalid sc(NULL) should panic\n", __FUNCTION__);
		return -1;
	}
#endif
	SInt32 oldval = OSDecrementAtomic(&sc->sc_refcnt);
	if (oldval == 1) { // now refcnt reach 0, free safely
		gre_sc_free(sc);
	}

	return oldval - 1;
}


/* register INET and INET6 protocol families */
int
gre_proto_register(void)
{
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


#ifdef DEBUG
	printf("%s: done\n", __FUNCTION__);
#endif

	return 0;

fail:
	return -1;
}


/* unregister INET and INET6 protocol families */
void
gre_proto_unregister(void)
{
#ifdef DEBUG
	printf("%s ...\n", __FUNCTION__);
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


int
gre_if_init(void)
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

	gre_lck = lck_rw_alloc_init(gre_lck_grp, gre_lck_attributes);
	if (gre_lck == NULL) {
#ifdef DEBUG
		printf("%s: faild, not enough mem???\n", __FUNCTION__);
#endif
		goto failed;
	}

	gre_ioctl_sx = lck_rw_alloc_init(gre_lck_grp, gre_lck_attributes);
	if (gre_ioctl_sx == NULL) {
#ifdef DEBUG
		printf("%s: faild, not enough mem???\n", __FUNCTION__);
#endif
		lck_rw_free(gre_lck, gre_lck_grp);
		goto failed;
	}

	LIST_INIT(&gre_softc_list);

	sysctl_register_oid(&sysctl__net_gre);
	sysctl_register_oid(&sysctl__net_gre_max_nesting);
	sysctl_register_oid(&sysctl__net_gre_ttl);
	sysctl_register_oid(&sysctl__net_gre_hlim);

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


int
gre_if_dispose(void)
{
#ifdef DEBUG
	printf("%s ...\n", __FUNCTION__);
#endif

	if (gre_lck == NULL) {
		goto success;
	}

	/* check if any interface are in use or any resources has not been freed */
	int busy = 0;
	struct gre_softc *sc, *tp_sc;

	lck_rw_lock_exclusive(gre_lck);
	LIST_FOREACH(sc, &gre_softc_list, gre_list) {
		if (sc->sc_refcnt > 1)
			busy++;
	}
	if (busy > 0) {
		lck_rw_unlock_exclusive(gre_lck);
#ifdef DEBUG
		printf("%s: resouces busy, please try later\n", __FUNCTION__);
#endif
		goto ebusy;
	}

	// safe to dispose
	LIST_FOREACH_SAFE(sc, &gre_softc_list, gre_list, tp_sc) {
		LIST_REMOVE(sc, gre_list);
		gre_sc_release(sc);
	}
	lck_rw_unlock_exclusive(gre_lck);


	sysctl_unregister_oid(&sysctl__net_gre_hlim);
	sysctl_unregister_oid(&sysctl__net_gre_ttl);
	sysctl_unregister_oid(&sysctl__net_gre_max_nesting);
	sysctl_unregister_oid(&sysctl__net_gre);

	lck_rw_free(gre_ioctl_sx, gre_lck_grp);
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

ebusy:
#ifdef DEBUG
	printf("%s: fail\n", __FUNCTION__);
#endif
	return EBUSY;
}


/*
 * gre_if_attach(), attach a new interface
 */
int
gre_if_attach(void)
{
	struct gre_softc *sc;

	lck_rw_lock_shared(gre_lck);
	/* Check for unused gre interface */
	LIST_FOREACH(sc, &gre_softc_list, gre_list) {
		/* If unused, return, no need to create a new interface */
		if (sc->gre_ifp && (ifnet_flags(sc->gre_ifp) & IFF_RUNNING) == 0) {
			lck_rw_unlock_shared(gre_lck);
			return 0;
		}
	}
	lck_rw_unlock_shared(gre_lck);

	// if reach max unit number
	SInt32 unit;
	if ((unit = OSIncrementAtomic(&ngre)) >= GRE_MAXUNIT) {
		OSDecrementAtomic(&ngre);
		return ENXIO;
	}

	// FIXME: find usable ifnet unit
	sc = gre_sc_allocate(unit);
	if (sc == NULL) {
		OSDecrementAtomic(&ngre);
		return ENOMEM;
	}

	gre_sc_reference(sc); // retain
	lck_rw_lock_exclusive(gre_lck);
	LIST_INSERT_HEAD(&gre_softc_list, sc, gre_list);
	lck_rw_unlock_exclusive(gre_lck);

	return 0;
}


static errno_t
gre_remove_address(ifnet_t ifp, protocol_family_t af, ifaddr_t addr, socket_t socket)
{
	errno_t result = EPROTONOSUPPORT;

	/* Attempt a detach */
	if (af == PF_INET) {
		struct ifreq ifr;

		bzero(&ifr, sizeof(ifr));
		snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s%d", ifnet_name(ifp), ifnet_unit(ifp));

		result = ifaddr_address(addr, &ifr.ifr_addr, sizeof(ifr.ifr_addr));
		if (result == 0) {
			result = sock_ioctl(socket, SIOCDIFADDR, &ifr);
			if (result != 0)
				printf("%s - SIOCDIFADDR failed: %d", __FUNCTION__, result);

		} else
			printf("%s - ifaddr_address failed: %d", __FUNCTION__, result);


	} else if (af == PF_INET6) {
		struct in6_ifreq ifr6;

		bzero(&ifr6, sizeof(ifr6));
		snprintf(ifr6.ifr_name, sizeof(ifr6.ifr_name), "%s%d", ifnet_name(ifp), ifnet_unit(ifp));

		result = ifaddr_address(addr, (struct sockaddr*)&ifr6.ifr_addr, sizeof(ifr6.ifr_addr));
		if (result == 0) {
			result = sock_ioctl(socket, SIOCDIFADDR_IN6, &ifr6);
			if (result != 0)
				printf("%s - SIOCDIFADDR_IN6 failed: %d", __FUNCTION__, result);

		} else
			printf("%s - ifaddr_address failed: %d", __FUNCTION__, result);

	}

	return result;
}


static void
gre_cleanup_family(ifnet_t ifp, protocol_family_t af)
{
#ifdef DEBUG
	printf("%s (%s%d, %d) ...\n", __FUNCTION__, ifnet_name(ifp), ifnet_unit(ifp), af);
#endif
	errno_t err = 0;
	socket_t sock;
	ifaddr_t *addrs;

	if (af != PF_INET && af != PF_INET6) {
		printf("%s: invalid protocol family %d\n", __FUNCTION__, af);
		return;
	}

	/* Create a socket for removing addresses and detaching the protocol */
	err = sock_socket(af, SOCK_DGRAM, 0, NULL, NULL, &sock);
	if (err != 0) {
		if (err != EAFNOSUPPORT)
			printf("%s: failed to create %s socket: %d\n", __FUNCTION__,
			       af == PF_INET ? "IP" : "IPv6", err);
		goto cleanup;
	}

	err = ifnet_get_address_list_family(ifp, &addrs, af);
	if (err != 0) {
		if (err != ENXIO)
			printf("%s: ifnet_get_address_list_family(%s%d, %p, %s) - failed: %d\n",
			       __FUNCTION__, ifnet_name(ifp), ifnet_unit(ifp), &addrs,
			       af == PF_INET ? "PF_INET" : "PF_INET6", err);
		goto cleanup;
	}

	for (int i = 0; addrs[i] != NULL; i++) {
		gre_remove_address(ifp, af, addrs[i], sock);
	}
	ifnet_free_address_list(addrs);

cleanup:
	if (sock != NULL)
		sock_close(sock);
#ifdef DEBUG
	printf("%s (%s%d, %d) done\n", __FUNCTION__, ifnet_name(ifp), ifnet_unit(ifp), af);
#endif
}


static struct gre_softc *
gre_sc_allocate(u_int32_t unit)
{
	struct gre_softc * sc;

	sc = (struct gre_softc *) _MALLOC(sizeof(struct gre_softc), M_GRE, M_WAITOK | M_ZERO);
	if (sc == NULL) // SHOULD NOT HAPPEN since M_WAITOK
		return NULL;

	sc->gre_lock = lck_rw_alloc_init(gre_sc_lck_grp, gre_sc_lck_attributes);
	if (sc->gre_lock == NULL) {
		_FREE(sc, M_GRE);
		return NULL;
	}

	sc->detach_mtx = lck_mtx_alloc_init(gre_sc_lck_grp, gre_sc_lck_attributes);
	if (sc->detach_mtx == NULL) {
		lck_rw_free(sc->gre_lock, gre_sc_lck_grp);
		_FREE(sc, M_GRE);
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
	init.softc = sc;
	init.ioctl = gre_ioctl;
	init.detach = gre_if_detached;

	errno_t err = ifnet_allocate(&init, &sc->gre_ifp);
	if (err) {
		lck_rw_free(sc->gre_lock, gre_sc_lck_grp);
		lck_mtx_free(sc->detach_mtx, gre_sc_lck_grp);
		_FREE(sc, M_GRE);

		printf("%s: ifnet_allocate() failed - %d\n", __FUNCTION__, err);
		return NULL;
	}

	sc->gre_mtu = GREMTU;
	sc->gre_hlen = sizeof(struct greip);

	ifnet_t ifp = sc->gre_ifp;

	ifnet_set_addrlen(ifp, 0);
	ifnet_set_mtu(ifp, sc->gre_mtu - sc->gre_hlen);
	ifnet_set_hdrlen(ifp, sc->gre_hlen);
	ifnet_set_flags(ifp, IFF_POINTOPOINT | IFF_MULTICAST, 0xffff);

	// reset the status in case as the interface may has been recycled
	struct ifnet_stats_param param;
	bzero(&param, sizeof(param));
	ifnet_set_stat(ifp, &param);

	ifnet_touch_lastchange(ifp);


	err = ifnet_attach(ifp, NULL);
	if (err) {
		printf("%s: ifnet_attach() failed - %d\n", __FUNCTION__, err);
		ifnet_release(ifp);

		lck_rw_free(sc->gre_lock, gre_sc_lck_grp);
		lck_mtx_free(sc->detach_mtx, gre_sc_lck_grp);
		_FREE(sc, M_GRE);

		return NULL;
	}

	bpfattach(ifp, DLT_NULL, sizeof(u_int32_t));

#ifdef DEBUG
	printf("%s: %s%d sc -> %p, ifp -> %p\n", __FUNCTION__, GRENAME, unit, sc, ifp);
#endif
	return sc;
}


static void
gre_sc_free(struct gre_softc *sc)
{
#ifdef DEBUG
	printf("%s ...\n", __FUNCTION__);

	if (sc == NULL || sc->gre_ifp == NULL) {
		// Should panic
		printf("%s: invalid parameters: sc = %p, sc->sc_ifp = %p, should panic!!!\n", __FUNCTION__, sc, sc == NULL ? NULL : sc->gre_ifp);
		return;
	}
#endif

	ifnet_t ifp = sc->gre_ifp;

	sx_xlock(gre_ioctl_sx);
	gre_delete_tunnel(ifp);
	sx_xunlock(gre_ioctl_sx);

	// mark interface down
	ifnet_set_flags(ifp, 0, IFF_UP);

	// clean up
	gre_cleanup_family(ifp, PF_INET6);
	gre_cleanup_family(ifp, PF_INET);

	//ifnet_detach_protocol(ifp, PF_INET6);
	//ifnet_detach_protocol(ifp, PF_INET);

	gre_detach_proto_family(ifp, PF_INET6);
	gre_detach_proto_family(ifp, PF_INET);

	lck_mtx_lock(sc->detach_mtx);
	sc->is_detaching = 1;
	lck_mtx_unlock(sc->detach_mtx);

#ifdef DEBUG
	printf("%s: ifnet_detach(%s%d) ...\n", __FUNCTION__, ifnet_name(ifp), ifnet_unit(ifp));
#endif
	errno_t err = ifnet_detach(ifp);
#ifdef DEBUG
	printf("%s: ifnet_detach(%s%d) ret -> %d\n", __FUNCTION__, ifnet_name(ifp), ifnet_unit(ifp), err);
#endif
	if (err) { // maybe it has already been detached
		printf("%s: ifnet_detach %s%d error: %d\n", __FUNCTION__, ifnet_name(ifp), ifnet_unit(ifp), err);

		lck_mtx_lock(sc->detach_mtx);
		sc->is_detaching = 0;
		lck_mtx_unlock(sc->detach_mtx);
	} else { // err == 0
		int max_cnt = 10;
		do {
			lck_mtx_lock(sc->detach_mtx);
			if (sc->is_detaching) {
				/* interface release is in progress, wait for callback */
#ifdef DEBUG
				printf("%s: detaching is in progress...\n", __FUNCTION__);
#endif
				struct timespec tv;
				bzero(&tv, sizeof(tv));
				tv.tv_sec = 0;
				tv.tv_nsec = NSEC_PER_SEC / 5; // 200ms

				msleep(&sc->is_detaching, sc->detach_mtx, PDROP, "gre_sc_free", &tv);  // sc->mtx will be unlocked by msleep
			} else {
				lck_mtx_unlock(sc->detach_mtx);
				break;
			}
		} while (--max_cnt > 0);
	}

	if (sc->is_detaching) {
		printf("%s: detach %s%d failed, continue, mem leaks\n", __FUNCTION__, ifnet_name(ifp), ifnet_unit(ifp));
		return;
	}

	// now it's safe to release
	ifnet_release(ifp);

	lck_rw_free(sc->gre_lock, gre_sc_lck_grp);
	lck_mtx_free(sc->detach_mtx, gre_sc_lck_grp);

	_FREE(sc, M_GRE);

	OSDecrementAtomic(&ngre);

#ifdef DEBUG
	printf("%s: done\n", __FUNCTION__);
#endif
}


/*
 * gre_if_detached() is called when ifp detaching is done,
 * then it is safe to call ifnet_release()
 */
static void
gre_if_detached(ifnet_t ifp)
{
#ifdef DEBUG
	printf("%s: %s%d ...\n", __FUNCTION__, ifnet_name(ifp), ifnet_unit(ifp));
#endif
	struct gre_softc *sc = ifnet_softc(ifp);
	lck_mtx_lock(sc->detach_mtx);
	if (sc->is_detaching) {
		sc->is_detaching = 0;
		wakeup(&sc->is_detaching);
	}
	lck_mtx_unlock(sc->detach_mtx);

#ifdef DEBUG
	printf("%s: detach done\n", __FUNCTION__);
#endif
}


/* attach inet/inet6 to a GRE interface through DLIL */
static errno_t
gre_attach_proto_family(ifnet_t ifp, protocol_family_t protocol_family)
{
#ifdef DEBUG
	printf("%s: fam=0x%x\n", __FUNCTION__, protocol_family);
#endif
	struct ifnet_attach_proto_param proto;
	errno_t err;

	bzero(&proto, sizeof(proto));
	proto.input = gre_media_input;
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


static void
gre_detach_proto_family(ifnet_t ifp, protocol_family_t protocol)
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
		printf("%s: ifnet_detach_protocol(), %s%d with proto: 0x%x, error = %s\n", __FUNCTION__, ifnet_name(ifp), ifnet_unit(ifp), protocol, err == ENOENT ? "ENOENT" : "ENXIO");

	printf("%s: fam=0x%x done\n", __FUNCTION__, protocol);
#endif
}


/*
 * is called by the stack when a protocol is attached to gre interface.
 */
static errno_t
gre_add_proto(ifnet_t ifp, protocol_family_t protocol,
	      const struct ifnet_demux_desc *demux_array, u_int32_t demux_count)
{
	switch (protocol) {
		case AF_INET:
		case AF_INET6:
			break;
		default:
			return ENOPROTOOPT; // happen for unknown protocol, or for empty descriptor
	}
#ifdef DEBUG
	printf("%s: add proto 0x%x for %s%d\n", __FUNCTION__, protocol,
	       ifnet_name(ifp), ifnet_unit(ifp));
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
	printf("%s: del proto %d for %s%d\n", __FUNCTION__, protocol, ifnet_name(ifp), ifnet_unit(ifp));
#endif
	switch (protocol) {
		case AF_INET:
		case AF_INET6:
			break;
		default:
			return EINVAL;    // happen for unknown protocol, or for empty descriptor
	}
	return 0;
}


static void
gre_updatehdr(struct gre_softc *sc)
{
	struct grehdr *gh = NULL;
	uint32_t *opts;
	uint16_t flags;

	switch (sc->gre_family) {
		case AF_INET:
			sc->gre_hlen = sizeof(struct greip);
			sc->gre_oip.ip_v = IPPROTO_IPV4;
			sc->gre_oip.ip_hl = sizeof(struct ip) >> 2;
			sc->gre_oip.ip_p = IPPROTO_GRE;
			gh = &sc->gre_gihdr->gi_gre;
			break;
		case AF_INET6:
			sc->gre_hlen = sizeof(struct greip6);
			sc->gre_oip6.ip6_vfc = IPV6_VERSION;
			sc->gre_oip6.ip6_nxt = IPPROTO_GRE;
			gh = &sc->gre_gi6hdr->gi6_gre;
			break;
		default:
			return;
	}
	flags = 0;
	opts = gh->gre_opts;
	if (sc->gre_options & GRE_ENABLE_CSUM) {
		flags |= GRE_FLAGS_CP;
		sc->gre_hlen += 2 * sizeof(uint16_t);
		*opts++ = 0;
	}
	if (sc->gre_key != 0) {
		flags |= GRE_FLAGS_KP;
		sc->gre_hlen += sizeof(uint32_t);
		*opts++ = htonl(sc->gre_key);
	}
	if (sc->gre_options & GRE_ENABLE_SEQ) {
		flags |= GRE_FLAGS_SP;
		sc->gre_hlen += sizeof(uint32_t);
		*opts++ = 0;
	} else
		sc->gre_oseq = 0;
	gh->gre_flags = htons(flags);
	//GRE2IFP(sc)->if_mtu = sc->gre_mtu - sc->gre_hlen;
	ifnet_set_mtu(sc->gre_ifp, sc->gre_mtu - sc->gre_hlen);
	ifnet_set_hdrlen(sc->gre_ifp, sc->gre_hlen);
}


/*
 * communicate ioctls from the stack to the driver.
 */
static errno_t
gre_ioctl(ifnet_t ifp, unsigned long cmd, void *data)
{
	struct ifreq *ifr = (struct ifreq *)data;
	struct sockaddr *src, *dst;
	struct gre_softc *sc;

	struct sockaddr_in *sin = NULL;
	struct sockaddr_in6 *sin6 = NULL;

	uint32_t opt;
	errno_t error = 0;

#ifdef DEBUG
	printf("%s: %s%d cmd -> %lu, data -> %p\n", __FUNCTION__, ifnet_name(ifp), ifnet_unit(ifp), cmd & 0xff, data);
#endif

	switch (cmd) {
		case SIOCSIFMTU:
			if (ifr->ifr_mtu < GRE_MIN_MTU || ifr->ifr_mtu > IF_MAXMTU)
				return EINVAL;
			break;
		case SIOCSIFADDR:
			ifnet_set_flags(ifp, IFF_UP, IFF_UP);
		case SIOCSIFFLAGS:
		case SIOCADDMULTI:
		case SIOCDELMULTI:
			return 0;
		case GRESADDRS:
		case GRESADDRD:
		case GREGADDRS:
		case GREGADDRD:
		case GRESPROTO:
		case GREGPROTO:
			return EOPNOTSUPP;
	}

	src = dst = NULL;
	sx_xlock(gre_ioctl_sx);
	sc = ifnet_softc(ifp);
	if (sc == NULL) {
		error = ENXIO;
		goto end;
	}
	error = 0;
	switch (cmd) {
		case SIOCSIFMTU:
			GRE_WLOCK(sc);
			sc->gre_mtu = ifr->ifr_mtu;
			gre_updatehdr(sc);
			GRE_WUNLOCK(sc);
			goto end;
		case SIOCSIFPHYADDR:
		case SIOCSIFPHYADDR_IN6:

			error = EINVAL;
			switch (cmd) {
				case SIOCSIFPHYADDR:
					src = (struct sockaddr *) \
					&(((struct in_aliasreq *)data)->ifra_addr);
					dst = (struct sockaddr *) \
					&(((struct in_aliasreq *)data)->ifra_dstaddr);
					break;
				case SIOCSIFPHYADDR_IN6:
					src = (struct sockaddr *) \
					&(((struct in6_aliasreq *)data)->ifra_addr);
					dst = (struct sockaddr *) \
					&(((struct in6_aliasreq *)data)->ifra_dstaddr);
					break;
				default:
					error = EAFNOSUPPORT;
					break;
			}

			/* sa_family must be equal */
			if (src->sa_family != dst->sa_family || \
			    src->sa_len != dst->sa_len)
				goto end;

			/* validate sa_len */
			switch (src->sa_family) {
				case AF_INET:
					if (src->sa_len != sizeof(struct sockaddr_in))
						goto end;
					break;
				case AF_INET6:
					if (src->sa_len != sizeof(struct sockaddr_in6))
						goto end;
					break;
				default:
					error = EAFNOSUPPORT;
					goto end;
			}

			/* check sa_family looks sane for the cmd */
			error = EAFNOSUPPORT;
			switch (cmd) {
				case SIOCSIFPHYADDR:
					if (src->sa_family == AF_INET)
						break;
					goto end;
				case SIOCSIFPHYADDR_IN6:
					if (src->sa_family == AF_INET6)
						break;
					goto end;
			}
			error = EADDRNOTAVAIL;
			switch (src->sa_family) {
				case AF_INET:
					if (satosin(src)->sin_addr.s_addr == INADDR_ANY ||
					    satosin(dst)->sin_addr.s_addr == INADDR_ANY)
						goto end;
					break;
				case AF_INET6:
					if (IN6_IS_ADDR_UNSPECIFIED(&satosin6(src)->sin6_addr)
					    ||
					    IN6_IS_ADDR_UNSPECIFIED(&satosin6(dst)->sin6_addr))
						goto end;
					/*
					 * Check validity of the scope zone ID of the
					 * addresses, and convert it into the kernel
					 * internal form if necessary.
					 */
					//                    error = sa6_embedscope(satosin6(src), 0);
					//                    if (error != 0)
					//                        goto end;
					//                    error = sa6_embedscope(satosin6(dst), 0);
					//                    if (error != 0)
					//                        goto end;
			};
			error = gre_set_tunnel(ifp, src, dst);
			break;
		case SIOCDIFPHYADDR:
			gre_delete_tunnel(ifp);
			break;
		case SIOCGIFPSRCADDR:
		case SIOCGIFPDSTADDR:
		case SIOCGIFPSRCADDR_IN6:
		case SIOCGIFPDSTADDR_IN6:
			if (sc->gre_family == 0) {
				error = EADDRNOTAVAIL;
				break;
			}
			GRE_RLOCK(sc);
			switch (cmd) {
				case SIOCGIFPSRCADDR:
				case SIOCGIFPDSTADDR:
					if (sc->gre_family != AF_INET) {
						error = EADDRNOTAVAIL;
						break;
					}
					sin = (struct sockaddr_in *)&ifr->ifr_addr;
					bzero(sin, sizeof(*sin));
					sin->sin_family = AF_INET;
					sin->sin_len = sizeof(*sin);
					break;
				case SIOCGIFPSRCADDR_IN6:
				case SIOCGIFPDSTADDR_IN6:
					if (sc->gre_family != AF_INET6) {
						error = EADDRNOTAVAIL;
						break;
					}
					sin6 = (struct sockaddr_in6 *)
					&(((struct in6_ifreq *)data)->ifr_addr);
					bzero(sin6, sizeof(*sin6));
					sin6->sin6_family = AF_INET6;
					sin6->sin6_len = sizeof(*sin6);
					break;
			}
			if (error == 0) {
				switch (cmd) {
					case SIOCGIFPSRCADDR:
						sin->sin_addr = sc->gre_oip.ip_src;
						break;
					case SIOCGIFPDSTADDR:
						sin->sin_addr = sc->gre_oip.ip_dst;
						break;
					case SIOCGIFPSRCADDR_IN6:
						sin6->sin6_addr = sc->gre_oip6.ip6_src;
						break;
					case SIOCGIFPDSTADDR_IN6:
						sin6->sin6_addr = sc->gre_oip6.ip6_dst;
						break;
				}
			}
			GRE_RUNLOCK(sc);
			if (error != 0)
				break;
			switch (cmd) {
				case SIOCGIFPSRCADDR:
				case SIOCGIFPDSTADDR:
					//                    error = prison_if(curthread->td_ucred,
					//                                      (struct sockaddr *)sin);
					if (error != 0)
						bzero(sin, sizeof(*sin));
					break;
				case SIOCGIFPSRCADDR_IN6:
				case SIOCGIFPDSTADDR_IN6:
					//                    error = prison_if(curthread->td_ucred,
					//                                      (struct sockaddr *)sin6);
					//                    if (error == 0)
					//                        error = sa6_recoverscope(sin6);
					if (error != 0)
						bzero(sin6, sizeof(*sin6));
			}
			break;
			//        case SIOCGTUNFIB:
			//            ifr->ifr_fib = sc->gre_fibnum;
			//            break;
			//        case SIOCSTUNFIB:
			//            if ((error = priv_check(curthread, PRIV_NET_GRE)) != 0)
			//                break;
			//            if (ifr->ifr_fib >= rt_numfibs)
			//                error = EINVAL;
			//            else
			//                sc->gre_fibnum = ifr->ifr_fib;
			//            break;
		case GRESKEY:
			//            if ((error = priv_check(curthread, PRIV_NET_GRE)) != 0)
			//                break;
			if ((error = copyin(ifr->ifr_data, &opt, sizeof(opt))) != 0)
				break;
			if (sc->gre_key != opt) {
				GRE_WLOCK(sc);
				sc->gre_key = opt;
				gre_updatehdr(sc);
				GRE_WUNLOCK(sc);
			}
			break;
		case GREGKEY:
			error = copyout(&sc->gre_key, ifr->ifr_data,
					sizeof(sc->gre_key));
			break;
		case GRESOPTS:
			//            if ((error = priv_check(curthread, PRIV_NET_GRE)) != 0)
			//                break;
			if ((error = copyin(ifr->ifr_data, &opt, sizeof(opt))) != 0)
				break;
			if (opt & ~GRE_OPTMASK)
				error = EINVAL;
			else {
				if (sc->gre_options != opt) {
					GRE_WLOCK(sc);
					sc->gre_options = opt;
					gre_updatehdr(sc);
					GRE_WUNLOCK(sc);
				}
			}
			break;

		case GREGOPTS:
			error = copyout(&sc->gre_options, ifr->ifr_data,
					sizeof(sc->gre_options));
			break;
		default:
			//error = EINVAL;
			error = EOPNOTSUPP; // HACK: darwin use EOPNOTSUPP
			break;
	}
end:
	sx_xunlock(gre_ioctl_sx);
#ifdef DEBUG
	printf("%s: error -> %d\n", __FUNCTION__, error);
#endif
	return error;
}


static void
gre_detach(struct gre_softc *sc)
{
	sx_assert(&gre_ioctl_sx, SA_XLOCKED);
	if (sc->gre_ecookie != NULL)
		gre_encap_detach(sc->gre_ecookie);
	sc->gre_ecookie = NULL;
}


static int
gre_set_tunnel(ifnet_t ifp, struct sockaddr *src, struct sockaddr *dst)
{
	struct gre_softc *sc, *tsc;
	struct ip6_hdr *ip6;
	struct ip *ip;
	void *hdr;
	int error;

	sx_assert(&gre_ioctl_sx, SA_XLOCKED);
	lck_rw_lock_shared(gre_lck);
	sc = ifnet_softc(ifp);
	LIST_FOREACH(tsc, &gre_softc_list, gre_list) {
		if (tsc == sc || tsc->gre_family != src->sa_family)
			continue;
		if (tsc->gre_family == AF_INET &&
		    tsc->gre_oip.ip_src.s_addr ==
		    satosin(src)->sin_addr.s_addr &&
		    tsc->gre_oip.ip_dst.s_addr ==
		    satosin(dst)->sin_addr.s_addr) {
			lck_rw_unlock_shared(gre_lck);
			return (EADDRNOTAVAIL);
		}
		if (tsc->gre_family == AF_INET6 &&
		    IN6_ARE_ADDR_EQUAL(&tsc->gre_oip6.ip6_src,
				       &satosin6(src)->sin6_addr) &&
		    IN6_ARE_ADDR_EQUAL(&tsc->gre_oip6.ip6_dst,
				       &satosin6(dst)->sin6_addr)) {
			    lck_rw_unlock_shared(gre_lck);
			    return (EADDRNOTAVAIL);
		    }
	}
	lck_rw_unlock_shared(gre_lck);

	switch (src->sa_family) {
		case AF_INET:
			hdr = ip = _MALLOC(sizeof(struct greip) +
					   3 * sizeof(uint32_t), M_GRE, M_WAITOK | M_ZERO);
			ip->ip_src = satosin(src)->sin_addr;
			ip->ip_dst = satosin(dst)->sin_addr;
			break;
		case AF_INET6:
			hdr = ip6 = _MALLOC(sizeof(struct greip6) +
					    3 * sizeof(uint32_t), M_GRE, M_WAITOK | M_ZERO);
			ip6->ip6_src = satosin6(src)->sin6_addr;
			ip6->ip6_dst = satosin6(dst)->sin6_addr;
			break;
		default:
			return (EAFNOSUPPORT);
	}
	if (sc->gre_family != 0)
		gre_detach(sc);

	GRE_WLOCK(sc);
	if (sc->gre_family != 0)
		_FREE(sc->gre_hdr, M_GRE);

	sc->gre_family = src->sa_family;
	sc->gre_hdr = hdr;
	sc->gre_oseq = 0;
	sc->gre_iseq = UINT32_MAX;
	gre_updatehdr(sc);
	GRE_WUNLOCK(sc);


	error = 0;
	switch (src->sa_family) {
		case AF_INET:
			error = in_gre_attach(sc);
			break;
		case AF_INET6:
			error = in6_gre_attach(sc);
			break;
	}
	if (error == 0)
		ifnet_set_flags(ifp, IFF_RUNNING, IFF_RUNNING);

	//HACK: here we ensure there is always one more GRE interface that is available
	gre_if_attach();

	return error;
}



static void
gre_delete_tunnel(ifnet_t ifp)
{
	struct gre_softc *sc = ifnet_softc(ifp);
	int family;

	GRE_WLOCK(sc);
	family = sc->gre_family;
	sc->gre_family = 0;
	GRE_WUNLOCK(sc);
	if (family != 0) {
		gre_detach(sc);
		_FREE(sc->gre_hdr, M_GRE);
	}
	ifnet_set_flags(ifp, 0, IFF_RUNNING);
}


void
gre_input(mbuf_t *mp, int *offp, int proto, void *arg)
{
	struct gre_softc *sc;
	struct grehdr *gh;
	ifnet_t ifp;
	mbuf_t m;
	uint32_t *opts, key;
	uint16_t flags;
	int hlen;
	uint32_t af;

	m = *mp;
//	sc = gre_encap_getarg(m); // HACK: we use arg directly
//	if (sc == NULL) {
//#ifdef DEBUG
//		printf("%s sc is NULL, drop\n", __FUNCTION__);
//#endif
//		goto drop1;
//	}
	sc = (struct gre_softc *)arg;

	ifp = sc->gre_ifp;
	gh = (struct grehdr *)mtodo(m, *offp);
	flags = ntohs(gh->gre_flags);
	if (flags & ~GRE_FLAGS_MASK)
		goto drop;
	opts = gh->gre_opts;
	hlen = 2 * sizeof(uint16_t);
	if (flags & GRE_FLAGS_CP) {
		/* reserved1 field must be zero */
		if (((uint16_t *)opts)[1] != 0)
			goto drop;
		//if (in_cksum_skip(m, mbuf_pkthdr_len(m), *offp) != 0)
		//	goto drop;
		{
			uint16_t csum = 0;
			if (mbuf_inet_cksum(m, 0, *offp, mbuf_pkthdr_len(m) - (*offp), &csum)
			    || csum != 0)
				goto drop;
		}
		hlen += 2 * sizeof(uint16_t);
		opts++;
	}
	if (flags & GRE_FLAGS_KP) {
		key = ntohl(*opts);
		hlen += sizeof(uint32_t);
		opts++;
	} else
		key = 0;
	/*
	 if (sc->gre_key != 0 && (key != sc->gre_key || key != 0))
	 goto drop;
	 */
	if (flags & GRE_FLAGS_SP) {
		/* seq = ntohl(*opts); */
		hlen += sizeof(uint32_t);
	}
	switch (ntohs(gh->gre_proto)) {
		case ETHERTYPE_WCCP:
			/*
			 * For WCCP skip an additional 4 bytes if after GRE header
			 * doesn't follow an IP header.
			 */
			if (flags == 0 && (*(uint8_t *)gh->gre_opts & 0xF0) != 0x40)
				hlen += sizeof(uint32_t);
			/* FALLTHROUGH */
		case ETHERTYPE_IP:
			//isr = NETISR_IP;
			af = AF_INET;
			break;
		case ETHERTYPE_IPV6:
			//isr = NETISR_IPV6;
			af = AF_INET6;
			break;
		default:
			goto drop;
	}
	// FIXME: check hlen > mbuf_pkthdr_len(m) ?
	if (hlen > mbuf_pkthdr_len(m)) { /* not a valid GRE packet */
		goto drop;
	}

	m_adj(m, *offp + hlen);

	mbuf_pkthdr_setrcvif(m, ifp);
	// FIXME: need set header??
#ifdef DEBUG
	void *ori_header = mbuf_pkthdr_header(m);
#endif
	mbuf_pkthdr_setheader(m, NULL);

	bpf_tap_in(ifp, DLT_NULL, m, &af, sizeof(af));

	struct ifnet_stat_increment_param incs;
	bzero(&incs, sizeof(incs));
	incs.packets_in = 1;
	incs.bytes_in = mbuf_pkthdr_len(m);

#ifdef DEBUG
	printf("%s ifnet_input,  ori_header is %p ...\n", __FUNCTION__, ori_header);
#endif

	ifnet_input(ifp, m, &incs);

#ifdef DEBUG
	printf("%s ifnet_input OK\n", __FUNCTION__);
#endif
	return;
drop:
#ifdef DEBUG
	printf("%s drop packet ...\n", __FUNCTION__);
#endif
	ifnet_stat_increment_in(ifp, 0, 0, 1);
drop1:
	m_freem(m);
	return;
}

/*
 void
 gre_input10(mbuf_t m, int off)
 {
 int proto;

 proto = (mtod(m, struct ip *))->ip_p;
 gre_input(&m, &off, proto);
 }
 */


/*
 * return EJUSTRETURN if mbuf is freed in this function since our caller dlil_input_packet_list()
 * will free the mbuf if any error code returned
 */
static errno_t
gre_demux(ifnet_t ifp, mbuf_t m, char *frame_header, protocol_family_t *protocol)
{
#ifdef DEBUG
	printf("%s: %s%d, m: %p, fh: %p, p: %p\n", __FUNCTION__, ifnet_name(ifp), ifnet_unit(ifp), m, frame_header, protocol);
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
			case 4:
				*protocol = AF_INET;
				break;
			case 6:
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
 * gre_media_input is the input handler for IP and IPv6 attached to gre,
 * our caller dlil_ifproto_input() will free the mbuf chain if any
 * error except EJUSTRETURN is returned
 */
static errno_t
gre_media_input(__unused ifnet_t ifp, protocol_family_t protocol, mbuf_t m,
		__unused char *frame_header)
{
#ifdef DEBUG
	printf("%s: protocol: %d\n", __FUNCTION__, protocol);
#endif

	errno_t err = proto_input(protocol, m);
#ifdef DEBUG
	if (err)
		printf("%s: warnning: proto_input() error: 0x%x\n", __FUNCTION__, err);
#endif

	return err;
}


static errno_t
gre_pre_output(ifnet_t ifp,
	       protocol_family_t protocol,
	       mbuf_t *m0,
	       const struct sockaddr *dst,
	       __unused void *route,
	       __unused char *frame_type,
	       __unused char *link_layer_dest)
{
	uint32_t af;
	mbuf_t m;
	errno_t error;

	m = *m0;

	if ((ifnet_flags(ifp) & (IFF_UP | IFF_RUNNING)) != (IFF_UP | IFF_RUNNING)) {
		error = ENETDOWN;
		goto drop;
	}

	error = gre_check_nesting(ifp, m);
	if (error != 0)
		goto drop;

	// m->m_flags &= ~(M_BCAST|M_MCAST);
	mbuf_setflags_mask(m, 0, MBUF_BCAST | MBUF_MCAST);

	if (dst->sa_family == AF_UNSPEC)
		bcopy(dst->sa_data, &af, sizeof(af));
	else
		af = dst->sa_family;

	// HACK: /* save af for gre_output */
	mbuf_set_csum_performed(m, 0, af);


	bpf_tap_out(ifp, DLT_NULL, m, &af, sizeof(af));

#ifdef DEBUG
	printf("%s: done\n", __FUNCTION__);
#endif

	return 0;
drop:
	ifnet_stat_increment_out(ifp, 0, 0, 1);
	return error;
}


static void
gre_setseqn(struct grehdr *gh, uint32_t seq)
{
	uint32_t *opts;
	uint16_t flags;

	opts = gh->gre_opts;
	flags = ntohs(gh->gre_flags);
	KASSERT((flags & GRE_FLAGS_SP) != 0,
		("gre_setseqn called, but GRE_FLAGS_SP isn't set "));
	if (flags & GRE_FLAGS_CP)
		opts++;
	if (flags & GRE_FLAGS_KP)
		opts++;
	*opts = htonl(seq);
}


static errno_t
gre_output(ifnet_t ifp, mbuf_t m) //, struct sockaddr *dst)
{
	struct gre_softc *sc;
	struct grehdr *gh;
	uint32_t iaf, oaf, oseq;
	int error, hlen, olen, plen;
	int want_seq, want_csum;


	plen = 0;
	sc = ifnet_softc(ifp);
	if (sc == NULL) {
		error = ENETDOWN;
		m_freem(m);
		goto drop;
	}
	GRE_RLOCK(sc);
	if (sc->gre_family == 0) {
		GRE_RUNLOCK(sc);
		error = ENETDOWN;
		m_freem(m);
		goto drop;
	}

	// HACK: get af from checksum
	{
		mbuf_csum_request_flags_t csum_flag;
		u_int32_t csum_value;
		mbuf_get_csum_requested(m, &csum_flag, &csum_value);

		iaf = csum_value;
	}

	oaf = sc->gre_family;
	hlen = sc->gre_hlen;
	want_seq = (sc->gre_options & GRE_ENABLE_SEQ) != 0;
	if (want_seq)
		oseq = sc->gre_oseq++; /* XXX */
	else
		oseq = 0;		/* Make compiler happy. */
	want_csum = (sc->gre_options & GRE_ENABLE_CSUM) != 0;
	//M_SETFIB(m, sc->gre_fibnum);
	mbuf_prepend(&m, hlen, MBUF_DONTWAIT);
	if (m == NULL) {
		GRE_RUNLOCK(sc);
		error = ENOBUFS;
		goto drop;
	}
	bcopy(sc->gre_hdr, mtod(m, void *), hlen);
	GRE_RUNLOCK(sc);
	switch (oaf) {
		case AF_INET:
			olen = sizeof(struct ip);
			break;
		case AF_INET6:
			olen = sizeof(struct ip6_hdr);
			break;
		default:
			error = ENETDOWN;
			goto drop;
	}
	gh = (struct grehdr *)mtodo(m, olen);
	switch (iaf) {
		case AF_INET:
			gh->gre_proto = htons(ETHERTYPE_IP);
			break;
		case AF_INET6:
			gh->gre_proto = htons(ETHERTYPE_IPV6);
			break;
		default:
			error = ENETDOWN;
			goto drop;
	}
	if (want_seq)
		gre_setseqn(gh, oseq);
	if (want_csum) {
		//*(uint16_t *)gh->gre_opts = in_cksum_skip(m, mbuf_pkthdr_len(m), olen);
		mbuf_inet_cksum(m, 0, olen, mbuf_pkthdr_len(m) - olen, (uint16_t *)gh->gre_opts);
	}
	plen = mbuf_pkthdr_len(m) - hlen;
	switch (oaf) {
		case AF_INET:
			error = in_gre_output(m, iaf, hlen);
			break;
		case AF_INET6:
			error = in6_gre_output(m, iaf, hlen);
			break;
		default:
			m_freem(m);
			error = ENETDOWN;
	};

drop:
	ifnet_stat_increment_out(ifp, 1, plen, error ? 1 : 0);

#ifdef DEBUG
	printf("%s: error -> %d\n", __FUNCTION__, error);
#endif
	return error;
}


#define	MTAG_GRE gre_if_family
static int
gre_check_nesting(ifnet_t ifp, mbuf_t m)
{
	ifnet_t *data;
	int count;

	count = 1;
	data = NULL;

	int max_type = MIN(0x7fff, max_gre_nesting);
	int type = 0;
	for (; type <= max_type; type++) {

		size_t length = 0;
		mbuf_tag_find(m, MTAG_GRE, type, &length, (void**)&data);

		if (!data) // not found
			break;

		if (*data == ifp) {
			printf("%s%d: loop detected\n", ifnet_name(ifp), ifnet_unit(ifp));
			return EIO;
		}
		count++;
	}

	if (count > max_gre_nesting) {
		printf("%s%d: if_output recursively called too many times(%d)\n",\
		       ifnet_name(ifp), ifnet_unit(ifp), count);
		return EIO;
	}

	// HACK
	if (type > 0x7fff) {
		printf("%s%d: if_output no more mbuf_tag_type available\n",\
		       ifnet_name(ifp), ifnet_unit(ifp));
		return EIO;
	}

	mbuf_tag_allocate(m, MTAG_GRE, type, sizeof(ifnet_t), MBUF_DONTWAIT, (void**)&data);

	if (data == NULL)
		return ENOMEM;

	*data = ifp;
	return 0;
}
