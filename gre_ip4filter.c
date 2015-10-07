/*
 *  gre_ipfilter.c
 *  gre
 *
 *  Created by Summer Town on 11/30/10.
 *  Copyright 2010 __MyCompanyName__. All rights reserved.
 *
 */

#include <sys/systm.h>
#include <sys/kpi_mbuf.h>
//#include <sys/socket.h>

//#include <net/if.h>
//#include <net/ethernet.h>

//#include <netinet/in.h>
//#include <netinet/ip.h>
#include <netinet/kpi_ipfilter.h>

#include "gre_ipfilter.h"
#include "gre_locks.h"
#include "gre_if.h"
#include "gre_ip_encap.h"


static lck_mtx_t *gre_ip4f_mtx = NULL;
static ipfilter_t gre_ipv4filter = NULL;

static errno_t gre_ip4filter_attach(void);
static errno_t gre_ip4filter_detach(void);


/*
 * gre_ipfilter_init(), initialize resources required by ip filter
 */
errno_t
gre_ip4filter_init(void)
{
#ifdef DEBUG
    printf("%s ...\n", __FUNCTION__);
#endif

    if (gre_ip4f_mtx != NULL) {
#ifdef DEBUG
        printf("%s: gre_if4p_mtx already inited\n", __FUNCTION__);
#endif
        goto success;
    }

    gre_ip4f_mtx = lck_mtx_alloc_init(gre_ipf_lck_grp, gre_ipf_lck_attributes);

    if (gre_ip4f_mtx == NULL)
        goto failed;

    if (gre_ip4filter_attach()) {/* attach ip filter */
        lck_mtx_free(gre_ip4f_mtx, gre_ipf_lck_grp);
        gre_ip4f_mtx = NULL;
        goto failed;
    }

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

/*
 * gre_ipfilter_dispose(), the opposite to gre_ipfilter_init(), ie clean up
 */
errno_t
gre_ip4filter_dispose(void)
{
#ifdef DEBUG
    printf("%s ...\n", __FUNCTION__);
#endif

    if (gre_ip4f_mtx == NULL) {
#ifdef DEBUG
        printf("%s: gre_ifp_mtx already freed\n", __FUNCTION__);
#endif
        return 0;
    }
    if (gre_ip4filter_detach() == 0) {
        if (gre_ip4f_mtx != NULL) {
            lck_mtx_free(gre_ip4f_mtx, gre_ipf_lck_grp);
            gre_ip4f_mtx = NULL;
        }
#ifdef DEBUG
        printf("%s: done\n", __FUNCTION__);
#endif
        return 0;
    }
#ifdef DEBUG
    printf("%s: error dispose ipfilter\n", __FUNCTION__);
#endif
    return -1;
}



/* the caller who call this function(ipv4_infilter) will free the mbuf when
 * it returns any error except EJUSTRETURN.
 * so, remember to check the function called by this function if it frees
 * the mbuf chain on error. That is, do remember return EJUSTRETURN
 * if you frees the mbuf or the function called by this function frees the mbuf.
 * Otherwise, DOUBLE FREE, causing kernel panic...
 *
 * return ZERO if this filter is not interested in the packet
 * otherwise, it means this filter deal with the packet, and other filters will
 * not see this packet
 *
 * @param cookie
 * @param m
 * @param offset    ip header offset
 * @param protocol  proto, IPPROTO_GRE/IPPROTO_MOBILE
 */
static errno_t
gre_ipv4_infilter(void *cookie, mbuf_t *data, int offset, u_int8_t protocol)
{
	mbuf_t m;
	errno_t error;

	m = *data;

	error = gre_encap4_input(m, offset);


	if (error && error != EJUSTRETURN) {
#if DEBUG
		printf("%s invalid return value: %d\n", __FUNCTION__, error);
#endif
		error = EJUSTRETURN; // FIXIT
	}
	return error;
}


/*
 * is called to notify the filter that it has been detached.
 */
static void
gre_ipv4_if_detach(void *cookie)
{
    lck_mtx_lock(gre_ip4f_mtx);
    if (gre_ipv4filter) {
        gre_ipv4filter = NULL;
        lck_mtx_unlock(gre_ip4f_mtx);
        wakeup(&gre_ipv4filter);
    } else
        lck_mtx_unlock(gre_ip4f_mtx);
}


/*
 * gre_ip4filter_attach(), attach ipv4 filter
 */
static errno_t
gre_ip4filter_attach(void)
{
    if (gre_ipv4filter)
        return 0;
#ifdef DEBUG
    printf("%s ...\n", __FUNCTION__);
#endif
    errno_t err = 0;
    struct ipf_filter ipf;
    bzero(&ipf, sizeof(struct ipf_filter));

    ipf.cookie = (caddr_t)&gre_ipv4filter;
    ipf.name = "org.gmshake.nke.gre_ipv4filter";
    ipf.ipf_input = gre_ipv4_infilter;
    ipf.ipf_detach = gre_ipv4_if_detach;

    err = ipf_addv4(&ipf, &gre_ipv4filter);
    if (err)
        printf("%s: ipf_addv4(), err=0x%x\n", __FUNCTION__, err);
#ifdef DEBUG
    printf("%s: done\n", __FUNCTION__);
#endif
    return err;
}


/*
 * gre_ipfilter_detach(), detach ipv4 filter
 */
static errno_t
gre_ip4filter_detach(void)
{
    if (gre_ipv4filter == NULL)
        return 0;
#ifdef DEBUG
    printf("%s ...\n", __FUNCTION__);
#endif
    errno_t err = 0;
    
    err = ipf_remove(gre_ipv4filter);
    if (err == 0) {
        lck_mtx_lock(gre_ip4f_mtx);
        if (gre_ipv4filter) {
            /* wait for the detach process */
            msleep(&gre_ipv4filter, gre_ip4f_mtx, PDROP, NULL, NULL);
        } else {
            lck_mtx_unlock(gre_ip4f_mtx);
        }
    }

#ifdef DEBUG
    printf("%s: done\n", __FUNCTION__);
#endif
    return err;
}
