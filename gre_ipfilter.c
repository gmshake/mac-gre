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
#include <sys/socket.h>

#include <net/if.h>
#include <net/ethernet.h>
//#include <netat/appletalk.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/kpi_ipfilter.h>

#if CONFIG_MACF_NET
#include <security/mac_framework.h>
#endif

#include "gre_if.h"  //IPPROTO_MOBILE
#include "gre_ipfilter.h"
#include "in_gre.h"
#include "gre_config.h"

extern lck_grp_t *gre_lck_grp;

static lck_mtx_t *gre_ipf_mtx = NULL;
static ipfilter_t gre_ipv4filter = NULL;

static errno_t ipv4_infilter(void *cookie, mbuf_t *m, int offset, u_int8_t protocol);
static void ipv4_if_detach(void *cookie);

/*
 * gre_ipfilter_init(), initialize resources required by ip filter
 */
errno_t gre_ipfilter_init()
{
#ifdef DEBUG
    printf("%s ...\n", __FUNCTION__);
#endif

    if (gre_ipf_mtx != NULL) {
#ifdef DEBUG
        printf("%s: gre_ifp_mtx already inited\n", __FUNCTION__);
#endif
        goto success;
    }

    gre_ipf_mtx = lck_mtx_alloc_init(gre_lck_grp, NULL);

    if (gre_ipf_mtx == NULL)
        goto failed;

    if (gre_ipfilter_attach()) {/* attach ip filter */
        lck_mtx_free(gre_ipf_mtx, gre_lck_grp);
        gre_ipf_mtx = NULL;
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
errno_t gre_ipfilter_dispose()
{
#ifdef DEBUG
    printf("%s ...\n", __FUNCTION__);
#endif

    if (gre_ipf_mtx == NULL) {
#ifdef DEBUG
        printf("%s: gre_ifp_mtx already freed\n", __FUNCTION__);
#endif
        return 0;
    }
    if (gre_ipfilter_detach() == 0) {
        if (gre_ipf_mtx != NULL) {
            lck_mtx_free(gre_ipf_mtx, gre_lck_grp);
            gre_ipf_mtx = NULL;
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

/*
 * gre_ipfilter_attach(), attach ipv4 filter
 */
errno_t gre_ipfilter_attach()
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
	ipf.name = "org.gmshake.nke.GRE";
	ipf.ipf_input = ipv4_infilter;
	ipf.ipf_detach = ipv4_if_detach;

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
errno_t gre_ipfilter_detach()
{
    if (gre_ipv4filter == NULL)
        return 0;
#ifdef DEBUG
    printf("%s ...\n", __FUNCTION__);
#endif
    errno_t err = 0;
    
    lck_mtx_lock(gre_ipf_mtx);
    if (gre_ipv4filter) {
        lck_mtx_unlock(gre_ipf_mtx);

        err = ipf_remove(gre_ipv4filter);
        if (err == 0) {
            lck_mtx_lock(gre_ipf_mtx);
            if (gre_ipv4filter) {
                /* wait for the detach process */
                msleep(&gre_ipv4filter, gre_ipf_mtx, PDROP, NULL, NULL);
            } else {
                lck_mtx_unlock(gre_ipf_mtx);
            }
        }
    } else {
        lck_mtx_unlock(gre_ipf_mtx);
    }
#ifdef DEBUG
    printf("%s: done\n", __FUNCTION__);
#endif
    return err;
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
static errno_t ipv4_infilter(void *cookie, mbuf_t *m, int offset, u_int8_t protocol)
{
    switch (protocol) {
        case IPPROTO_GRE:
        {
#if !(PROTO_WITH_GRE)
#ifdef DEBUG
            printf("%s: got packet\n", __FUNCTION__);
#endif
            mbuf_t m0 = in_gre_input2(*m ,offset);
            if (m0 == NULL) /* has been processed */
                return EJUSTRETURN;
            else
                *m = m0;
#endif
            break;
        }
        case IPPROTO_MOBILE:
#ifdef DEBUG
            printf("%s: IPPROTO_MOBILE will be processed by ip_protox[IPPROTO_MOBILE]\n", __FUNCTION__);
#endif
            break;
        default:
            break;
    }
    
    return 0;
}

/*
 * is called to notify the filter that it has been detached.
 */
static void ipv4_if_detach(void *cookie)
{
    lck_mtx_lock(gre_ipf_mtx);
    if (gre_ipv4filter) {
        gre_ipv4filter = NULL;
        lck_mtx_unlock(gre_ipf_mtx);
        wakeup(&gre_ipv4filter);
    } else
        lck_mtx_unlock(gre_ipf_mtx);
}
