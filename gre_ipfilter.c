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

#include <net/if.h>
#include <net/ethernet.h>
#include <netat/appletalk.h>

#include <netinet/in.h>
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

extern lck_grp_t *gre_lck_grp;
extern lck_rw_t *gre_domain_lck;
extern TAILQ_HEAD(gre_softc_head, gre_softc) gre_softc_list;

static lck_mtx_t *gre_ipf_mtx = NULL;
ipfilter_t gre_ipv4filter = NULL;

//static struct gre_softc * gre_lookup(mbuf_t m, u_int8_t protocol);
static errno_t ipv4_infilter(void *cookie, mbuf_t *m, int offset, u_int8_t protocol);
static void ipv4_if_detach(void *cookie);

/*
 * gre_ipfilter_init(), initialize resources required by ip filter
 */
errno_t gre_ipfilter_init()
{
#ifdef DEBUG
    if (gre_ipf_mtx != NULL) {
        printf("%s: gre_ifp_mtx already inited\n", __FUNCTION__);
        return 0;
    }
#endif
    gre_ipf_mtx = lck_mtx_alloc_init(gre_lck_grp, NULL);
    
    if (gre_ipf_mtx == NULL)
        return -1;
    else
        return 0;
}

/*
 * gre_ipfilter_dispose(), the opposite to gre_ipfilter_init(), ie clean up
 */
errno_t gre_ipfilter_dispose()
{
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
        return EEXIST;
#ifdef DEBUG
    printf("%s\n", __FUNCTION__);
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
    printf("%s\n", __FUNCTION__);
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
    
    return err;
}

/* use gre_hash_find() instead */
/*
 * gre_lookup(), on success, return pointer point to matching gre_softc, otherwise return NULL
 * @param m         in, mbuf_t with ip header
 * @param protocol  in, which protocol, IPPROTO_GRE/IPPROTO_MOBILE
 */
/*
static struct gre_softc * gre_lookup(mbuf_t m, u_int8_t protocol)
{
	struct ip *ip = mbuf_data(m);
	struct gre_softc *sc;
    
    TAILQ_FOREACH(sc, &gre_softc_list, sc_list) {
        if (ifnet_flags(sc->sc_ifp) & (IFF_UP | IFF_RUNNING) == (IFF_UP | IFF_RUNNING) && \
            sc->encap_proto == protocol && \
            sc->gre_pdst.sa_family != AF_UNSPEC && \
            sc->gre_psrc.sa_family != AF_UNSPEC && \
            in_hosteq(ip->ip_dst, ((struct sockaddr_in *)&sc->gre_psrc)->sin_addr) && \
            in_hosteq(ip->ip_src, ((struct sockaddr_in *)&sc->gre_pdst)->sin_addr)) {
            return sc;
        }
    }
    
	return NULL;
}
*/

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
    ifnet_t             ifp;
    size_t              extra = 0;
    size_t              iph_len;
    uint32_t            key = 0;
    struct greip        *gh;
    struct gre_softc    *sc;

    switch (protocol) {
        case IPPROTO_GRE:
            if (mbuf_pkthdr_len(*m) < sizeof(struct greip))
                return 0; /* too small, just ignore it */
            
            /* make data in first packet continuers */
            mbuf_pullup(m, sizeof(struct greip));
            if (*m == NULL)
                return EJUSTRETURN; // mbuf_pullup() has freed the buff, so, return EJUSTRETURN to avoid DOUBLE FREE!!!
            
            gh = mbuf_data(*m);
            /* chksum bit is set */
            if (gh->gi_flags & htons(GRE_CP)) {
#ifdef DEBUG
                printf("\tJust ignore checksum...\n");
#endif
                extra += sizeof(uint32_t);
            }
            /* We don't support routing fields (variable length) */
            if (gh->gi_flags & GRE_RP)
                return 0;
            /* key present */
            if (gh->gi_ptype & htons(GRE_KP)) {
                extra += sizeof(uint32_t);
                mbuf_pullup(m, sizeof(struct greip) + extra);
                if (*m == NULL)
                    return EJUSTRETURN;
                gh = mbuf_data(*m); /* mbuf_pullup may change *m */
                key = ntohl(gh->gi_options[extra / sizeof(uint32_t)]);
            }
            /* Sequence Present */
            if (gh->gi_ptype & htons(GRE_SP))
                extra += sizeof(uint32_t);
            
            switch (gh->gi_ptype) {
                case htons(WCCP_PROTOCOL_TYPE):
                    extra += sizeof(uint32_t);
                    iph_len = sizeof(struct ip);
                    break;
                case htons(ETHERTYPE_IP):
                    iph_len = sizeof(struct ip);
                    break;
                case htons(ETHERTYPE_IPV6):
                    iph_len = sizeof(struct ip6_hdr);
                    break;
                case htons(ETHERTYPE_AT):
                    iph_len = sizeof(uint16_t);
                    break;
                default:
#ifdef DEBUG
                    printf("Proto type %d is not supported yet.\n", ntohs(gh->gi_ptype));
#endif
                    return 0;
            }
            
            mbuf_pullup(m, sizeof(struct greip) + extra + iph_len);
            if (*m == NULL)
                return EJUSTRETURN; /* maybe it is not a valid ip packet */
            
            gh = mbuf_data(*m);
            /* find a matching interface */
            lck_rw_lock_shared(gre_domain_lck);
            sc = gre_hash_find(gh->gi_dst, gh->gi_src, key, protocol);
            if (sc == NULL) {
                lck_rw_unlock_shared(gre_domain_lck);
                return 0;
            }
            ifp = sc->sc_ifp;
            if (ifnet_reference(ifp)) {
                lck_rw_unlock_shared(gre_domain_lck);
                return 0;
            }
            lck_rw_unlock_shared(gre_domain_lck);
#ifdef DEBUG
            printf("---->interface %s%d found\n", ifnet_name(ifp), ifnet_unit(ifp));
#endif
            mbuf_pkthdr_setheader(*m, mbuf_data(*m) + sizeof(struct ip));
            /* set data point to payload packet */
            if (mbuf_setdata(*m, \
                             mbuf_data(*m) + sizeof(struct greip) + extra, \
                             mbuf_len(*m) - sizeof(struct greip) - extra)) {
#ifdef DEBUG
                printf("---->invalid mbuf\n");
#endif
                return EINVAL;
            }
            mbuf_pkthdr_adjustlen(*m, - sizeof(struct greip) - extra);
            mbuf_pkthdr_setrcvif(*m, ifp);
            
             /* ifnet_input() always frees the mbuf chain */
            if (ifnet_input(ifp, *m, NULL)) {
#ifdef DEBUG
                printf("---->ifnet_input() error\n");
#endif
            }
            
            ifnet_release(ifp);
            
             /* since we see the packet and send it to GRE interfaces, \
              * then ifnet_input() will free the mbuf, \
              * so, tell the caller not to do any further stuff, otherwise, kernel panic
              * if you want to take other action on the mbuf, dump it before ifnet_input()
              */
            return EJUSTRETURN;
        case IPPROTO_MOBILE:
#ifdef DEBUG
            printf("%s: IPPROTO_MOBILE is under deployment!!!\n", __FUNCTION__);
#endif
            return 0;
        default:
            return 0;
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
