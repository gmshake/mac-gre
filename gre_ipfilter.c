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

#include <netinet/in.h>
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

extern lck_grp_t *gre_lck_grp;
extern lck_rw_t *gre_domain_lck;
extern TAILQ_HEAD(gre_softc_head, gre_softc) gre_softc_list;

static lck_mtx_t *gre_ipf_mtx = NULL;
ipfilter_t gre_ipv4filter = NULL;

static errno_t ipv4_infilter(void *cookie, mbuf_t *m, int offset, u_int8_t protocol);
//static errno_t ipv4_outfilter(void* cookie, mbuf_t *m, ipf_pktopts_t options);
static void ipv4_if_detach(void *cookie);

errno_t gre_ipfilter_init()
{
    if (gre_ipf_mtx != NULL)
        return 0;
    dprintf("%s: attach ipfilter, \tseq: %llu\n", __FUNCTION__, get_seq());

    gre_ipf_mtx = lck_mtx_alloc_init(gre_lck_grp, NULL);
    
    if (gre_ipf_mtx == NULL)
        return -1;

    return 0;
}

errno_t gre_ipfilter_dispose()
{
    dprintf("%s: dispose ipfilter, \tseq: %llu\n", __FUNCTION__, get_seq());
    
    if (gre_ipfilter_detach() == 0) {
        if (gre_ipf_mtx != NULL) {
            lck_mtx_free(gre_ipf_mtx, gre_lck_grp);
            gre_ipf_mtx = NULL;
        }
        return 0;
    }
    dprintf("%s: error dispose ipfilter\n", __FUNCTION__);
    return -1;
}

errno_t gre_ipfilter_attach()
{
    dprintf("%s: attach ipfilter, \tseq: %llu\n", __FUNCTION__, get_seq());
    if (gre_ipv4filter)
        return EEXIST;
    
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

errno_t gre_ipfilter_detach()
{
    if (gre_ipv4filter == NULL)
        return 0;
    dprintf("%s: detach ipfilter, \tseq: %llu\n", __FUNCTION__, get_seq());
    
    errno_t err = 0;
    
    lck_mtx_lock(gre_ipf_mtx);
    if (gre_ipv4filter) {
        lck_mtx_unlock(gre_ipf_mtx);

        err = ipf_remove(gre_ipv4filter);
        if (err == 0) {
            lck_mtx_lock(gre_ipf_mtx);
            if (gre_ipv4filter) {
                /* wait for the detach */
                msleep(&gre_ipv4filter, gre_ipf_mtx, PDROP, NULL, NULL);
            } else 
                lck_mtx_unlock(gre_ipf_mtx);
        }
    } else
        lck_mtx_unlock(gre_ipf_mtx);
    
    return err;
}

/* the caller who call this function(ipv4_infilter) will free the mbuf when 
 * error returns except EJUSTRETURN
 * so, remember to check the function called in this function if it frees
 * the mbuf chain when error occurs. That is, do remember return EJUSTRETURN
 * if you frees the mbuf or the called function frees the mbuf. Otherwise, 
 * DOUBLE FREE will cause system panic...
 *
 * return ZERO if this filter is not interested in the packet
 * otherwise, it means this filter deal with the packet, and other filters will
 * not see this packet
 */
static errno_t ipv4_infilter(void *cookie, mbuf_t *m, int offset, u_int8_t protocol)
{
    errno_t             err = 0;
    size_t              extra = 0;
    struct greip        *gh = NULL;
    struct gre_softc    *sc = NULL;

    switch (protocol) {
        case IPPROTO_GRE:
            if (mbuf_pkthdr_len(*m) < sizeof(struct greip) + sizeof(struct ip))
                break; /* maybe it is a PPTP packet, just ignore it */
            
            /* make data in first packet continuers */
            mbuf_pullup(m, sizeof(struct greip) + sizeof(struct ip));
            if (*m == NULL) {
                err = EJUSTRETURN; // mbuf_pullup() has freed the buff, so, return EJUSTRETURN to avoid DOUBLE FREE!!!
                break;  // mbuf_pullup() should never fail since mbuf_len(*m) is long enough, Ah... no MEMERY???
            }
            
            gh = mbuf_data(*m);

            /* the data in ip header in mbuf that is passed into ip filters always use network byte order */
            switch (gh->gi_ptype) {
                case htons(WCCP_PROTOCOL_TYPE):
                    extra += sizeof(uint32_t);
                    break;
                case htons(ETHERTYPE_IP):
                    break;
                case htons(ETHERTYPE_IPV6):
                default:
                    dprintf("Proto type %d is not supported yet.\n", ntohs(gh->gi_ptype));
                    goto done;
            }
            
            dprintf("offset:%d\n", offset);
            
            /* key present */
            if (gh->gi_flags & htons(GRE_KP))
                extra += sizeof(uint32_t);
            
            /* check if chksum bit is set */
            if (gh->gi_flags & htons(GRE_CP))
                dprintf("\tJust ignore checksum...\n");

            lck_rw_lock_shared(gre_domain_lck);
            TAILQ_FOREACH(sc, &gre_softc_list, sc_list) {
                if (sc->sc_ifp && \
                    ifnet_flags(sc->sc_ifp) & (IFF_UP | IFF_RUNNING) == (IFF_UP | IFF_RUNNING) && \
                    sc->gre_pdst && \
                    sc->gre_psrc && \
                    in_hosteq(gh->gi_dst, ((struct sockaddr_in *)sc->gre_psrc)->sin_addr) && \
                    in_hosteq(gh->gi_src, ((struct sockaddr_in *)sc->gre_pdst)->sin_addr)) {

                    dprintf("---->find interface gre%d\n", ifnet_unit(sc->sc_ifp));
                    
                    if (extra > 0) {
                        mbuf_pullup(m, sizeof(struct greip) + extra + sizeof(struct ip));
                        if (*m == NULL) {
                            err = EJUSTRETURN; // since we have freed the mbuf, return EJUSTRETURN to avoid DOUBLE FREE
                            break;
                        }
                    }
                    
                    if ((err = mbuf_setdata(*m, \
                                            mbuf_data(*m) + sizeof(struct greip) + extra, \
                                            mbuf_len(*m) - sizeof(struct greip) - extra)) != 0) {
                        dprintf("---->mbuf_setdata() error=0x%x\n", err);
                        break;
                    }
                    mbuf_pkthdr_adjustlen(*m, - (sizeof(struct greip) + extra));

                    if ((err = mbuf_pkthdr_setrcvif(*m, sc->sc_ifp)) != 0) {
                        dprintf("---->error set rcvif: %d\n", err); //sould never happen since this version(xnu1228) \
                                                                        of mbuf_pkthdr_setrcvif() do not check the interface, \
                                                                        maybe the next version will do, there is no gurantee
                        break;
                    }
#ifdef DEBUG
                    if (chk_mbuf(*m) != 0) { // we check the mbuf by ourselves first, preventing the anoying kernel panic...
                        printf("---->warning: invalid mbuf: %p\n", *m);
                        err = EINVAL;
                        break;
                    }
#endif
                     
                     /* ifnet_input() always frees the mbuf chain */
                    if ((err = ifnet_input(sc->sc_ifp, *m, NULL)) != 0)
                        dprintf("---->ifnet_input() error=0x%x\n", err);

                     /* since we see the packet and send it to GRE interfaces, \
                      * then ifnet_input() will free the mbuf, \
                      * so, tell the caller not to do any further stuff, otherwise, kernel panic
                      * if you want to take other action on the mbuf, dump it before ifnet_input()
                      */
                    err = EJUSTRETURN;
                    break;
                } /* else continue to check if next interface is satisfied */
            }
            lck_rw_unlock_shared(gre_domain_lck);
            break;
        case IPPROTO_MOBILE:
            dprintf("%s: IPPROTO_MOBILE is under deployment!!!\n", __FUNCTION__);
            break;
        default:
            break;
    }
    
done:
    return err;
}


/*
 * is called to notify the filter that it has been detached.
 */
static void ipv4_if_detach(void *cookie)
{
    dprintf("%s: \tseq: %llu\n", __FUNCTION__, get_seq());
    lck_mtx_lock(gre_ipf_mtx);
    if (gre_ipv4filter) {
        gre_ipv4filter = NULL;
        lck_mtx_unlock(gre_ipf_mtx);
        wakeup(&gre_ipv4filter);
    } else
        lck_mtx_unlock(gre_ipf_mtx);
}

