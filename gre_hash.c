/*
 *  gre_hash_slot.c
 *  gre
 *
 *  Created by Summer Town on 1/9/11.
 *  Copyright 2011 __MyCompanyName__. All rights reserved.
 *
 */

/*
 * should include these
 */
#include <sys/systm.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ip.h>

#include "gre_if.h"

#define BITS 10
/* 1024 should be enough */
#define SLOT_CNT (1 << BITS)

extern unsigned int ngre;
extern lck_grp_t *gre_lck_grp;

static lck_rw_t *gre_slot_lck = NULL; // protect gre_hash_slot

static struct gre_softc *gre_hash_slot[SLOT_CNT];

#define lrotl(x, n) ((x << n) | (x >> (sizeof(x) * 8 - n)))
#define lrotr(x, n) ((x >> n) | (x << (sizeof(x) * 8 - n)))
/*
 * gre_hash(), hash function used to get hash key
 * modified AP Hash
 */
static inline uint32_t gre_hash(uint32_t k0, uint32_t k1, uint32_t k2)
{
#define BIGPRIME 1783256291
    register uint32_t hash = BIGPRIME ^ k2;
    hash ^=   ((hash <<  7) ^ k0 ^ (hash >> 3));
    hash ^= (~((hash << 11) ^ k1 ^ (hash >> 5)));
    //hash ^= (hash >> 8) ^ (hash >> 16) ^ (hash >> 24);
    hash ^= hash >> 16;
    return hash;
#undef BIGPRIME
}
/*
static inline uint32_t gre_hash2(uint32_t k0, uint32_t k1, uint32_t k2)
{
    register uint32_t hash = lrotl(k2, BITS);
    hash ^= k0 ^ k1;
    //hash ^= hash >> 16;
    //hash ^= (hash >> 8) ^ (hash >> 16) ^ (hash >> 24);
    //hash ^= (hash >> 4) ^ (hash >> 8) ^ (hash >> 12) ^ (hash >> 16) ^ (hash >> 20) ^ (hash >> 24) ^ (hash >> 28);
    
    hash ^= (hash >> 2) ^ (hash >> 4) ^ (hash >> 6) ^ (hash >> 8) ^ (hash >> 10) ^ \
        (hash >> 12) ^ (hash >> 14) ^ (hash >> 16) ^ (hash >> 18) ^ (hash >> 20) ^ \
        (hash >> 22) ^ (hash >> 24) ^ (hash >> 26) ^ (hash >> 28) ^ (hash >> 30);
    return hash;
} */

/*
 * gre_hash_init(), init gre softc hash table
 */
errno_t gre_hash_init()
{
#ifdef DEBUG
    printf("%s ...\n", __FUNCTION__);
#endif
    if (gre_slot_lck != NULL) {
#ifdef DEBUG
        printf("%s: warnning: gre_slot_lck has already been inited\n", __FUNCTION__);
#endif
        goto success;
    }

    gre_slot_lck = lck_rw_alloc_init(gre_lck_grp, NULL);
    if (gre_slot_lck == NULL)
        goto failed;

success:
#ifdef DEBUG
    printf("%s: done\n", __FUNCTION__);
#endif
    return 0;

failed:
#ifdef DEBUG
    printf("%s: error\n", __FUNCTION__);
#endif
    return -1;
}

/*
 * gre_hash_dispose(), free all resources
 * should we check if sc in slot have been all freed???
 */
void gre_hash_dispose()
{
#ifdef DEBUG
    printf("%s ...\n", __FUNCTION__);
#endif
    if (gre_slot_lck == NULL) {
#ifdef DEBUG
        printf("%s: warnning: gre_slot_lck has already been freed\n", __FUNCTION__);
#endif
        return;
    }
    
#ifdef DEBUG
    int i;
    for (i = 0; i < SLOT_CNT; i++) {
        if (gre_hash_slot[i] != NULL)
            printf("%s: warnning: \
                   gre_hash_slot has a member sc(%p) not been freed\n", \
                   __FUNCTION__, gre_hash_slot[i]);
    }
#endif
    
    lck_rw_free(gre_slot_lck, gre_lck_grp);
    gre_slot_lck = NULL;

#ifdef DEBUG
    printf("%s: done\n", __FUNCTION__);
#endif
}

/*
 * gre_hash_add(), add a gre softc to hash table, we also add refcnt here
 * @param sc,   to be added
 * return 0 on success, otherwise return -1
 */
errno_t gre_hash_add(struct gre_softc *sc)
{
    if (sc == NULL || sc->sc_refcnt == 0) {
#ifdef DEBUG
        printf("%s: invalid softc, sc = %p, sc->sc_refcnt = %d\n", __FUNCTION__, sc, sc->sc_refcnt);
#endif
        return EINVAL;
    }
    gre_reference(sc); /* here, we increase the ref of sc, indicates that it's in hash table */
    
    uint32_t slot = gre_hash(ntohl(((struct sockaddr_in *)&sc->gre_psrc)->sin_addr.s_addr), \
                             ntohl(((struct sockaddr_in *)&sc->gre_pdst)->sin_addr.s_addr), \
                             sc->encap_proto) & (SLOT_CNT - 1);
#ifdef DEBUG
    printf("%s: slot: %u\n", __FUNCTION__, slot);
#endif
    lck_rw_lock_exclusive(gre_slot_lck);
    
    if (gre_hash_slot[slot] == NULL) {
        gre_hash_slot[slot] = sc;
    } else {
        struct gre_softc *p = gre_hash_slot[slot];
        while (p->pcb_next) {
            /* exist */
            if (p->pcb_next == sc) {
                lck_rw_unlock_exclusive(gre_slot_lck);
#ifdef DEBUG
                printf("%s: exist\n", __FUNCTION__);
#endif
                gre_release(sc);
                return EEXIST;
            }
            p = p->pcb_next;
        }
        p->pcb_next = sc;
        sc->pcb_next = NULL; /* prevent infinite loops */
    }
    lck_rw_unlock_exclusive(gre_slot_lck);
#ifdef DEBUG
    printf("%s: done\n", __FUNCTION__);
#endif
    return 0;
}

/*
 * gre_hash_delete(), delete a gre softc from hash table
 * @param sc,   to be deleted
 * return 0 on success, otherwise return -1
 */
errno_t gre_hash_delete(struct gre_softc *sc)
{
    if (sc == NULL || sc->sc_refcnt == 0) {
#ifdef DEBUG
        printf("%s: invalid softc, sc = %p, sc->sc_refcnt = %d\n", __FUNCTION__, sc, sc->sc_refcnt);
#endif
        return EINVAL;
    }
    gre_reference(sc);
    
    uint32_t slot = gre_hash(ntohl(((struct sockaddr_in *)&sc->gre_psrc)->sin_addr.s_addr), \
                             ntohl(((struct sockaddr_in *)&sc->gre_pdst)->sin_addr.s_addr), \
                             sc->encap_proto) & (SLOT_CNT - 1);
#ifdef DEBUG
    printf("%s: slot: %u\n", __FUNCTION__, slot);
#endif
    
    lck_rw_lock_exclusive(gre_slot_lck);
    if (gre_hash_slot[slot] == NULL)
        goto notfound;
    else if (gre_hash_slot[slot] == sc) {
        gre_hash_slot[slot] = sc->pcb_next;
        sc->pcb_next = NULL; /* clear sc->pcb_next */
        lck_rw_unlock_exclusive(gre_slot_lck);
#ifdef DEBUG
        printf("%s: done\n", __FUNCTION__);
#endif
        gre_release_n(sc, 2); /* YES, decrease ref by 2 */
        return 0;
    }
    
    struct gre_softc *p = gre_hash_slot[slot];
    while (p->pcb_next) {
        if (p->pcb_next == sc) {
            p->pcb_next = sc->pcb_next;
            sc->pcb_next = NULL;
            lck_rw_unlock_exclusive(gre_slot_lck);
#ifdef DEBUG
            printf("%s: done\n", __FUNCTION__);
#endif
            gre_release_n(sc, 2); /* YES, decrease ref by 2 */
            return 0;
        }
        p = p->pcb_next;
    }
    
notfound:
    lck_rw_unlock_exclusive(gre_slot_lck);
#ifdef DEBUG
    printf("%s: not found\n", __FUNCTION__);
#endif
    gre_release(sc);
    return -1;
}

/*
 * gre_hash_find(), find a right gre softc from hash table by supplied parameters
 * @param src,  src address
 * @param dst,  dst address
 * @param key,  key
 * @param proto, which proto, IPPROTO_GRE, IPPROTO_MOBILE...
 * return pointer to softc on success, otherwise return NULL
 * on success, we add reference count of sc && sc->sc_ifp
 * do remember to unref sc->sc_ifp && sc
 */
struct gre_softc * gre_hash_find(struct in_addr src, struct in_addr dst, u_int8_t proto)
{
    uint32_t slot = gre_hash(ntohl(src.s_addr), ntohl(dst.s_addr), proto) & (SLOT_CNT - 1);
#ifdef DEBUG
    printf("%s: slot: %u\n", __FUNCTION__, slot);
#endif
    lck_rw_lock_shared(gre_slot_lck);
    struct gre_softc *sc = gre_hash_slot[slot];
    while (sc) {
        if (sc->sc_refcnt <= 1) { /* this sc should not be in our hash_table */
            printf("%s: find a sc that should not appear in our hash table, sc = %p\n", __FUNCTION__, sc);
            if (sc->sc_refcnt == 0) { /* Oh shit, it has been already freed but not deleted from hash table */
                printf("%s: find a sc that has been already freed but not deleted from hash table, sc = %p\n", __FUNCTION__, sc);
                goto notfound;
            }
            sc = sc->pcb_next;
            continue;
        }
        gre_reference(sc);
        if ((ifnet_flags(sc->sc_ifp) & (IFF_UP | IFF_RUNNING)) == (IFF_UP | IFF_RUNNING) && \
            sc->encap_proto == proto && \
            in_hosteq(src, ((struct sockaddr_in *)&sc->gre_psrc)->sin_addr) && \
            in_hosteq(dst, ((struct sockaddr_in *)&sc->gre_pdst)->sin_addr)) {
            lck_rw_unlock_shared(gre_slot_lck);
            ifnet_reference(sc->sc_ifp);
#ifdef DEBUG
            printf("%s: found\n", __FUNCTION__);
#endif
            return sc;
        } else {
            gre_release(sc);
            sc = sc->pcb_next;
        }
    }
    
notfound:
    lck_rw_unlock_shared(gre_slot_lck);
#ifdef DEBUG
    printf("%s: not found\n", __FUNCTION__);
#endif
    return NULL;
}
