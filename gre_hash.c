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
#include "gre_hash.h"

#define BITS 5
/* 32 should be enough */
#define SLOT_CNT (1 << BITS)

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
    register uint32_t hash = BIGPRIME ^ k1;
    hash ^=   ((hash <<  7) ^ k0 ^ (hash >> 3));
    hash ^= (~((hash << 11) ^ k2 ^ (hash >> 5)));
    hash ^= hash >> 16;
    return hash;
#undef BIGPRIME
}

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
    int release_count = 0;
#endif
    if (gre_slot_lck == NULL) {
#ifdef DEBUG
        printf("%s: warnning: gre_slot_lck has already been freed\n", __FUNCTION__);
#endif
        return;
    }
    
    gre_hash_lock_exclusive();
    for (int i = 0; i < SLOT_CNT; i++) {
        for (struct gre_softc *sc = gre_hash_slot[i]; sc != NULL; ) {
#ifdef DEBUG
            printf("%s: found sc = %p, sc->sc_refcnt = %d, sc->pcb_next = %p\n", __FUNCTION__, sc, sc->sc_refcnt, sc->pcb_next);
            release_count++;
#endif
            struct gre_softc * sc1 = sc;
            sc = sc->pcb_next;
            
            sc1->pcb_next = NULL;
            gre_sc_release(sc1);
        }
        gre_hash_slot[i] = NULL;
    }
    gre_hash_unlock_exclusive();

    lck_rw_free(gre_slot_lck, gre_lck_grp);
    gre_slot_lck = NULL;

#ifdef DEBUG
    printf("%s: done, released %d total\n", __FUNCTION__, release_count);
#endif
}

/*
 * gre_hash_lock_shared()
 */
void gre_hash_lock_shared()
{
    lck_rw_lock_shared(gre_slot_lck);
}

/*
 * gre_hash_unlock_shared()
 */
void gre_hash_unlock_shared()
{
    lck_rw_unlock_shared(gre_slot_lck);
}

/*
 * gre_hash_lock_exclusive()
 */
void gre_hash_lock_exclusive()
{
    lck_rw_lock_exclusive(gre_slot_lck);
}

/*
 * gre_hash_unlock_exclusive()
 */
void gre_hash_unlock_exclusive()
{
    lck_rw_unlock_exclusive(gre_slot_lck);
}


/*
 * gre_hash_add(), add a gre softc to hash table, we also add refcnt here
 * @param sc,   to be added
 * return 0 on success, otherwise return -1
 */
errno_t gre_hash_add(struct gre_softc *sc)
{
    if (sc == NULL || sc->pcb_next != NULL) {
#ifdef DEBUG
        printf("%s: invalid softc, sc = %p, sc->pcb_next = %p\n", __FUNCTION__, sc, sc == NULL ? NULL : sc->pcb_next);
#endif
        return EINVAL;
    }
    
    uint32_t slot = gre_hash(((struct sockaddr_in *)&sc->gre_psrc)->sin_addr.s_addr, \
                             ((struct sockaddr_in *)&sc->gre_pdst)->sin_addr.s_addr, \
                             sc->encap_proto) & (SLOT_CNT - 1);
#ifdef DEBUG
    printf("%s: slot -> %u\n", __FUNCTION__, slot);
#endif

    for (struct gre_softc *p = gre_hash_slot[slot]; p != NULL; p = p->pcb_next) {
        if (p == sc) {
#ifdef DEBUG
            printf("%s: exist\n", __FUNCTION__);
#endif
            return EEXIST;
        }
    }

    // NOT FOUND
    gre_sc_reference(sc); /* here, we increase the ref of sc, indicates that it's in hash table */

    sc->pcb_next = gre_hash_slot[slot];
    gre_hash_slot[slot] = sc;

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
        printf("%s: invalid softc, sc = %p, sc->sc_refcnt = %d\n", __FUNCTION__, sc, sc == NULL ? 0 : sc->sc_refcnt);
#endif
        return EINVAL;
    }
    
    uint32_t slot = gre_hash(((struct sockaddr_in *)&sc->gre_psrc)->sin_addr.s_addr, \
                             ((struct sockaddr_in *)&sc->gre_pdst)->sin_addr.s_addr, \
                             sc->encap_proto) & (SLOT_CNT - 1);
#ifdef DEBUG
    printf("%s: slot -> %u\n", __FUNCTION__, slot);
#endif
    
    struct gre_softc *prev = gre_hash_slot[slot];
    struct gre_softc *p = prev;
    
    while (p) {
        struct gre_softc *next = p->pcb_next;
        if (p == sc) { // found
            if (prev == p)
                gre_hash_slot[slot] = next;
            else
                prev->pcb_next = next;
            
            sc->pcb_next = NULL;
            gre_sc_release(sc);

#ifdef DEBUG
            printf("%s: done\n", __FUNCTION__);
#endif
            return 0;
        }
        // next
        prev = p;
        p = next;
    }
    
notfound:
#ifdef DEBUG
    printf("%s: not found\n", __FUNCTION__);
#endif
    return -1;
}


/*
 * gre_hash_find(), find a right gre softc from hash table by supplied parameters
 * @param src,  src address
 * @param dst,  dst address
 * @param proto, which proto, IPPROTO_GRE, IPPROTO_MOBILE...
 * return pointer to softc on success, otherwise return NULL
 * on success, we add reference count of sc
 * do remember to unref sc
 */
struct gre_softc * gre_hash_find(struct in_addr src, struct in_addr dst, u_int8_t proto)
{
    uint32_t slot = gre_hash(src.s_addr, dst.s_addr, proto) & (SLOT_CNT - 1);
#ifdef DEBUG
    printf("%s: slot -> %u\n", __FUNCTION__, slot);
#endif
    
    for (struct gre_softc *sc = gre_hash_slot[slot]; sc != NULL; sc = sc->pcb_next) {
        if (in_hosteq(src, ((struct sockaddr_in *)&sc->gre_psrc)->sin_addr) && \
            in_hosteq(dst, ((struct sockaddr_in *)&sc->gre_pdst)->sin_addr) && \
            sc->encap_proto == proto) {
            
            gre_sc_reference(sc);

#ifdef DEBUG
            printf("%s: found\n", __FUNCTION__);
#endif
            
            return sc;
        }
    }
    
notfound:
#ifdef DEBUG
    printf("%s: not found\n", __FUNCTION__);
#endif
    return NULL;
}
