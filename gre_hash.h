/*
 *  gre_pcb.h
 *  gre
 *
 *  Created by Summer Town on 1/9/11.
 *  Copyright 2011 __MyCompanyName__. All rights reserved.
 *
 */

#ifndef _GRE_PCB_H
#define _GRE_PCB_H

#if USE_GRE_HASH
struct gre_softc;
struct in_addr;

// locks
extern void gre_hash_lock_shared(void);
extern void gre_hash_unlock_shared(void);
extern void gre_hash_lock_exclusive(void);
extern void gre_hash_unlock_exclusive(void);

extern errno_t gre_hash_init(void);
extern void gre_hash_dispose(void);

extern errno_t gre_hash_add(struct gre_softc *sc);
extern errno_t gre_hash_delete(struct gre_softc *sc);
extern struct gre_softc * gre_hash_find(struct in_addr src, struct in_addr dst, u_int8_t proto);

#endif

#endif
