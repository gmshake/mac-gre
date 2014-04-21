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
struct gre_softc;
struct in_addr;

extern errno_t gre_hash_init();
extern void gre_hash_dispose();

// locks
extern void gre_hash_lock_shared();
extern void gre_hash_unlock_shared();
extern void gre_hash_lock_exclusive();
extern void gre_hash_unlock_exclusive();

extern errno_t gre_hash_add(struct gre_softc *sc);
extern errno_t gre_hash_delete(struct gre_softc *sc);
extern struct gre_softc * gre_hash_find(struct in_addr src, struct in_addr dst, u_int8_t proto);

#endif
