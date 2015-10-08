/*
 *  gre_ipfilter.h
 *  gre
 *
 *  Created by Summer Town on 11/30/10.
 *  Copyright 2010 __MyCompanyName__. All rights reserved.
 *
 */

#ifndef _GRE_IPFILTER_H
#define _GRE_IPFILTER_H

extern int gre_ip4filter_init(void);
extern int gre_ip4filter_dispose(void);

extern int gre_ip6filter_init(void);
extern int gre_ip6filter_dispose(void);

#endif
