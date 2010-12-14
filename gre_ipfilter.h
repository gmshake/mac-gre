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

extern errno_t gre_ipfilter_init();
extern errno_t gre_ipfilter_dispose();
extern errno_t gre_ipfilter_attach();
extern errno_t gre_ipfilter_detach();

#endif // _GRE_IPFILTER_H