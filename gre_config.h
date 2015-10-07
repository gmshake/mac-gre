/*
 *  gre_config.h
 *  gre
 *
 *  Created by Summer Town on 1/13/11.
 *  Copyright 2011 __MyCompanyName__. All rights reserved.
 *
 */

#ifndef _GRE_CONFIG_H
#define _GRE_CONFIG_H

#include "kernel_build.h"


/*
 * we got a anoying bug here, that Apple's implementation of PPTP
 * take the slot ip_protox[IPPROTO_GRE], and if kextload/kextunload is 
 * not in a push/pop sequence, may cause kernel panic.
 * So we use ipfilter filtering IPPROTO_GRE instead.
 * those who DO NOT USE Apple's PPTP(VPN), can change PROTO_WITH_GRE to 1
 * Note: ipfiltering is done before the packet will be send to ip_protox[xxx]
 */
#define PROTO_WITH_GRE 0

#define PROTO_WITH_MOBILE 0

#define USE_GRE_HASH 0


#endif //_GRE_CONFIG_H
