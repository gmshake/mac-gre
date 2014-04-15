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

/*
 * we got a anoying bug here, that Apple's implementation of PPTP
 * take the slot ip_protox[IPPROTO_GRE], and if kextload/kextunload is 
 * not in a push/pop sequence, may cause kernel panic.
 * So we use ipfilter filtering IPPROTO_GRE instead.
 * those who DO NOT USE Apple's PPTP(VPN), can change PROTO_WITH_GRE to 1
 * Note: ipfiltering is done before the packet will be send to ip_protox[xxx]
 */
#define PROTO_WITH_GRE 0

/*
 * as ipf_output() would send our packet to the wrong interface when tunnel
 * dst and p-p remote is the same one, I'm considering allocating a properer route
 * and send the packet with ip_output(), setting USE_IP_OUTPUT to 1
 */
#define USE_IP_OUTPUT 1

#if USE_IP_OUTPUT
#include "route.h"

#define	IP_FORWARDING		0x1		/* most of ip header exists */
#define	IP_RAWOUTPUT		0x2		/* raw ip header exists */
#define	IP_NOIPSEC		0x4		/* No IPSec processing */
#define	IP_ROUTETOIF		SO_DONTROUTE	/* bypass routing tables (0x0010) */
#define	IP_ALLOWBROADCAST	SO_BROADCAST	/* can send broadcast packets (0x0020) */
#define	IP_OUTARGS		0x100		/* has ancillary output info */


struct ip_moptions;
/*
 * Extra information passed to ip_output when IP_OUTARGS is set.
 */
struct ip_out_args {
	unsigned int	ipoa_ifscope;	/* interface scope */
};


extern int ip_output(mbuf_t, mbuf_t, struct route *, int, struct ip_moptions *, struct ip_out_args *);

#endif //USE_IP_OUTPUT

#endif //_GRE_CONFIG_H
