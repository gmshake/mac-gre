//
//  ip6_gre.h
//  gre
//
//  Created by Zhenlei Huang on 10/7/15.
//
//

#ifndef _IP6_GRE_H
#define _IP6_GRE_H

#include <sys/sysctl.h>

#include "gre_if.h"


extern struct sysctl_oid sysctl__net_gre_hlim;


errno_t in6_gre_output(mbuf_t m, int af, int hlen);
errno_t in6_gre_attach(struct gre_softc *sc);

#endif
