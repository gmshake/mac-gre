//
//  gre_ip_encap.h
//  gre
//
//  Created by Zhenlei Huang on 10/7/15.
//
//

/*	$FreeBSD$	*/
/*	$KAME: ip_encap.h,v 1.7 2000/03/25 07:23:37 sumikawa Exp $	*/

/*-
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _GRE_IP_ENCAP_H
#define _GRE_IP_ENCAP_H

#include <sys/appleapiopts.h>
#include <sys/socket.h>
#include <sys/queue.h>


struct gre_encaptab {
	LIST_ENTRY(gre_encaptab) chain;
	int af;
	int proto;                      /* -1: don't care, I'll check myself */
	struct sockaddr_storage src;    /* my addr */
	struct sockaddr_storage srcmask;
	struct sockaddr_storage dst;    /* remote addr */
	struct sockaddr_storage dstmask;
	int (*func)(const mbuf_t, int, int, void *);
	//const struct protosw *psw;      /* only pr_input will be used */
	void (*pr_input)(mbuf_t *, int *, int, void *);
	void *arg;                      /* passed via m->m_pkthdr.aux */
};


int	gre_encap_init(void);
int	gre_encap_dispose(void);
int	gre_encap4_input(mbuf_t, int);
int	gre_encap6_input(mbuf_t *, int *, int);
const struct gre_encaptab *gre_encap_attach(int, int, const struct sockaddr *,
        const struct sockaddr *, const struct sockaddr *,
        const struct sockaddr *, void (*pr_input)(mbuf_t *, int *, int, void *), void *);
const struct gre_encaptab *gre_encap_attach_func(int, int,
					 int (*)(const mbuf_t , int, int, void *),
					 void (*pr_input)(mbuf_t *, int *, int, void *),
					 void *);
int	gre_encap_detach(const struct gre_encaptab *);
void *	gre_encap_getarg(mbuf_t);

#endif
