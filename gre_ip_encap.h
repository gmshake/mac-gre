//
//  gre_ip_encap.h
//  gre
//
//  Created by Zhenlei Huang on 10/7/15.
//
//

#ifndef _GRE_IP_ENCAP_H
#define _GRE_IP_ENCAP_H

#include <sys/appleapiopts.h>
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


errno_t	gre_encap_init(void);
errno_t	gre_encap_dispose(void);
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
void *	gre_encap_getarg(mbuf_t );

#endif
