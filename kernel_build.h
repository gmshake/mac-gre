//
//  kernel_build.h
//  gre
//
//  Created by Zhenlei Huang on 4/7/14.
//
//

#ifndef gre_kernel_build_h
#define gre_kernel_build_h

/* fix NKE building */
#ifndef PRIVATE
#define PRIVATE 1
#endif

#ifndef BSD_KERNEL_PRIVATE
#define BSD_KERNEL_PRIVATE 1
#endif
/*
#ifndef in_cksum_skip
#define in_cksum_skip(m, l, o)  inet_cksum(m, 0, o, (l) - (o))
#endif
*/

#ifndef ip_newid
#define ip_newid() gre_ip_randomid()
#endif

/*-
 * Macro for type conversion: convert mbuf pointer to data pointer of correct
 * type:
 *
 * mtod(m, t)   -- Convert mbuf pointer to data pointer of correct type.
 * mtodo(m, o) -- Same as above but with offset 'o' into data.
 */
#define mtod(m, t)      ((t)(mbuf_data(m)))
#define mtodo(m, o)     ((void *)(mbuf_data(m) + (o)))
#define m_adj(m, l)	(mbuf_adj(m, l))
#define m_freem(m)	(mbuf_freem(m))


/*
 * from BSD10, fs/nfs/nfskpiport.h
 *
#define mbuf_freem(m)           m_freem(m)
#define mbuf_data(m)            mtod((m), void *)
#define mbuf_len(m)             ((m)->m_len)
#define mbuf_next(m)            ((m)->m_next)
#define mbuf_setlen(m, l)       ((m)->m_len = (l))
#define mbuf_setnext(m, p)      ((m)->m_next = (p))
#define mbuf_pkthdr_len(m)      ((m)->m_pkthdr.len)
#define mbuf_pkthdr_setlen(m, l) ((m)->m_pkthdr.len = (l))
#define mbuf_pkthdr_setrcvif(m, p) ((m)->m_pkthdr.rcvif = (p))
*/

#endif
