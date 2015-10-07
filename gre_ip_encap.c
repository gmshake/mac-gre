//
//  gre_ip_encap.c
//  gre
//
//  Created by Zhenlei Huang on 10/7/15.
//
//


#include <sys/param.h>
#include <sys/systm.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/mbuf.h>
#include <sys/errno.h>
#include <sys/protosw.h>
#include <sys/queue.h>

#include <net/if.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/ip_mroute.h>

#include <netinet/ip6.h>


#include "kernel_build.h"
#include "gre_ip_encap.h"
#include "gre_locks.h"


LIST_HEAD(, gre_encaptab) gre_encaptab = LIST_HEAD_INITIALIZER(&gre_encaptab);

#define GRE_MODULE_TAG_ENCAT "org.gmshake.nke.gre_encaptab"
static mbuf_tag_id_t gre_module_tag_id;

#define GRE_MODULE_TAG_ID gre_module_tag_id
#define GRE_TAG_TYPE_ENCAP 0


static lck_rw_t *gre_encap_lck;


static void gre_encap_add(struct gre_encaptab *);
static int gre_mask_match(const struct gre_encaptab *, const struct sockaddr *,
		      const struct sockaddr *);

static void gre_encap_fillarg(mbuf_t, void *);


errno_t
gre_encap_init(void)
{
#ifdef DEBUG
	printf("%s ...\n", __FUNCTION__);
#endif
	errno_t err;

	if (gre_encap_lck)
		return 0;

	err = mbuf_tag_id_find(GRE_MODULE_TAG_ENCAT, &gre_module_tag_id);
	if (err != 0) {
		printf("%s: mbuf_tag_id_find failed: %d\n", __FUNCTION__, err);
		return err;
	} else if ((gre_module_tag_id & 0xffff) != gre_module_tag_id) {
		printf("%s: gre_if_family overflow: %d\n", __FUNCTION__, gre_module_tag_id);
		return ENOENT;
	}

#ifdef DEBUG
	printf("%s: gre_module_tag_id -> %d\n", __FUNCTION__, gre_module_tag_id);
#endif

	gre_encap_lck = lck_rw_alloc_init(gre_lck_grp, gre_lck_attributes);
	if (gre_encap_lck == NULL) {
		printf("%s: lck_rw_alloc_init failed\n", __FUNCTION__);
		return ENOMEM;
	}

	LIST_INIT(&gre_encaptab);

#ifdef DEBUG
	printf("%s: done\n", __FUNCTION__);
#endif
	return 0;
}

errno_t
gre_encap_dispose(void)
{
#ifdef DEBUG
	printf("%s ...\n", __FUNCTION__);
#endif
	if (!gre_encap_lck)
		return 0;

	lck_rw_lock_shared(gre_encap_lck);
	int list_empty = LIST_EMPTY(&gre_encaptab);
	lck_rw_unlock_shared(gre_encap_lck);

	if (!list_empty) {
		printf("%s gre_encap_dispose dispose error, encap tab not empty", __FUNCTION__);
		return EBUSY;
	}

	lck_rw_free(gre_encap_lck, gre_lck_grp);

#ifdef DEBUG
	printf("%s: done\n", __FUNCTION__);
#endif
	return 0;
}


int
gre_encap4_input(mbuf_t m, int off)
{

	int proto;
	struct ip *ip;
	struct sockaddr_in s, d;
	//const struct protosw *psw;
	void (*pr_input)(mbuf_t *, int *, int, void *);
	struct gre_encaptab *ep, *match;
	void *arg;
	int prio, matchprio;

	/* Expect 32-bit aligned data pointer on strict-align platforms */
	//MBUF_STRICT_DATA_ALIGNMENT_CHECK_32(m);

	ip = mtod(m, struct ip *);
	proto = ip->ip_p;

	bzero(&s, sizeof(s));
	s.sin_family = AF_INET;
	s.sin_len = sizeof(struct sockaddr_in);
	s.sin_addr = ip->ip_src;
	bzero(&d, sizeof(d));
	d.sin_family = AF_INET;
	d.sin_len = sizeof(struct sockaddr_in);
	d.sin_addr = ip->ip_dst;

	match = NULL;
	matchprio = 0;
	lck_rw_lock_shared(gre_encap_lck);
	for (ep = LIST_FIRST(&gre_encaptab); ep; ep = LIST_NEXT(ep, chain)) {
		if (ep->af != AF_INET)
			continue;
		if (ep->proto >= 0 && ep->proto != proto)
			continue;
		if (ep->func)
			prio = (*ep->func)(m, off, proto, ep->arg);
		else {
			/*
			 * it's inbound traffic, we need to match in reverse
			 * order
			 */
			prio = gre_mask_match(ep, (struct sockaddr *)&d,
					  (struct sockaddr *)&s);
		}

		/*
		 * We prioritize the matches by using bit length of the
		 * matches.  mask_match() and user-supplied matching function
		 * should return the bit length of the matches (for example,
		 * if both src/dst are matched for IPv4, 64 should be returned).
		 * 0 or negative return value means "it did not match".
		 *
		 * The question is, since we have two "mask" portion, we
		 * cannot really define total order between entries.
		 * For example, which of these should be preferred?
		 * mask_match() returns 48 (32 + 16) for both of them.
		 *      src=3ffe::/16, dst=3ffe:501::/32
		 *      src=3ffe:501::/32, dst=3ffe::/16
		 *
		 * We need to loop through all the possible candidates
		 * to get the best match - the search takes O(n) for
		 * n attachments (i.e. interfaces).
		 */
		if (prio <= 0)
			continue;
		if (prio > matchprio) {
			matchprio = prio;
			match = ep;
		}
	}
	if (match) {
		pr_input = match->pr_input;
		arg = match->arg;
	}
	lck_rw_unlock_shared(gre_encap_lck);

	if (match) {
		/* found a match, "match" has the best one */
//		psw = (const struct protosw *)match->psw;
//		if (psw && psw->pr_input) {
//			encap_fillarg(m, match);
//			(*psw->pr_input)(m, off);
//		} else
//			m_freem(m);
		if (pr_input) {
			//gre_encap_fillarg(m, arg);
			(*pr_input)(&m, &off, proto, arg);
		} else
			m_freem(m);
		return EJUSTRETURN;
	}

	return 0; // not interested
}



int
gre_encap6_input(mbuf_t *mp, int *offp, int proto)
{
	mbuf_t m = *mp;
	struct ip6_hdr *ip6;
	struct sockaddr_in6 s, d;
	//const struct ip6protosw *psw;
	void (*pr_input)(mbuf_t *, int *, int, void *);
	struct gre_encaptab *ep, *match;
	void *arg;
	int prio, matchprio;

	/* Expect 32-bit aligned data pointer on strict-align platforms */
	//MBUF_STRICT_DATA_ALIGNMENT_CHECK_32(m);

	ip6 = mtod(m, struct ip6_hdr *);
	bzero(&s, sizeof(s));
	s.sin6_family = AF_INET6;
	s.sin6_len = sizeof(struct sockaddr_in6);
	s.sin6_addr = ip6->ip6_src;
	bzero(&d, sizeof(d));
	d.sin6_family = AF_INET6;
	d.sin6_len = sizeof(struct sockaddr_in6);
	d.sin6_addr = ip6->ip6_dst;

	match = NULL;
	matchprio = 0;
	lck_rw_lock_shared(gre_encap_lck);
	for (ep = LIST_FIRST(&gre_encaptab); ep; ep = LIST_NEXT(ep, chain)) {
		if (ep->af != AF_INET6)
			continue;
		if (ep->proto >= 0 && ep->proto != proto)
			continue;
		if (ep->func)
			prio = (*ep->func)(m, *offp, proto, ep->arg);
		else {
			/*
			 * it's inbound traffic, we need to match in reverse
			 * order
			 */
			prio = gre_mask_match(ep, (struct sockaddr *)&d,
					  (struct sockaddr *)&s);
		}

		/* see encap4_input() for issues here */
		if (prio <= 0)
			continue;
		if (prio > matchprio) {
			matchprio = prio;
			match = ep;
		}
	}
	if (match) {
		pr_input = match->pr_input;
		arg = match->arg;
	}
	lck_rw_unlock_shared(gre_encap_lck);

	if (match) {
		/* found a match */
//		psw = (const struct ip6protosw *)match->psw;
//		if (psw && psw->pr_input) {
//			encap_fillarg(m, match);
//			return (*psw->pr_input)(mp, offp, proto);
//		} else {
//			m_freem(m);
//			return IPPROTO_DONE;
//		}
		if (pr_input) {
			//gre_encap_fillarg(m, arg);
			(*pr_input)(mp, offp, proto, arg);
		} else
			m_freem(m);
		return EJUSTRETURN;
	}

	return 0; // not interested
}


static void
gre_encap_add(ep)
struct gre_encaptab *ep;
{

	//mtx_assert(&encapmtx, MA_OWNED);
	LIST_INSERT_HEAD(&gre_encaptab, ep, chain);
}


/*
 * sp (src ptr) is always my side, and dp (dst ptr) is always remote side.
 * length of mask (sm and dm) is assumed to be same as sp/dp.
 * Return value will be necessary as input (cookie) for encap_detach().
 */
const struct gre_encaptab *
gre_encap_attach(af, proto, sp, sm, dp, dm, pr_input, arg)
int af;
int proto;
const struct sockaddr *sp, *sm;
const struct sockaddr *dp, *dm;
void (*pr_input)(mbuf_t *, int *, int, void *);
void *arg;
{
	struct gre_encaptab *ep;
	int error;

	/* sanity check on args */
	if (sp->sa_len > sizeof(ep->src) || dp->sa_len > sizeof(ep->dst)) {
		error = EINVAL;
		goto fail;
	}
	if (sp->sa_len != dp->sa_len) {
		error = EINVAL;
		goto fail;
	}
	if (af != sp->sa_family || af != dp->sa_family) {
		error = EINVAL;
		goto fail;
	}

	/* check if anyone have already attached with exactly same config */
	lck_rw_lock_exclusive(gre_encap_lck);
	for (ep = LIST_FIRST(&gre_encaptab); ep; ep = LIST_NEXT(ep, chain)) {
		if (ep->af != af)
			continue;
		if (ep->proto != proto)
			continue;
		if (ep->src.ss_len != sp->sa_len ||
		    bcmp(&ep->src, sp, sp->sa_len) != 0 ||
		    bcmp(&ep->srcmask, sm, sp->sa_len) != 0)
			continue;
		if (ep->dst.ss_len != dp->sa_len ||
		    bcmp(&ep->dst, dp, dp->sa_len) != 0 ||
		    bcmp(&ep->dstmask, dm, dp->sa_len) != 0)
			continue;

		error = EEXIST;
		lck_rw_unlock_exclusive(gre_encap_lck);
		goto fail;
	}

	ep = _MALLOC(sizeof(*ep), M_TEMP, M_WAITOK); /*XXX*/
	if (ep == NULL) {
		error = ENOBUFS;
		lck_rw_unlock_exclusive(gre_encap_lck);
		goto fail;
	}
	bzero(ep, sizeof(*ep));

	ep->af = af;
	ep->proto = proto;
	bcopy(sp, &ep->src, sp->sa_len);
	bcopy(sm, &ep->srcmask, sp->sa_len);
	bcopy(dp, &ep->dst, dp->sa_len);
	bcopy(dm, &ep->dstmask, dp->sa_len);
	ep->pr_input = pr_input;
	ep->arg = arg;

	gre_encap_add(ep);
	lck_rw_unlock_exclusive(gre_encap_lck);

	error = 0;
	return ep;

fail:
	return NULL;
}


const struct gre_encaptab *
gre_encap_attach_func(af, proto, func, pr_input, arg)
int af;
int proto;
int (*func)(const mbuf_t , int, int, void *);
void (*pr_input)(mbuf_t *, int *, int, void *);
void *arg;
{
#ifdef DEBUG
	printf("%s ...\n", __FUNCTION__);
#endif
	struct gre_encaptab *ep;
	int error;

	/* sanity check on args */
	if (!func) {
		error = EINVAL;
		goto fail;
	}

	ep = _MALLOC(sizeof(*ep), M_TEMP, M_WAITOK); /*XXX*/
	if (ep == NULL) {
		error = ENOBUFS;
		goto fail;
	}
	bzero(ep, sizeof(*ep));

	ep->af = af;
	ep->proto = proto;
	ep->func = func;
	ep->pr_input = pr_input;
	ep->arg = arg;

	lck_rw_lock_exclusive(gre_encap_lck);
	gre_encap_add(ep);
	lck_rw_unlock_exclusive(gre_encap_lck);

	error = 0;
#ifdef DEBUG
	printf("%s done\n", __FUNCTION__);
#endif
	return ep;

fail:
#ifdef DEBUG
	printf("%s failed\n", __FUNCTION__);
#endif
	return NULL;
}


int
gre_encap_detach(const struct gre_encaptab *cookie)
{
#ifdef DEBUG
	printf("%s ...\n", __FUNCTION__);
#endif
	const struct gre_encaptab *ep = cookie;
	struct gre_encaptab *p;
	lck_rw_lock_exclusive(gre_encap_lck);
	for (p = LIST_FIRST(&gre_encaptab); p; p = LIST_NEXT(p, chain)) {
		if (p == ep) {
			LIST_REMOVE(p, chain);
			lck_rw_unlock_exclusive(gre_encap_lck);
			_FREE(p, M_TEMP);
#ifdef DEBUG
			printf("%s done\n", __FUNCTION__);
#endif
			return 0;
		}
	}
	lck_rw_unlock_exclusive(gre_encap_lck);

#ifdef DEBUG
	printf("%s failed\n", __FUNCTION__);
#endif
	return EINVAL;
}


static int
gre_mask_match(ep, sp, dp)
const struct gre_encaptab *ep;
const struct sockaddr *sp;
const struct sockaddr *dp;
{
	struct sockaddr_storage s;
	struct sockaddr_storage d;
	int i;
	const u_int8_t *p, *q;
	u_int8_t *r;
	int matchlen;

	if (sp->sa_len > sizeof(s) || dp->sa_len > sizeof(d))
		return 0;
	if (sp->sa_family != ep->af || dp->sa_family != ep->af)
		return 0;
	if (sp->sa_len != ep->src.ss_len || dp->sa_len != ep->dst.ss_len)
		return 0;

	matchlen = 0;

	p = (const u_int8_t *)sp;
	q = (const u_int8_t *)&ep->srcmask;
	r = (u_int8_t *)&s;
	for (i = 0 ; i < sp->sa_len; i++) {
		r[i] = p[i] & q[i];
		/* XXX estimate */
		matchlen += (q[i] ? 8 : 0);
	}

	p = (const u_int8_t *)dp;
	q = (const u_int8_t *)&ep->dstmask;
	r = (u_int8_t *)&d;
	for (i = 0 ; i < dp->sa_len; i++) {
		r[i] = p[i] & q[i];
		/* XXX rough estimate */
		matchlen += (q[i] ? 8 : 0);
	}

	/* need to overwrite len/family portion as we don't compare them */
	s.ss_len = sp->sa_len;
	s.ss_family = sp->sa_family;
	d.ss_len = dp->sa_len;
	d.ss_family = dp->sa_family;

	if (bcmp(&s, &ep->src, ep->src.ss_len) == 0 &&
	    bcmp(&d, &ep->dst, ep->dst.ss_len) == 0) {
		return matchlen;
	} else
		return 0;
}


// FIXME: bugs here...
static void
gre_encap_fillarg(
	      mbuf_t m,
	      void *arg)
{
	void **et;

	if (mbuf_tag_allocate(m, GRE_MODULE_TAG_ID, GRE_TAG_TYPE_ENCAP,
			      sizeof(et), MBUF_WAITOK, (void **)&et) == 0) {
#ifdef DEBUG
		printf("%s mbuf_tag_allocate OK %p\n", __FUNCTION__, et);
#endif
		*et = arg;
	}
#ifdef DEBUG
	else {
		printf("%s mbuf_tag_allocate failed\n", __FUNCTION__);
	}
#endif
}


// FIXME: bugs here...
void *
gre_encap_getarg(mbuf_t m)
{
	void *p = NULL;

	size_t length = 0;
	if (mbuf_tag_find(m, GRE_MODULE_TAG_ID, GRE_TAG_TYPE_ENCAP, &length, (void**)&p) == 0) {
		mbuf_tag_free(m, GRE_MODULE_TAG_ID, GRE_TAG_TYPE_ENCAP);
#ifdef DEBUG
		printf("%s found %p\n", __FUNCTION__, p);
#endif
	}

//	tag = m_tag_locate(m, KERNEL_MODULE_TAG_ID, KERNEL_TAG_TYPE_ENCAP, NULL);
//	if (tag) {
//		et = (struct encaptabtag*)(tag + 1);
//		p = et->arg;
//		m_tag_delete(m, tag);
//	}

	return p;
}
