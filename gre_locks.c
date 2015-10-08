//
//  gre_locks.c
//  gre
//
//  Created by Zhenlei Huang on 10/4/15.
//
//

#include <sys/systm.h>
#include <sys/lock.h>


void gre_locks_dispose(void);


static lck_grp_attr_t	*gre_grp_attributes;

lck_grp_t	*gre_lck_grp;
#if USE_GRE_HASH
lck_grp_t	*gre_hash_lck_grp;
#endif
lck_grp_t	*gre_ipf_lck_grp;
lck_grp_t	*gre_sc_lck_grp;

lck_attr_t	*gre_lck_attributes;
#if USE_GRE_HASH
lck_attr_t	*gre_hash_lck_attributes;
#endif
lck_attr_t	*gre_ipf_lck_attributes;
lck_attr_t	*gre_sc_lck_attributes;


int
gre_locks_init(void)
{
#ifdef DEBUG
	printf("%s ...\n", __FUNCTION__);
#endif
	gre_grp_attributes = lck_grp_attr_alloc_init();
	if (!gre_grp_attributes) {
		printf("%s: lck_grp_attr_alloc_init() failed\n", __FUNCTION__);
		goto error;
	}

	/* global gre lock group */
	gre_lck_grp = lck_grp_alloc_init("GRE lock group", gre_grp_attributes);
	if (!gre_lck_grp) {
		printf("%s: lck_grp_alloc_init() failed\n", __FUNCTION__);
		goto error;
	}

#if USE_GRE_HASH
	/* global gre hash lock group */
	gre_hash_lck_grp = lck_grp_alloc_init("GRE hash lock group", gre_grp_attributes);
	if (!gre_hash_lck_grp) {
		printf("%s: lck_grp_alloc_init() failed\n", __FUNCTION__);
		goto error;
	}
#endif

	/* ipfilter gre hash lock group */
	gre_ipf_lck_grp = lck_grp_alloc_init("GRE ipfilter lock group", gre_grp_attributes);
	if (!gre_ipf_lck_grp) {
		printf("%s: lck_grp_alloc_init() failed\n", __FUNCTION__);
		goto error;
	}

	/* global gre softc lock group */
	gre_sc_lck_grp = lck_grp_alloc_init("GRE softc lock group", gre_grp_attributes);
	if (!gre_sc_lck_grp) {
		printf("%s: lck_grp_alloc_init() failed\n", __FUNCTION__);
		goto error;
	}


	gre_lck_attributes = lck_attr_alloc_init();
	if (!gre_lck_attributes) {
		printf("%s: lck_attr_alloc_init() failed\n", __FUNCTION__);
		goto error;
	}

#if USE_GRE_HASH
	gre_hash_lck_attributes = lck_attr_alloc_init();
	if (!gre_hash_lck_attributes) {
		printf("%s: lck_attr_alloc_init() failed\n", __FUNCTION__);
		goto error;
	}
#endif

	gre_ipf_lck_attributes = lck_attr_alloc_init();
	if (!gre_ipf_lck_attributes) {
		printf("%s: lck_attr_alloc_init() failed\n", __FUNCTION__);
		goto error;
	}

	gre_sc_lck_attributes = lck_attr_alloc_init();
	if (!gre_sc_lck_attributes) {
		printf("%s: lck_attr_alloc_init() failed\n", __FUNCTION__);
		goto error;
	}


#ifdef DEBUG
	printf("%s done\n", __FUNCTION__);
#endif
	return 0;

error:
	gre_locks_dispose();

#ifdef DEBUG
	printf("%s failed\n", __FUNCTION__);
#endif
	return -1;
}


void
gre_locks_dispose(void)
{
#ifdef DEBUG
	printf("%s ...\n", __FUNCTION__);
#endif
	if (gre_sc_lck_attributes) {
		lck_attr_free(gre_sc_lck_attributes);
		gre_sc_lck_attributes = LCK_ATTR_NULL;
	}

	if (gre_ipf_lck_attributes) {
		lck_attr_free(gre_ipf_lck_attributes);
		gre_ipf_lck_attributes = LCK_ATTR_NULL;
	}

#if USE_GRE_HASH
	if (gre_hash_lck_attributes) {
		lck_attr_free(gre_hash_lck_attributes);
		gre_hash_lck_attributes = LCK_ATTR_NULL;
	}
#endif

	if (gre_lck_attributes) {
		lck_attr_free(gre_lck_attributes);
		gre_lck_attributes = LCK_ATTR_NULL;
	}

	if (gre_sc_lck_grp) {
		lck_grp_free(gre_sc_lck_grp);
		gre_sc_lck_grp = (lck_grp_t *)0;
	}

	if (gre_ipf_lck_grp) {
		lck_grp_free(gre_ipf_lck_grp);
		gre_ipf_lck_grp = (lck_grp_t *)0;
	}

#if USE_GRE_HASH
	if (gre_hash_lck_grp) {
		lck_grp_free(gre_hash_lck_grp);
		gre_hash_lck_grp = (lck_grp_t *)0;
	}
#endif

	if (gre_lck_grp) {
		lck_grp_free(gre_lck_grp);
		gre_lck_grp = (lck_grp_t *)0;
	}

	if (gre_grp_attributes) {
		lck_grp_attr_free(gre_grp_attributes);
		gre_grp_attributes = LCK_GRP_ATTR_NULL;
	}

#ifdef DEBUG
	printf("%s done\n", __FUNCTION__);
#endif
}
