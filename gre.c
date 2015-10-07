//
//  gre.c
//  gre
//
//  Created by Zhenlei Huang.
//
//

#include <mach/mach_types.h>
#include <sys/systm.h>
#include <sys/kernel.h>

#include "gre_locks.h"
#include "gre_ipfilter.h"
#include "gre_hash.h"
#include "gre_if.h"
#include "gre_ip_encap.h"


static int gre_init;

kern_return_t
gre_start(kmod_info_t *ki, void *data)
{
#ifdef DEBUG
	printf("%s ...\n", __FUNCTION__);
#endif
	if (gre_init)
		goto success;

	if (gre_locks_init() != 0)
		goto failed;

	if (gre_encap_init())
		goto failed;

#if USE_GRE_HASH
	if (gre_hash_init() != 0)
		goto error;
#endif

	if (gre_proto_register() != 0)
		goto error;

	if (gre_if_init() != 0)
		goto error;

	if (gre_ip4filter_init() != 0)
		goto error;

	if (gre_ip6filter_init() != 0)
		goto error;

	/* add first gre interface */
	gre_if_attach();


	gre_init = 1;

success:
#ifdef DEBUG
	printf("%s: done\n", __FUNCTION__);
#endif
	return KERN_SUCCESS;

error:
	gre_ip6filter_dispose();
	gre_ip4filter_dispose();
	gre_if_dispose();
	gre_proto_unregister();
#if USE_GRE_HASH
	gre_hash_dispose();
#endif
	gre_encap_dispose();
	gre_locks_dispose();

failed:

#ifdef DEBUG
	printf("%s: fail\n", __FUNCTION__);
#endif
	return KERN_FAILURE;
}


kern_return_t gre_stop(kmod_info_t *ki, void *data)
{
#ifdef DEBUG
	printf("%s ...\n", __FUNCTION__);
#endif
	if (!gre_init)
		goto success;

	if (gre_ip6filter_dispose()) {
		printf("gre: gre_ip6filter_dispose error\n");
		goto failed;
	}

	if (gre_ip4filter_dispose()) {
		printf("gre: gre_ip4filter_dispose error\n");
		goto failed;
	}

#ifdef DEBUG
	extern unsigned int get_ngre();
	printf("%s: before gre_dispose, current ngre = %d\n", __FUNCTION__, get_ngre());
#endif

	if (gre_if_dispose()) {
		printf("gre: gre_dispose error\n");
		goto failed;
	}

#ifdef DEBUG
	printf("%s: before gre_hash_dispose, current ngre = %d\n", __FUNCTION__, get_ngre());
#endif

	gre_proto_unregister();

#if USE_GRE_HASH
	gre_hash_dispose();
#endif

#ifdef DEBUG
	printf("%s: current ngre = %d\n", __FUNCTION__, get_ngre());
#endif

	if (gre_encap_dispose()) {
		printf("gre: gre_encap_dispose error\n");
		goto failed;
	}

	gre_locks_dispose();

	gre_init = 0;

success:
#ifdef DEBUG
	printf("%s: done\n", __FUNCTION__);
#endif
	return KERN_SUCCESS;

failed:
#ifdef DEBUG
	printf("%s: fail\n", __FUNCTION__);
#endif
	return KERN_FAILURE;
}
