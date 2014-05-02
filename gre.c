#include <mach/mach_types.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/sysctl.h>
#include <sys/socket.h>

#include <net/if_types.h>
#include <net/if_var.h>
#include <net/kpi_protocol.h>

#include "gre_ipfilter.h"
#include "gre_hash.h"
#include "gre_if.h"


lck_grp_t *gre_lck_grp = NULL;

kern_return_t gre_start(kmod_info_t *ki, void *data)
{
#ifdef DEBUG
    printf("%s ...\n", __FUNCTION__);
#endif
    if (gre_lck_grp)
        goto success;

    /* globle lock group */
    gre_lck_grp = lck_grp_alloc_init("GRE locks", LCK_GRP_ATTR_NULL);

    /* if the allocation of lck_grp fails, the KEXT won't work */
    if (gre_lck_grp == NULL) {
        printf("%s: lck_grp_alloc_init failed\n", __FUNCTION__);
        goto failed;
    }

    if (gre_proto_register() != 0)
        goto error;

    if (gre_hash_init() != 0)
        goto error;

    if (gre_if_init() != 0)
        goto error;

    if (gre_ipfilter_init() != 0)
        goto error;

    /* add first gre interface */
    gre_if_attach();

success:
#ifdef DEBUG
    printf("%s: done\n", __FUNCTION__);
#endif
    return KERN_SUCCESS;

error:
    gre_ipfilter_dispose();
    gre_if_dispose();
    gre_hash_dispose();
    gre_proto_unregister();

    lck_grp_free(gre_lck_grp);
    gre_lck_grp = NULL;

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
    if (gre_lck_grp == NULL)
        goto success;

    if (gre_ipfilter_dispose()) {
        printf("gre: gre_ipfilter_dispose error\n");
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

    gre_hash_dispose();

    gre_proto_unregister();

#ifdef DEBUG
    printf("%s: current ngre = %d\n", __FUNCTION__, get_ngre());
#endif

    lck_grp_free(gre_lck_grp);
    gre_lck_grp = NULL;

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
