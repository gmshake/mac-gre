#include <mach/mach_types.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/lock.h>

#include <net/if_var.h>
#include <net/kpi_protocol.h>

#include "gre_domain.h"
#include "gre_ipfilter.h"
#include "gre_hash.h"
#include "gre_debug.h"

extern int gre_init();
extern int gre_dispose();
extern int gre_attach();
extern errno_t gre_attach_proto_family(ifnet_t ifp, protocol_family_t protocol);
extern void gre_detach_proto_family(ifnet_t ifp, protocol_family_t protocol);

static int gre_inited = 0;

lck_grp_t *gre_lck_grp = NULL;

kern_return_t gre_start (kmod_info_t * ki, void * data)
{
    if (gre_inited)
        return KERN_SUCCESS;
    
    /* globle lock group */
    gre_lck_grp = lck_grp_alloc_init("GRE locks", LCK_GRP_ATTR_NULL);
    
    /* if something fails, the lock won't work */
    if (gre_lck_grp == NULL) {
        printf("%s: lck_grp_alloc_init failed\n", __FUNCTION__);
        return KERN_FAILURE;
    }
    
    if (gre_domain_init() != 0)
        goto error;
    if (gre_hash_init() != 0)
        goto error;
    
    
    int err;
    /* register INET, INET6 adn APPLETALK protocol families */
    err = proto_register_plumber(PF_INET, APPLE_IF_FAM_TUN, gre_attach_proto_family, gre_detach_proto_family);
    if (err)
        printf("gre: could not register AF_INET protocol family: %d\n", err);
    err = proto_register_plumber(PF_INET6, APPLE_IF_FAM_TUN, gre_attach_proto_family, gre_detach_proto_family);
    if (err)
        printf("gre: could not register AF_INET6 protocol family: %d\n", err);
    err = proto_register_plumber(PF_APPLETALK, APPLE_IF_FAM_TUN, gre_attach_proto_family, gre_detach_proto_family);
    if (err)
        printf("gre: could not register AF_APPLETALK protocol family: %d\n", err);
    
    if (gre_init() != 0)
		goto error;
    if (gre_ipfilter_init() != 0)
        goto error;
    
    gre_inited = 1;
    return KERN_SUCCESS;
    
error:
    gre_domain_dispose();
    gre_hash_dispose();
    gre_dispose();
    gre_ipfilter_dispose();
    
    proto_unregister_plumber(PF_APPLETALK, APPLE_IF_FAM_TUN);
    proto_unregister_plumber(PF_INET6, APPLE_IF_FAM_TUN);
    proto_unregister_plumber(PF_INET, APPLE_IF_FAM_TUN);

    if (gre_lck_grp)
        lck_grp_free(gre_lck_grp);
    return KERN_FAILURE;
}


kern_return_t gre_stop (kmod_info_t * ki, void * data)
{
    if (!gre_inited)
        return KERN_SUCCESS;
#ifdef DEBUG
    printf("%s: starting unregister_plumber...\n", __FUNCTION__);
#endif
    proto_unregister_plumber(PF_APPLETALK, APPLE_IF_FAM_TUN);
    proto_unregister_plumber(PF_INET6, APPLE_IF_FAM_TUN);
    proto_unregister_plumber(PF_INET, APPLE_IF_FAM_TUN);
#ifdef DEBUG
    printf("%s: unregister_plumber done\n", __FUNCTION__);
#endif
    
    if (gre_ipfilter_dispose()) {
        printf("gre: gre_ipfilter_dispose error\n");
        return KERN_FAILURE;
    }
    
    if (gre_dispose()) {
        printf("gre: gre_dispose error\n");
        return KERN_FAILURE;
    }
    
    gre_hash_dispose();
    
    if (gre_domain_dispose()) {
        printf("gre: gre_domain_dispose error\n");
        return KERN_FAILURE;
    }
    
    lck_grp_free(gre_lck_grp);

    gre_inited = 0;
    return KERN_SUCCESS;
}
