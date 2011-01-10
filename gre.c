#include <mach/mach_types.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/lock.h>

#include <net/if_var.h>
#include <net/kpi_protocol.h>

#include "gre_ipfilter.h"
#include "gre_pcb.h"
#include "gre_debug.h"

extern int gre_init();
extern int gre_dispose();
extern int gre_attach();
extern errno_t gre_attach_proto_family(ifnet_t ifp, protocol_family_t protocol);
extern void gre_detach_proto_family(ifnet_t ifp, protocol_family_t protocol);

static int gre_inited = 0;

lck_grp_t *gre_lck_grp = NULL;

kern_return_t gre_start (kmod_info_t * ki, void * data) {
    if (gre_inited)
        return KERN_SUCCESS;
    
    /* globle lock group */
    gre_lck_grp = lck_grp_alloc_init("GRE locks", LCK_GRP_ATTR_NULL);
    
    /* if something fails, the lock won't work */
    if (gre_lck_grp == NULL) {
        printf("%s: lck_grp_alloc_init failed\n", __FUNCTION__);
        return KERN_FAILURE;
    }
    
    if (gre_hash_init() != 0)
        goto error;
    if (gre_ipfilter_init() != 0)
        goto error;
    if (gre_init() != 0)
		goto error;
    
    int err;
    /* register INET, INET6 adn APPLETALK protocol families */
    err = proto_register_plumber(AF_INET, APPLE_IF_FAM_TUN, gre_attach_proto_family, gre_detach_proto_family);
    if (err)
        printf("gre: could not register AF_INET protocol family: %d\n", err);
    err = proto_register_plumber(AF_INET6, APPLE_IF_FAM_TUN, gre_attach_proto_family, gre_detach_proto_family);
    if (err)
        printf("gre: could not register AF_INET6 protocol family: %d\n", err);
    err = proto_register_plumber(AF_APPLETALK, APPLE_IF_FAM_TUN, gre_attach_proto_family, gre_detach_proto_family);
    if (err)
        printf("gre: could not register AF_APPLETALK protocol family: %d\n", err);
    
    gre_attach(); /* attach the first interface */
    gre_ipfilter_attach(); /* attach ip filter */
    
    gre_inited = 1;
    return KERN_SUCCESS;
    
error:
    gre_hash_dispose();
    gre_ipfilter_dispose();

    if (gre_lck_grp)
        lck_grp_free(gre_lck_grp);
    return KERN_FAILURE;
}


kern_return_t gre_stop (kmod_info_t * ki, void * data) {
    if (!gre_inited)
        return KERN_SUCCESS;
    
    if (gre_ipfilter_detach())
        return KERN_FAILURE;
    
    proto_unregister_plumber(AF_APPLETALK, APPLE_IF_FAM_TUN);
    proto_unregister_plumber(AF_INET6, APPLE_IF_FAM_TUN);
    proto_unregister_plumber(AF_INET, APPLE_IF_FAM_TUN);
    
    if (gre_dispose()) {
        printf("gre: gre_dispose error\n");
        return KERN_FAILURE;
    }
    
    gre_ipfilter_dispose();
    gre_hash_dispose();
    
    lck_grp_free(gre_lck_grp);

    gre_inited = 0;
    return KERN_SUCCESS;
}
