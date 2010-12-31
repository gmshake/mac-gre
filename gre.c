#include <mach/mach_types.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/lock.h>

#include <net/if_var.h>
#include <net/kpi_protocol.h>

#include "gre_ipfilter.h"

#include "gre_debug.h"
#ifdef DEBUG
#include "gre_seq.h"
#endif

extern int gre_init();
extern int gre_dispose();
extern int gre_attach();
extern errno_t gre_attach_proto_family(ifnet_t ifp, protocol_family_t protocol);
extern void gre_detach_proto_family(ifnet_t ifp, protocol_family_t protocol);

static int gre_inited = 0;

lck_grp_t *gre_lck_grp = NULL;

kern_return_t gre_start (kmod_info_t * ki, void * data) {
    int err;
    
    if (gre_inited)
        return KERN_SUCCESS;
    
    // globle lock group
    gre_lck_grp = lck_grp_alloc_init("GRE locks", LCK_GRP_ATTR_NULL);

    if (gre_lck_grp == NULL) {
        /* if something fails, the lock won't work */
        printf("%s: lck_grp_alloc_init failed\n", __FUNCTION__);
        return KERN_FAILURE;
    }

    if (gre_ipfilter_init() != 0)
        goto end;
    if (gre_init() != 0)
		goto end;

    /* register INET and INET6 protocol families */
    err = proto_register_plumber(AF_INET, APPLE_IF_FAM_TUN, gre_attach_proto_family, gre_detach_proto_family);
    if (err)
        printf("gre: could not register AF_INET protocol family: %d\n", err);

    err = proto_register_plumber(AF_INET6, APPLE_IF_FAM_TUN, gre_attach_proto_family, gre_detach_proto_family);
    if (err)
        printf("gre: could not register AF_INET6 protocol family: %d\n", err);
    
    // attach the first interface
    gre_attach();
    gre_inited = 1;
    return KERN_SUCCESS;
    
end:
    gre_ipfilter_dispose();

    if (gre_lck_grp)
        lck_grp_free(gre_lck_grp);

    return KERN_FAILURE;
}


kern_return_t gre_stop (kmod_info_t * ki, void * data) {
    int err;
    
    if (!gre_inited)
        return KERN_SUCCESS;
    
    proto_unregister_plumber(AF_INET6, APPLE_IF_FAM_TUN);
    proto_unregister_plumber(AF_INET, APPLE_IF_FAM_TUN);
    
    err = gre_dispose();
    if (err) {
        dprintf("%s: gre_dispose error = 0x%x\n", __FUNCTION__, err);
        return KERN_FAILURE;
    }
    
    gre_ipfilter_dispose();
    
    lck_grp_free(gre_lck_grp);

    gre_inited = 0;
    return KERN_SUCCESS;
}
