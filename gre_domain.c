/*
 *  gre_domain.c
 *  gre
 *
 *  Created by Summer Town on 1/10/11.
 *  Copyright 2011 __MyCompanyName__. All rights reserved.
 *
 */

#include <sys/systm.h>
#include <sys/sysctl.h>
#include <sys/socket.h>

#include <net/if.h>
#include <net/if_types.h>

#include <netinet/in.h>
#include <netinet/in_var.h>

#include "gre_if.h"
#include "in_gre.h"
#include "protosw.h"
#include "domain.h"
#include "gre_config.h"

struct socket;

//extern lck_mtx_t *rt_mtx;
extern lck_mtx_t *ip_mutex;
#ifdef DEBUG
extern lck_mtx_t *inet_domain_mutex;
#endif
extern struct protosw *ip_protox[IPPROTO_MAX];

extern unsigned int max_gre_nesting;
extern lck_grp_t *gre_lck_grp;

static lck_mtx_t *gre_domain_lck = NULL;
static struct domain *inet_domain = NULL;
#if PROTO_WITH_GRE
struct protosw *old_pr_gre;
#endif
struct protosw *old_pr_mobile;

extern int sosend(struct socket *, struct sockaddr *, struct uio *, struct mbuf *, struct mbuf *, int );
extern int soreceive(struct socket *, struct sockaddr **, struct uio *, struct mbuf **, struct mbuf **, int *);

int gre_proto_attach(struct socket *, int, struct proc *);
int gre_proto_detach(struct socket *);
int	gre_proto_ioctl(struct socket *, u_long, caddr_t, struct ifnet *, struct proc *);

struct pr_usrreqs gre_usrreqs = {
pru_abort_notsupp, pru_accept_notsupp, gre_proto_attach, pru_bind_notsupp, pru_connect_notsupp,
pru_connect2_notsupp, gre_proto_ioctl, gre_proto_detach, pru_disconnect_notsupp,
pru_listen_notsupp, pru_peeraddr_notsupp, pru_rcvd_notsupp,
pru_rcvoob_notsupp, pru_send_notsupp, pru_sense_null, pru_shutdown_notsupp,
pru_sockaddr_notsupp, sosend, soreceive, pru_sopoll_notsupp
};

#if PROTO_WITH_GRE
static struct protosw in_gre_protosw = {
        .pr_type =              SOCK_RAW,
        .pr_domain =            NULL,
        .pr_protocol =          IPPROTO_GRE,
        .pr_flags =             PR_ATOMIC|PR_ADDR|PR_PROTOLOCK,
        .pr_input =             in_gre_input,
        .pr_ctloutput =         NULL,
        .pr_usrreqs =           &gre_usrreqs
};
#endif
static struct protosw in_mobile_protosw = {
        .pr_type =              SOCK_RAW,
        .pr_domain =            NULL,
        .pr_protocol =          IPPROTO_MOBILE,
        .pr_flags =             PR_ATOMIC|PR_ADDR|PR_PROTOLOCK,
        .pr_input =             gre_mobile_input,
        .pr_ctloutput =         NULL,
        .pr_usrreqs =           &gre_usrreqs
};


SYSCTL_DECL(_net);
SYSCTL_NODE(_net, IFT_OTHER, gre, CTLFLAG_RW, 0, "Generic Routing Encapsulation");
SYSCTL_UINT(_net_gre, OID_AUTO, maxnesting, CTLTYPE_INT | CTLFLAG_RW, &max_gre_nesting, 0, "Max nested tunnels");

extern struct domain *pffinddomain(int);

int gre_domain_init()
{
    if (gre_domain_lck) {
#ifdef DEBUG
        printf("%s: has already inited\n", __FUNCTION__);
#endif
        return 0;
    }

    inet_domain = pffinddomain(AF_INET);
    if (!inet_domain) {
        printf("%s: AF_INET domain does not exist, should panic...\n", __FUNCTION__);
        return KERN_FAILURE; // or panic(...) ?
    }
    
#ifdef DEBUG   
    struct protosw *pr = pffindproto(PF_INET, IPPROTO_RAW, SOCK_RAW);
    if (!pr) {
        printf("%s: unable to find IPPROTO_RAW proto, should panic...\n", __FUNCTION__);
        return KERN_FAILURE; // or panic(...) ?
    }
#endif
#if PROTO_WITH_GRE
    in_gre_protosw.pr_domain    = inet_domain;
#endif
    in_mobile_protosw.pr_domain = inet_domain;
    gre_domain_lck = inet_domain->dom_mtx;
    
#ifdef DEBUG
    if (gre_domain_lck != inet_domain_mutex)
        printf("%s: inet_domain_mutex is different\n", __FUNCTION__);
#endif
    
    /*
     * there seems to be some bug here, that is anoying
     */
    sysctl_register_oid(&sysctl__net_gre);
    //sysctl_register_oid(&sysctl__net_gre_maxnesting);
    
    lck_mtx_lock(gre_domain_lck);
#if PROTO_WITH_GRE
    net_add_proto(&in_gre_protosw, inet_domain);
#endif
    net_add_proto(&in_mobile_protosw, inet_domain);
    lck_mtx_unlock(gre_domain_lck);
    
    lck_mtx_lock(ip_mutex);
#ifdef DEBUG
    /* hack: sigh!!! */
#if PROTO_WITH_GRE
    if (ip_protox[IPPROTO_GRE] != pr) {
        printf("warning: proto IPPROTO_GRE has already been registerd\n");
    }
#endif
    if (ip_protox[IPPROTO_MOBILE] != pr) {
        printf("warning: proto IPPROTO_MOBILE has already been registerd\n");
    }
#endif
#if PROTO_WITH_GRE
    old_pr_gre = ip_protox[IPPROTO_GRE];
#endif
    old_pr_mobile = ip_protox[IPPROTO_MOBILE];
    
#if PROTO_WITH_GRE
    ip_protox[IPPROTO_GRE] = &in_gre_protosw;
#endif
    ip_protox[IPPROTO_MOBILE] = &in_mobile_protosw;
    lck_mtx_unlock(ip_mutex);
    
#ifdef DEBUG
    printf("%s: done\n", __FUNCTION__);
#endif
    return 0;
}

int gre_domain_dispose()
{
    if (gre_domain_lck == NULL) {
#ifdef DEBUG
        printf("%s: has already disposed\n", __FUNCTION__);
#endif
        return 0;
    }
    
    int err = 0;

    lck_mtx_lock(ip_mutex);
    /* hack: sigh... */
    if (ip_protox[IPPROTO_MOBILE] != &in_mobile_protosw) {
        printf("warning: proto IPPROTO_MOBILE has been modified by other KEXT\n"); /* wait other change it back */
        if (ip_protox[IPPROTO_MOBILE] == old_pr_mobile) {
#ifdef DEBUG
            printf("notice: proto IPPROTO_MOBILE has been changed back by other KEXT\n");
#endif
            goto nextproto;
        }
        err = -1;
        lck_mtx_unlock(ip_mutex);
        goto error;
    }
    ip_protox[IPPROTO_MOBILE] = old_pr_mobile;
    
nextproto:
#if PROTO_WITH_GRE
    if (ip_protox[IPPROTO_GRE] != &in_gre_protosw) {
        printf("warning: proto IPPROTO_GRE has been modified by other KEXT\n"); /* wait other change it back */
        if (ip_protox[IPPROTO_GRE] == old_pr_gre) {
#ifdef DEBUG
            printf("notice: proto IPPROTO_GRE has been changed back by other KEXT\n");
#endif
            goto pgredone;
        }
        err = -1;
        lck_mtx_unlock(ip_mutex);
        goto error;
    }
    ip_protox[IPPROTO_GRE] = old_pr_gre;
#endif //PROTO_WITH_GRE
    
pgredone:
    lck_mtx_unlock(ip_mutex);
    
    lck_mtx_lock(gre_domain_lck);
    net_del_proto(SOCK_RAW, IPPROTO_MOBILE, inet_domain);
#if PROTO_WITH_GRE
    net_del_proto(SOCK_RAW, IPPROTO_GRE, inet_domain);
#endif
    lck_mtx_unlock(gre_domain_lck);
    
    //sysctl_unregister_oid(&sysctl__net_gre_maxnesting);
    sysctl_unregister_oid(&sysctl__net_gre);
    
    gre_domain_lck = NULL;
    
error:
#ifdef DEBUG
    printf("%s: %s\n", __FUNCTION__, err ? "error" : "done");
#endif
    return err;
}

int gre_proto_attach(struct socket *so, int proto, struct proc *p)
{
    //return soreserve(so, 8192, 8192);
#ifdef DEBUG
    printf("%s: proto = %d\n", __FUNCTION__, proto);
#endif
    return 0;
}
int gre_proto_detach(struct socket *so)
{
#ifdef DEBUG
    printf("%s: done\n", __FUNCTION__);
#endif
    return 0;
}
int	gre_proto_ioctl(struct socket *so, u_long cmd, caddr_t data, struct ifnet *ifp, struct proc *p)
{
#ifdef DEBUG
    printf("%s: cmd: %lu, ifp: %p\n", __FUNCTION__, cmd, ifp);
#endif
    return 0;
}
