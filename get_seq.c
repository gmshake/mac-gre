/*
 *  get_seq.c
 *  gre
 *
 *  Created by Summer Town on 12/1/10.
 *  Copyright 2010 __MyCompanyName__. All rights reserved.
 *
 */

#include <sys/kernel.h>
#include <sys/syslog.h>
#include <sys/lock.h>

#include "gre_if.h"

extern lck_grp_t *gre_lck_grp;

static lck_mtx_t *cnt_mtx = NULL;

errno_t seq_init()
{
    if (gre_lck_grp == 0) {
        log(LOG_CRIT, "%s: please allocate gre_lck_grp first!!!\n", __FUNCTION__);
        return -1;
    }

    if (cnt_mtx != NULL)
        return 0;

    cnt_mtx = lck_mtx_alloc_init(gre_lck_grp, NULL);

    if (cnt_mtx == NULL) {
        log(LOG_ERR, "%s: lck_mtx_alloc_init() failed\n", __FUNCTION__);
        return -1;
    }
    return 0;
}

errno_t seq_dispose()
{
    if (cnt_mtx == NULL)
        return 0;
    if (gre_lck_grp == NULL) {
        log(LOG_CRIT, "%s: gre_lck_grp freed before cnt_mtx is freed!!!\n", __FUNCTION__);
        return 0; // mem leaks???
    }

    lck_mtx_free(cnt_mtx, gre_lck_grp);
    cnt_mtx = NULL;
    return 0;
}

u_int64_t get_seq()
{
    static u_int64_t cnt = 0;
    if (cnt_mtx == NULL)
        return cnt;
    lck_mtx_lock(cnt_mtx);
    u_int64_t ret = cnt++;
    lck_mtx_unlock(cnt_mtx);
    return ret;
}

