/*
 *  get_seq.c
 *  gre
 *
 *  Created by Summer Town on 12/1/10.
 *  Copyright 2010 __MyCompanyName__. All rights reserved.
 *
 */

#include <sys/kernel.h>

#include <libkern/OSBase.h>
#include <libkern/OSTypes.h>
#include <libkern/OSAtomic.h>

u_int64_t get_seq()
{
    static volatile SInt64 cnt = 0;
    return OSIncrementAtomic64(&cnt);
}

