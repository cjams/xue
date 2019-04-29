//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <dbc.h>
#include <erst.h>
#include <stdio.h>
#include <string.h>
#include <sys.h>
#include <trb.h>
#include <xhc.h>

struct dbc g_dbc;
struct erst_segment g_erst[NR_SEGS];
struct trb g_evtring[TRB_PER_SEG];

static inline void* dbc_alloc(unsigned long long size)
{
    return sys_alloc_aligned(64, size);
}

static inline void dbc_free(void *ptr)
{
    sys_free(ptr);
}

void dbc_dump_regs(struct dbc_reg *reg)
{
    printf("DbC registers:\n");

    printf("id: 0x%x\n", reg->id);
    printf("db: 0x%x\n", reg->db);
    printf("erstsz: 0x%x\n", reg->erstsz);
    printf("erstba: 0x%llx\n", reg->erstba);
    printf("erdp: 0x%llx\n", reg->erdp);
    printf("ctrl: 0x%x\n", reg->ctrl);
    printf("st: 0x%x\n", reg->st);
    printf("portsc: 0x%x\n", reg->portsc);
    printf("cp: 0x%llx\n", reg->cp);
    printf("ddi1: 0x%x\n", reg->ddi1);
    printf("ddi2: 0x%x\n", reg->ddi2);
}

int dbc_init(void)
{
    memset(&g_dbc, 0, sizeof(g_dbc));

    struct dbc_reg *reg = xhc_find_dbc_base();
    if (!reg) {
        return 0;
    }

    g_dbc.regs = reg;

    /*
     * Initialize the ERST
     *
     * 1. init erst_segment (descriptor)
     * 2. init erst_segment data (page of TRBs)
     */

    int erstmax = (reg->id & 0x1F0000) >> 16;
    if (NR_SEGS > (1 << erstmax)) {
        return 0;
    }

    return 0;
}
