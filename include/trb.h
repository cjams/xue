/*
 * Copyright (C) 2019 Assured Information Security, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef XUE_TRB_H
#define XUE_TRB_H

#include <stdio.h>

/**
 * Transfer request blocks (TRBs) are the basic blocks on which
 * all DbC (and xHC) transactions occur. Each TRB is 16 bytes,
 * with the first 8 bytes being the TRB "parameters", next 4
 * bytes the "status" and the next 4 bytes the "control".
 *
 * There are several different types of TRBs, each with
 * their own interpretation of the 16 bytes mentioned above
 * and their own rules of use. The type is uniquely determined
 * by the ring type (i.e., command, event, or transfer) and the
 * ID assigned in Table 6-86.
 */

#pragma pack(push, 1)

struct trb {
    unsigned long long params;
    unsigned int status;
    unsigned int ctrl;
};

#pragma pack(pop)

#define TRB_PER_PAGE (4096 / sizeof(struct trb))
#define PAGE_PER_SEG 1
#define SEG_PER_RING 1

enum {
    trb_type_norm = 1,
    trb_type_link = 6,
    trb_type_te = 32,
    trb_type_psce = 34
};

/* Fields common to every TRB (section 4.11.1) */

static inline unsigned int trb_cycle(struct trb *trb)
{
    return trb->ctrl & 0x1;
}

static inline unsigned int trb_type(struct trb *trb)
{
    return (trb->ctrl & 0xFC00) >> 10;
}

static inline void trb_set_cycle(struct trb *trb)
{
    trb->ctrl |= 0x1;
}

static inline void trb_clear_cycle(struct trb *trb)
{
    trb->ctrl &= ~0x1UL;
}

static inline void trb_set_type(struct trb *trb, unsigned int type)
{
    trb->ctrl &= ~0xFC00UL;
    trb->ctrl |= (type << 10);
}

#endif
