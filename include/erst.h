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

#ifndef XUE_ERST_H
#define XUE_ERST_H

#include <trb.h>

#pragma pack(push, 1)

/**
 * struct erst_entry
 *
 * The ERST segment below is defined in section 6.5. This
 * structure is used by both software and the xHC hardware.
 */
struct erst_segment {
    /* Ring segment base address lo. Bits [5:0] must be 0. */
    unsigned int rsba_lo;

    /* Ring segment base address hi. */
    unsigned int rsba_hi;

    /*
     * Ring segment size defines the number of TRBs supported by
     * the segment. Valid values are in [16, 4096].
     */
    unsigned short nr_trb;

    /* Reserved 0 */
    unsigned char rsvdz[6];
};

#pragma pack(pop)

#define NR_SEGS 1
#define SEG_SIZE 4096
#define TRB_SIZE sizeof(struct trb)
#define TRB_PER_SEG (SEG_SIZE / TRB_SIZE)

/**
 * ERST
 *
 * The event ring segment table contains event ring segment descriptors
 * Each descriptor contains the address and size (in TRBs) of the segment.
 *
 * The number of entries must be at most 2^erstmax.
 */
extern struct erst_segment g_erst[NR_SEGS];
extern struct trb g_evtring[TRB_PER_SEG];

#endif
