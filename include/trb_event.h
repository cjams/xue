
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

#ifndef XUE_TRB_EVENT_H
#define XUE_TRB_EVENT_H

#include <stdio.h>

/*
 * Fields for Transfer Event TRBs (see section 6.4.2.1). Note that event
 * TRBs are read-only from software
 */

/* TRB pointer */
static inline unsigned long long trb_te_ptr(struct trb *trb)
{
    return trb->params;
}

/* Completion code */
static inline unsigned int trb_te_code(struct trb *trb)
{
    return trb->status >> 24;
}

/* Transfer length */
static inline unsigned int trb_te_tfrlen(struct trb *trb)
{
    return trb->status & 0xFFFFFF;
}

static inline unsigned int trb_te_slotid(struct trb *trb)
{
    return trb->ctrl >> 24;
}

/* Endpoint ID */
static inline unsigned int trb_te_epid(struct trb *trb)
{
    return (trb->ctrl & 0x1F0000) >> 16;
}

/* Event data (immediate) */
static inline unsigned int trb_te_ed(struct trb *trb)
{
    return (trb->ctrl & 0x4) >> 2;
}

static inline void trb_te_dump(struct trb *trb)
{
    printf("tfr event trb: cycle: %d type: %d trbptr: 0x%llx code: %u ",
           trb_cycle(trb), trb_type(trb), trb_te_ptr(trb), trb_te_code(trb));

    printf("tfrlen: %u slotid: %u endpointid: %u ed: %u\n", trb_te_tfrlen(trb),
           trb_te_slotid(trb), trb_te_epid(trb), trb_te_ed(trb));
}

/*
 * Fields for Port Status Change Event TRBs (see section 6.4.2.3)
 */

/* Port ID */
static inline unsigned int trb_psce_portid(struct trb *trb)
{
    return (trb->params & 0xFF000000) >> 24;
}

/* Completion code */
static inline unsigned int trb_psce_code(struct trb *trb)
{
    return trb->status >> 24;
}

static inline void trb_psce_dump(struct trb *trb)
{
    printf("psc event trb: cycle: %d type: %d portid: %u code: %u\n",
           trb_cycle(trb), trb_type(trb), trb_psce_portid(trb),
           trb_psce_code(trb));
}

#endif
