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

#include <string.h>
#include <sys.h>
#include <trb.h>
#include <trb_normal.h>
#include <trb_ring.h>

void trb_ring_init(struct trb_ring *ring, struct trb *trbs, int producer)
{
    ring->size = SEG_PER_RING * PAGE_PER_SEG * TRB_PER_PAGE;

    memset(trbs, 0, ring->size);

    ring->trb = trbs;
    ring->enq = 0;
    ring->deq = 0;
    ring->cycle = 1;

    /*
     * Producer implies transfer ring, so we have to place a
     * link TRB at the end that points back to trbs[0]
     */
    if (producer) {
        struct trb *link = &trbs[ring->size - 1];
        trb_link_set_rsp(link, sys_virt_to_phys(trbs));
        trb_link_set_tc(link);
    }
}

void trb_ring_enqueue(struct trb_ring *ring, const char *buf, unsigned int len)
{
    struct trb trb;

    trb_init(&trb);

    trb_set_type(&trb, trb_type_norm);
    trb_set_cycle(&trb, ring->cycle);

    trb_norm_set_buf(&trb, sys_virt_to_phys(buf));
    trb_norm_set_len(&trb, len);
    trb_norm_set_ioc(&trb);

    ring->trb[ring->enq] = trb;
    ring->enq = (ring->enq + 1) & (ring->size - 1);
    ring->cycle = (ring->enq) ? ring->cycle : ring->cycle ^ 1;
}
