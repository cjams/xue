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

#ifndef XUE_TRB_RING_H
#define XUE_TRB_RING_H

#include <trb.h>
#include <trb_link.h>

/**
 * TRB rings are circular queues of TRBs shared between the xHC and the driver.
 * Each ring has one producer and one consumer. The producer pushes items on
 * the ring by advancing the ring's enqueue pointer.  The consumer pops items
 * off the ring by advancing the ring's dequeue pointer. The DbC has one event
 * ring and two transfer rings, one for each direction of transfer.
 *
 * The xHC hardware is the producer of all events on the event ring, and the
 * driver is the consumer. This means that the event TRBs are read-only from
 * the driver. The hardware enqueues events, and the driver dequeues events.
 *
 * OTOH, the driver is the producer of all transfer TRBs on the two transfer
 * rings, so the driver enqueues transfers, and the hardware dequeues
 * transfers. The dequeue pointer of a transfer ring can be discovered in the
 * driver by examining the latest transfer event on the _event_ring_. The
 * transfer event TRB contains the address of the transfer TRB that generated
 * the event.
 *
 * To make each queue circular, the last TRB must be a Link TRB, which points
 * to the beginning of the next queue.
 */

struct trb_ring {
    /* The array of TRBs */
    struct trb *trb;

    /* The number of TRBs in the ring */
    unsigned int size;

    /* The offset of the enqueue pointer from the base address */
    unsigned int enq;

    /* The offset of the dequeue pointer from the base address */
    unsigned int deq;

    /* Producer cycle state - value written to cycle bit as a producer */
    unsigned int pcs : 1;

    /* Consumer cycle state - value compared to the cycle bit as a consumer */
    unsigned int ccs : 1;
};

static inline int trb_ring_empty(struct trb_ring *ring)
{
    return ring->enq == ring->deq;
}

/* This assumes that each ring has only one segment */
static inline int trb_ring_full(struct trb_ring *ring)
{
    return ((ring->enq + 1) & (ring->size - 1)) == ring->deq;
}

static inline void init_trb_ring(struct trb_ring *ring, struct trb *trb,
                                 int producer)
{
    ring->size = SEG_PER_RING * PAGE_PER_SEG * TRB_PER_PAGE;

    memset(trb, 0, ring->size);

    ring->trb = trb;
    ring->enq = 0;
    ring->deq = 0;

    if (producer) {
        ring->pcs = 1;
        ring->ccs = -1;

        /*
         * Producer implies transfer ring, so we have to place a
         * link TRB at the end
         */
        struct trb *link = &trb[ring->size - 1];
        trb_link_set_rsp(link, sys_virt_to_phys(trb));
        trb_link_set_tc(link);

    } else {
        ring->pcs = -1;
        ring->ccs = 1;
    }
}

static inline void init_producer_ring(struct trb_ring *ring, struct trb *trb)
{
    init_trb_ring(ring, trb, 1);
}

static inline void init_consumer_ring(struct trb_ring *ring, struct trb *trb)
{
    init_trb_ring(ring, trb, 0);
}

#endif
