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

    /* Cycle state toggled on each ring wrap-around */
    unsigned int cycle;
};

/**
 * trb_ring_init
 *
 * Initialize an empty TRB ring. If producer != 0, then a
 * link TRB will be created at the end of the ring.
 *
 * @param ring the ring to initialize
 * @param trbs the array of TRBs
 * @param producer nonzero if transfer ring, 0 otherwise
 */
void trb_ring_init(struct trb_ring *ring, struct trb *trbs, int producer);

/**
 * trb_ring_enqueue
 *
 * Push a new work item on the transfer ring. This is undefined for event rings
 * since they are read-only. The provided ring must not be full.
 *
 * @param ring the ring to enqueue
 * @param buf the virtual address of the data to transfer
 * @param len the number of bytes to transfer
 */
void trb_ring_enqueue(struct trb_ring *ring, const char *buf, unsigned int len);

static inline void init_producer_ring(struct trb_ring *ring, struct trb *trb)
{
    trb_ring_init(ring, trb, 1);
}

static inline void init_consumer_ring(struct trb_ring *ring, struct trb *trb)
{
    trb_ring_init(ring, trb, 0);
}

static inline int trb_ring_empty(struct trb_ring *ring)
{
    return ring->enq == ring->deq;
}

static inline int trb_ring_full(struct trb_ring *ring)
{
    return ((ring->enq + 1) & (ring->size - 1)) == ring->deq;
}

#endif
