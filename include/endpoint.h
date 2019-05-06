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

#ifndef XUE_ENDPOINT_H
#define XUE_ENDPOINT_H

#include <dbc.h>
#include <string.h>

/* Enpoint states */
enum ep_state_t {
    disabled,
    running,
    halted,
    stopped,
    error,
    rsvd5,
    rsvd6,
    rsvd7
};

/* Enpoint types */
enum ep_type_t {
    not_valid,
    isoch_out,
    bulk_out,
    intr_out,
    ctrl,
    isoch_in,
    bulk_in,
    intr_in
};

static inline unsigned int ep_state(unsigned int *ep)
{
    return ep[0] & 0x7;
}

static inline void set_ep_state(unsigned int *ep, unsigned int state)
{
    ep[0] &= ~0x7UL;
    ep[0] |= state;
}

static inline unsigned int ep_type(unsigned int *ep)
{
    return (ep[1] & 0x38) >> 3;
}

static inline void set_ep_type(unsigned int *ep, unsigned int type)
{
    ep[1] &= ~0x38UL;
    ep[1] |= (type << 3);
}

/**
 * init_endpoint
 *
 * Initialize the endpoint as specified in sections 7.6.3.2 and 7.6.9.2.
 * Each endpoint is Bulk, so
 *
 *   MaxPStreams, LSA, HID, CErr, FE
 *   Interval, Mult, and Max ESIT Payload
 *
 * are all 0.
 *
 * Max packet size: 1024
 * Max burst size: debug max burst size (in ctrl register)
 * EP type: 2 for OUT bulk, 6 for IN bulk
 * TR dequeue ptr: phys addr of transfer ring
 * Avg TRB length: software defined (see section 4.14.1.1)
 *
 */
static inline void init_endpoint(unsigned int *ep, unsigned int mbs,
                                 unsigned int type, unsigned long long tr_phys)
{
    memset(ep, 0, DBC_CTX_SIZE);

    set_ep_type(ep, type);

    /* Max packet size */
    const unsigned int mps = 1024;
    ep[1] |= (mps << 16);

    /* Max burst size */
    ep[1] |= (mbs << 8);

    /* TR dequeue pointer */
    ep[2] = (tr_phys & 0xFFFFFFFF) | 1;
    ep[3] = tr_phys >> 32;

    /*
     * Avg TRB length..the best value for this is workload dependent. See
     * the implementation note in section 4.14.1.1 for details
     */
    ep[4] = 3 * 1024;
}

#endif
