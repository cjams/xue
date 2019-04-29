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

#ifndef XUE_EP_H
#define XUE_EP_H

#include <string.h>

#pragma pack(push, 1)

/**
 * struct dbc_endpoint
 *
 * Describes a DbC endpoint context.
 * All DbC endpoint contexts are 64 bytes
 */
struct dbc_endpoint {
    unsigned int data[16];
};

#pragma pack(pop)

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

/**
 * ep_state
 */
static inline unsigned int ep_state(struct dbc_endpoint *ep)
{
    return ep->data[0] & 0x7;
}
static inline void set_ep_state(struct dbc_endpoint *ep, unsigned int state)
{
    ep->data[0] |= state;
}

/**
 * ep_type
 */
static inline unsigned int ep_type(struct dbc_endpoint *ep)
{
    return (ep->data[1] & 0x38) >> 3;
}
static inline void set_ep_type(struct dbc_endpoint *ep, unsigned int type)
{
    ep->data[1] |= (type << 3);
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
 * TR dequeue ptr: hpa of transfer ring
 * Avg TRB length: software defined (see section 4.14.1.1)
 *
 */
static inline void init_endpoint(struct dbc_endpoint *ep, unsigned int type)
{
    memset(ep, 0, sizeof(*ep));

    set_ep_state(ep, disabled);
    set_ep_type(ep, type);

    /* Max packet size */
    const unsigned int mps = 1024;
    ep->data[1] |= (mps << 16);

    /* Max burst size */
    const unsigned int mbs = (g_dbc.regs->ctrl & 0xFF0000) >> 16;
    ep->data[1] |= (mbs << 8);

    //TODO: tr dequeue ptr, avg trb length

}


#endif
