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
 * and their own rules of use.
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

/* Every ring is one segment i.e., one contiguous chunk of memory */
#define SEG_PER_RING 1

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

/* Fields for normal TRBs (see section 6.4.1.1) */

static inline unsigned long long trb_norm_addr(struct trb *trb)
{
    return trb->params;
}

static inline unsigned int trb_norm_intr_tgt(struct trb *trb)
{
    return (trb->status & 0xFFC00000) >> 22;
}

static inline unsigned int trb_norm_td_size(struct trb *trb)
{
    return (trb->status & 0x003E0000) >> 17;
}

static inline unsigned int trb_norm_transfer_len(struct trb *trb)
{
    return (trb->status & 0x0001FFFF);
}

static inline unsigned int trb_norm_bei(struct trb *trb)
{
    return (trb->ctrl & 0x200) >> 9;
}

static inline unsigned int trb_norm_idt(struct trb *trb)
{
    return (trb->ctrl & 0x40) >> 6;
}

static inline unsigned int trb_norm_ioc(struct trb *trb)
{
    return (trb->ctrl & 0x20) >> 5;
}

static inline unsigned int trb_norm_ch(struct trb *trb)
{
    return (trb->ctrl & 0x10) >> 4;
}

static inline unsigned int trb_norm_ns(struct trb *trb)
{
    return (trb->ctrl & 0x8) >> 3;
}

static inline unsigned int trb_norm_isp(struct trb *trb)
{
    return (trb->ctrl & 0x4) >> 2;
}

static inline void trb_norm_set_addr(struct trb *trb, unsigned long long addr)
{
    trb->params = addr;
}

static inline void trb_norm_set_intr_tgt(struct trb *trb, unsigned int tgt)
{
    trb->status &= ~0xFFC00000UL;
    trb->status |= (tgt << 22);
}

static inline void trb_norm_set_td_size(struct trb *trb, unsigned int size)
{
    trb->status &= ~0x3E0000UL;
    trb->status |= (size << 17);
}

static inline void trb_norm_set_transfer_len(struct trb *trb, unsigned int len)
{
    trb->status &= ~0x1FFFFUL;
    trb->status |= len;
}

static inline void trb_norm_set_bei(struct trb *trb)
{
    trb->ctrl |= 0x200;
}

static inline void trb_norm_clear_bei(struct trb *trb)
{
    trb->ctrl &= ~0x200UL;
}

static inline void trb_norm_set_idt(struct trb *trb)
{
    trb->ctrl |= 0x40;
}

static inline void trb_norm_clear_idt(struct trb *trb)
{
    trb->ctrl &= ~0x40UL;
}

static inline void trb_norm_set_ioc(struct trb *trb)
{
    trb->ctrl |= 0x20;
}

static inline void trb_norm_clear_ioc(struct trb *trb)
{
    trb->ctrl &= ~0x20UL;
}

static inline void trb_norm_set_ch(struct trb *trb)
{
    trb->ctrl |= 0x10;
}

static inline void trb_norm_clear_ch(struct trb *trb)
{
    trb->ctrl &= ~0x10UL;
}

static inline void trb_norm_set_ns(struct trb *trb)
{
    trb->ctrl |= 0x8;
}

static inline void trb_norm_clear_ns(struct trb *trb)
{
    trb->ctrl &= ~0x8UL;
}

static inline void trb_norm_set_isp(struct trb *trb)
{
    trb->ctrl |= 0x4;
}

static inline void trb_norm_clear_isp(struct trb *trb)
{
    trb->ctrl &= ~0x4UL;
}

/*
 * Fields for event TRBs (see section 6.4.2). Note that event
 * TRBs are read-only from software
 */

static inline unsigned long long trb_evt_addr(struct trb *trb)
{
    return trb->params;
}

static inline unsigned int trb_evt_compl_code(struct trb *trb)
{
    return trb->status >> 24;
}

static inline unsigned int trb_evt_transfer_len(struct trb *trb)
{
    return trb->status & 0xFFFFFF;
}

static inline unsigned int trb_evt_slot_id(struct trb *trb)
{
    return trb->ctrl >> 24;
}

static inline unsigned int trb_evt_endpoint_id(struct trb *trb)
{
    return (trb->ctrl & 0x1F0000) >> 16;
}

static inline unsigned int trb_evt_ed(struct trb *trb)
{
    return (trb->ctrl & 0x4) >> 2;
}

/*
 * Fields for link TRBs (section 6.4.4.1)
 */

static inline unsigned long long trb_link_rsp(struct trb *trb)
{
    return trb->params;
}

static inline unsigned int trb_link_tc(struct trb *trb)
{
    return (trb->ctrl & 0x2) >> 1;
}

static inline unsigned int trb_link_ch(struct trb *trb)
{
    return (trb->ctrl & 0x10) >> 4;
}

static inline unsigned int trb_link_ioc(struct trb *trb)
{
    return (trb->ctrl & 0x20) >> 5;
}

static inline void trb_link_set_rsp(struct trb *trb, unsigned long long rsp)
{
    trb->params = rsp;
}

static inline void trb_link_set_tc(struct trb *trb)
{
    trb->ctrl |= 0x2;
}

static inline void trb_link_clear_tc(struct trb *trb)
{
    trb->ctrl &= ~0x2UL;
}

static inline void trb_link_set_ch(struct trb *trb)
{
    trb->ctrl |= 0x10;
}

static inline void trb_link_clear_ch(struct trb *trb)
{
    trb->ctrl &= ~0x10UL;
}

static inline void trb_link_set_ioc(struct trb *trb)
{
    trb->ctrl |= 0x20;
}

static inline void trb_link_clear_ioc(struct trb *trb)
{
    trb->ctrl &= ~0x20UL;
}

#endif
