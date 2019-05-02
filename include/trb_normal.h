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

#ifndef XUE_TRB_NORMAL_H
#define XUE_TRB_NORMAL_H

#include <trb.h>

static inline unsigned long long trb_norm_dbp(struct trb *trb)
{
    return trb->params;
}

static inline unsigned int trb_norm_inttgt(struct trb *trb)
{
    return (trb->status & 0xFFC00000) >> 22;
}

static inline unsigned int trb_norm_tdsz(struct trb *trb)
{
    return (trb->status & 0x003E0000) >> 17;
}

static inline unsigned int trb_norm_tfrlen(struct trb *trb)
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

static inline unsigned int trb_norm_ent(struct trb *trb)
{
    return (trb->ctrl & 0x2) >> 1;
}

static inline void trb_norm_set_dbp(struct trb *trb, unsigned long long addr)
{
    trb->params = addr;
}

static inline void trb_norm_set_inttgt(struct trb *trb, unsigned int tgt)
{
    trb->status &= ~0xFFC00000UL;
    trb->status |= (tgt << 22);
}

static inline void trb_norm_set_tdsz(struct trb *trb, unsigned int size)
{
    trb->status &= ~0x3E0000UL;
    trb->status |= (size << 17);
}

static inline void trb_norm_set_tfrlen(struct trb *trb, unsigned int len)
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

static inline void trb_norm_set_ent(struct trb *trb)
{
    trb->ctrl |= 0x2;
}

static inline void trb_norm_clear_ent(struct trb *trb)
{
    trb->ctrl &= ~0x2UL;
}

static inline void trb_norm_dump(struct trb *trb)
{
    printf("normal    trb: cycle: %d type: %d dbp: 0x%llx tgt: %u ",
           trb_cycle(trb), trb_type(trb), trb_norm_dbp(trb),
           trb_norm_inttgt(trb));
    printf("tdsz: %u tfrlen: %u bei: %u idt: %u ioc: %u ch: %u ns: %u ",
           trb_norm_tdsz(trb), trb_norm_tfrlen(trb), trb_norm_bei(trb),
           trb_norm_idt(trb), trb_norm_ioc(trb), trb_norm_ch(trb),
           trb_norm_ns(trb));
    printf("isp: %u ent: %u\n", trb_norm_isp(trb), trb_norm_ent(trb));
}

#endif
