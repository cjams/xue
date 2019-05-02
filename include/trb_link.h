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

#ifndef XUE_TRB_LINK_H
#define XUE_TRB_LINK_H

/*
 * Fields for link TRBs (section 6.4.4.1)
 */

static inline unsigned long long trb_link_rsp(struct trb *trb)
{
    return trb->params;
}

static inline unsigned int trb_link_inttgt(struct trb *trb)
{
    return trb->status >> 22;
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

static inline void trb_link_set_inttgt(struct trb *trb, unsigned int tgt)
{
    trb->status &= ~0xFFC00000UL;
    trb->status |= (tgt << 22);
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

static inline void trb_link_dump(struct trb *trb)
{
    printf("link      trb: cycle: %d type: %d rsp: 0x%llx tgt: %u ",
           trb_cycle(trb), trb_type(trb), trb_link_rsp(trb),
           trb_link_inttgt(trb));
    printf("ioc: %u ch: %u tc: %u ", trb_link_ioc(trb), trb_link_ch(trb),
           trb_link_tc(trb));
}
#endif
