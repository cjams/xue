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

#include <dbc.h>
#include <endpoint.h>
#include <erst.h>
#include <stdio.h>
#include <string.h>
#include <sys.h>
#include <trb.h>
#include <trb_event.h>
#include <trb_link.h>
#include <trb_normal.h>
#include <trb_ring.h>
#include <xhc.h>

/**
 * Info context strings. Each string is UTF-16LE encoded
 */

static void trb_dump(struct trb *trb)
{
    switch (trb_type(trb)) {
    case trb_type_norm:
        trb_norm_dump(trb);
        return;
    case trb_type_link:
        trb_link_dump(trb);
        return;
    case trb_type_te:
        trb_te_dump(trb);
        return;
    case trb_type_psce:
        trb_psce_dump(trb);
        return;
    default:
        printf("unknown TRB type: %d\n", trb_type(trb));
        return;
    }
}

int dbc_state()
{
    const struct dbc_reg *regs = g_dbc.regs;
    if (!regs) {
        return dbc_off;
    }

    unsigned int ctrl = regs->ctrl;
    unsigned int port = regs->portsc;

    if (ctrl & (1UL << CTRL_DCR_SHIFT)) {
        return dbc_configured;
    }

    if (!(ctrl & (1UL << CTRL_DCE_SHIFT))) {
        return dbc_off;
    }

    if (!(port & (1UL << PORTSC_CCS_SHIFT))) {
        return dbc_disconnected;
    }

    if (port & (1UL << PORTSC_PR_SHIFT)) {
        return dbc_resetting;
    }

    if (port & (1UL << PORTSC_PED_SHIFT)) {
        int pls = (port & PORTSC_PLS_MASK) >> PORTSC_PLS_SHIFT;
        if (pls == 6) {
            /* PLS inactive */
            return dbc_error;
        } else {
            /* PLS not inactive */
            return dbc_enabled;
        }
    } else {
        int pls = (port & PORTSC_PLS_MASK) >> PORTSC_PLS_SHIFT;
        if (pls == 4) {
            /* PLS disabled */
            return dbc_disabled;
        } else {
            /* PLS not inactive */
            return dbc_enabled;
        }
    }
}

void dbc_dump()
{
    printf("ST:     0x%x\n", g_dbc.regs->st);
    printf("CTRL:   0x%x\n", g_dbc.regs->ctrl);
    printf("PORTSC: 0x%x\n", g_dbc.regs->portsc);
}

void dbc_ack()
{
    handle_events(&g_dbc);
}

void dbc_write(const char *data, unsigned int size)
{
    handle_events(&g_dbc);

    if (size > MAX_WRITE) {
        printf("ALERT: size %u is greater than MAX_WRITE %u\n", size,
               MAX_WRITE);
        size = MAX_WRITE;
    }

    struct trb_ring *oring = g_dbc.oring;
    if (trb_ring_full(oring)) {
        printf("ALERT: OUT ring is full\n");
    }

    memcpy(g_write, data, size);
    trb_ring_enqueue(oring, g_write, size);
    g_dbc.regs->db &= 0xFFFF00FF;
}
