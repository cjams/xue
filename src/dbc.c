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

#define __cachealign __attribute__((aligned(64)))
#define __pagealign __attribute__((aligned(4096)))

/**
 * These values are used so that the xhci_dbc linux host
 * driver binds to the DbC at enumeration time
 */
#define DBC_VENDOR 0x1d6b
#define DBC_PRODUCT 0x0010
#define DBC_PROTOCOL 0x0000

/**
 * Info context strings. Each string is UTF-16LE encoded
 */

/* clang-format off */

/* String 0 descriptor. Only one LANGID is allowed */
#define STR0_LEN 6
static const char str0[STR0_LEN] = {
    STR0_LEN, /* bLength */
    3,        /* bDescriptorType */
    9, 0,     /* English */
    4, 0      /* United States */
};

/* Manufacturer string descriptor */
#define MFR_LEN 8
static const char mfr[MFR_LEN] = {
    MFR_LEN,
    3,
    'A', 0, 'I', 0, 'S', 0
};

/* Product string descriptor */
#define PRD_LEN 32
static const char prd[PRD_LEN] = {
    PRD_LEN,
    3,
    'x', 0, 'H', 0, 'C', 0, 'I', 0, ' ', 0,
    'D', 0, 'b', 0, 'C', 0, ' ', 0,
    'D', 0, 'r', 0, 'i', 0, 'v', 0, 'e', 0, 'r', 0
};

/* Serial string descriptor */
#define SER_LEN 4
static const char ser[SER_LEN] = {
    SER_LEN,
    3,
    '0', 0
};

/* clang-format on */

static struct dbc g_dbc __cachealign;
static struct dbc_ctx g_ctx __cachealign;
static struct erst_segment g_erst[NR_SEGS] __cachealign;

static struct trb g_etrb[TRB_PER_PAGE] __pagealign;
static struct trb g_otrb[TRB_PER_PAGE] __pagealign;
static struct trb g_itrb[TRB_PER_PAGE] __pagealign;

static struct trb_ring g_ering;
static struct trb_ring g_oring;
static struct trb_ring g_iring;

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

static void init_info(unsigned int *info)
{
    unsigned long long *sda = (unsigned long long *)info;
    unsigned long long *mfa = (unsigned long long *)(&info[2]);
    unsigned long long *pfa = (unsigned long long *)(&info[4]);
    unsigned long long *sea = (unsigned long long *)(&info[6]);

    *sda = sys_virt_to_phys(str0);
    *mfa = sys_virt_to_phys(mfr);
    *pfa = sys_virt_to_phys(prd);
    *sea = sys_virt_to_phys(ser);

    info[8] = (SER_LEN << 24) | (PRD_LEN << 16) | (MFR_LEN << 8) | STR0_LEN;
}

void dbc_dump_regs(struct dbc_reg *reg)
{
    printf("DbC registers:\n");

    printf("    - id: 0x%x\n", reg->id);
    printf("    - db: 0x%x\n", reg->db);
    printf("    - erstsz: 0x%x\n", reg->erstsz);
    printf("    - erstba: 0x%llx\n", reg->erstba);
    printf("    - erdp: 0x%llx\n", reg->erdp);
    printf("    - ctrl: 0x%x\n", reg->ctrl);
    printf("    - st: 0x%x\n", reg->st);
    printf("    - portsc: 0x%x\n", reg->portsc);
    printf("    - cp: 0x%llx\n", reg->cp);
    printf("    - ddi1: 0x%x\n", reg->ddi1);
    printf("    - ddi2: 0x%x\n", reg->ddi2);
}

/* See section 7.6.4.1 for explanation of the initialization sequence */
int dbc_init()
{
    memset(&g_dbc, 0, sizeof(g_dbc));

    /* Registers */
    struct dbc_reg *reg = xhc_find_dbc_base();
    if (!reg) {
        return 0;
    }
    g_dbc.regs = reg;

    int erstmax = (reg->id & 0x1F0000) >> 16;
    if (NR_SEGS > (1 << erstmax)) {
        return 0;
    }

    /* TRB rings */
    init_consumer_ring(&g_ering, g_etrb);
    init_producer_ring(&g_oring, g_otrb);
    init_producer_ring(&g_iring, g_itrb);

    g_dbc.ering = &g_ering;
    g_dbc.oring = &g_oring;
    g_dbc.iring = &g_iring;

    /* Event ring segment table */
    memset(&g_erst, 0, sizeof(g_erst));
    unsigned long long erdp = sys_virt_to_phys(g_ering.trb);
    if (!erdp) {
        return 0;
    }

    g_erst[0].base = erdp;
    g_erst[0].nr_trb = PAGE_PER_SEG * TRB_PER_PAGE;
    g_dbc.erst = g_erst;

    /* Info and endpoint context */
    memset(&g_ctx, 0, sizeof(g_ctx));

    unsigned int max_burst = (reg->ctrl & 0xFF0000) >> 16;
    unsigned long long out = sys_virt_to_phys(g_oring.trb);
    unsigned long long in = sys_virt_to_phys(g_iring.trb);

    init_endpoint(g_ctx.ep_out, max_burst, bulk_out, out);
    init_endpoint(g_ctx.ep_in, max_burst, bulk_in, in);
    init_info(g_ctx.info);

    g_dbc.ctx = &g_ctx;

    /* Hardware registers */
    reg->erstsz = SEG_PER_RING;
    reg->erstba = sys_virt_to_phys(g_erst);
    reg->erdp = erdp;
    reg->cp = sys_virt_to_phys(&g_ctx);
    reg->ddi1 = (DBC_VENDOR << 16) | DBC_PROTOCOL;
    reg->ddi2 = DBC_PRODUCT;

    dbc_enable();
    return 1;
}

int dbc_is_enabled()
{
    return g_dbc.regs->ctrl & (1UL << 31);
}

void dbc_enable()
{
    g_dbc.regs->ctrl |= (1UL << 31);
}

void dbc_disable()
{
    g_dbc.regs->ctrl &= ~(1UL << 31);
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

// TODO
static void handle_psce(struct trb *trb)
{
    unsigned int *psc = &g_dbc.regs->portsc;
    unsigned int mask = (1UL << PORTSC_CSC_SHIFT) | (1UL << PORTSC_PRC_SHIFT) |
                        (1UL << PORTSC_PLC_SHIFT) | (1UL << PORTSC_CEC_SHIFT);

    unsigned int ack = mask & *psc;
    *psc |= ack;
}

static void handle_te(struct trb_ring *tr, struct trb *trb)
{
    unsigned int cc = trb_te_code(trb);

    if (cc != trb_cc_success) {
        printf("ERROR: transfer completion code: %d\n", cc);
        return;
    }

    /*
     * Update the *transfer* deq with the TRB offset. This assumes
     * each segment is one page
     */
    tr->deq = (trb_te_ptr(trb) & 0xFFF) >> 4;
}

static void handle_event(struct trb_ring *tfr, struct trb *evt)
{
    switch (trb_type(evt)) {
    case trb_type_te:
        handle_te(tfr, evt);
        trb_dump(evt);
        return;
    case trb_type_psce:
        handle_psce(evt);
        trb_dump(evt);
        return;
    default:
        printf("ALERT: unhandled TRB event type: %d\n", trb_type(evt));
        return;
    }
}

static inline int own_event_trb(struct trb_ring *er, struct trb *evt)
{
    return trb_cycle(evt) == er->cycle;
}

static inline struct trb *next_event(struct trb_ring *er)
{
    er->cycle = (er->deq == er->size - 1) ? er->cycle ^ 1 : er->cycle;
    er->deq = (er->deq + 1) & (er->size - 1);

    return &er->trb[er->deq];
}

static void handle_events(struct dbc *dbc)
{
    struct trb_ring *er = dbc->ering;
    struct trb_ring *tr = dbc->oring;
    struct trb *evt = &er->trb[er->deq];

    while (own_event_trb(er, evt)) {
        handle_event(tr, evt);
        evt = next_event(er);
    }

    /* TODO: pretranslate */
    dbc->regs->erdp = sys_virt_to_phys(&er->trb[er->deq]);
}

void dbc_ack()
{
    handle_events(&g_dbc);
}

void dbc_write(const char *data, unsigned int size)
{
    handle_events(&g_dbc);

    struct trb_ring *oring = g_dbc.oring;
    if (trb_ring_full(oring)) {
        printf("ALERT: OUT ring is full\n");
    }

    trb_ring_enqueue(oring, data, size);
    g_dbc.regs->db &= 0xFFFF00FF;
}
