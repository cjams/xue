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

#ifndef XUE_DBC_H
#define XUE_DBC_H

#define DBC_CTX_DWORDS 16
#define DBC_CTX_SIZE (DBC_CTX_DWORDS * sizeof(unsigned int))

#pragma pack(push, 1)

struct dbc_ctx {
    /* Info context defined in section 7.6.9.1 */
    unsigned int info[DBC_CTX_DWORDS];

    /* OUT bulk transfer ring */
    unsigned int ep_out[DBC_CTX_DWORDS];

    /* IN bulk transfer ring */
    unsigned int ep_in[DBC_CTX_DWORDS];
};

/**
 * struct dbc_reg
 *
 * The register layout of the Debug Capability Structure as
 * defined in section 7.6.8.
 */
struct dbc_reg {
    /* xHCI capability ID (0xA) */
    unsigned int id; // base + 0x0

    /* Doorbell */
    unsigned int db; // base + 0x4

    /* The number of entries in the event ring segment table (ERST) */
    unsigned int erstsz; /* base + 0x8 */

    /* Reserved 0 */
    unsigned int rsvdz; /* base + 0xC */

    /* Base address of the ERST */
    unsigned long long erstba; // base + 0x10

    /* ERST dequeue pointer */
    unsigned long long erdp; // base + 0x18

    /* Control */
    unsigned int ctrl; // base + 0x20

    /* Status */
    unsigned int st; // base + 0x24

    /* Port status and control */
    unsigned int portsc; // base + 0x28

    /* Reserved/preserved */
    unsigned int rsvdp;

    /* Context pointer */
    unsigned long long cp; // base + 0x30

    /* Device descriptor info 1 */
    unsigned int ddi1; // base + 0x38

    /* Device descriptor info 2 */
    unsigned int ddi2; // base + 0x3C
};

#pragma pack(pop)

struct erst_segment;
struct trb;

struct dbc {
    struct dbc_reg *regs;
    struct dbc_ctx *ctx;
    struct erst_segment *erst;
    struct trb *ering;
    struct trb *oring;
    struct trb *iring;
};

int dbc_init(void);
void dbc_enable(void);
int dbc_enabled(void);
void dbc_disable(void);
void dbc_dump_regs(struct dbc_reg *reg);

#endif
