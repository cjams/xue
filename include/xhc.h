//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#ifndef XUE_XHC_H
#define XUE_XHC_H

#include "xue.h"

/**
 * eXtensible Host Controller (xhc)
 *
 * The DbC is an optional xHCI extended capability. Before the DbC can be used,
 * it needs to be found in the host controller's extended capability list. This
 * list resides in the controller's MMIO region, which in turn is referred to
 * by the 64-bit BAR0/BAR1 in the controller's PCI config space.
 *
 */

/* PCI constants */

#define XHC_VENDOR 0x8086
#define XHC_DEV_SKYLK 0xA2AF
#define XHC_DEV_CANLK 0xA36D
#define XHC_CLASSC 0x000C0330

enum {
    pci_hdr_normal = 0x00,
    pci_hdr_normal_multi = 0x80 | pci_hdr_normal,
};

static inline uint32_t xhc_read_reg(struct xue *xue, uint32_t cf8, uint32_t reg)
{
    uint32_t addr = (cf8 & 0xFFFFFF03UL) | (reg << 2);
    xue->outd(0xCF8, addr);
    return xue->ind(0xCFC);
}

static inline void xhc_write_reg(struct xue *xue, uint32_t cf8, uint32_t reg, uint32_t val)
{
    uint32_t addr = (cf8 & 0xFFFFFF03UL) | (reg << 2);
    xue->outd(0xCF8, addr);
    xue->outd(0xCFC, val);
}

static inline int xhc_init(struct xue *xue)
{
    xue->xhc_cf8 = 0;

    // Search PCI bus 0 for the xHC
    for (size_t devfn = 0; devfn < 256; devfn++) {
        uint32_t dev = (devfn & 0xF8) >> 3;
        uint32_t fun = devfn & 0x07;
        uint32_t cf8 = (1UL << 31) | (dev << 11) | (fun << 8);

        switch (xhc_read_reg(xue, cf8, 0)) {
        case (XHC_DEV_SKYLK << 16) | XHC_VENDOR:
        case (XHC_DEV_CANLK << 16) | XHC_VENDOR:
            break;
        default:
            continue;
        }

        uint32_t hdr = (xhc_read_reg(xue, cf8, 3) & 0xFF0000U) >> 16;
        if (hdr == pci_hdr_normal || hdr == pci_hdr_normal_multi) {
            if ((xhc_read_reg(xue, cf8, 2) >> 8) == XHC_CLASSC) {
                xue->xhc_cf8 = cf8;
                break;
            }
        }
    }

    if (!xue->xhc_cf8) {
        return 0;
    }

    uint32_t bar0 = xhc_read_reg(xue, xue->xhc_cf8, 4);
    uint32_t bar1 = xhc_read_reg(xue, xue->xhc_cf8, 5);

    // IO BARs not allowed, BAR must be 64-bit
    if ((bar0 & 0x1) != 0 || ((bar0 & 0x6) >> 1) != 2) {
        return 0;
    }

    xhc_write_reg(xue, xue->xhc_cf8, 4, 0xFFFFFFFF);
    size_t size = ~(xhc_read_reg(xue, xue->xhc_cf8, 4) & 0xFFFFFFF0) + 1U;
    xhc_write_reg(xue, xue->xhc_cf8, 4, bar0);

    xue->xhc_mmio_size = size;
    xue->xhc_mmio_phys = (bar0 & 0xFFFFFFF0) | ((uint64_t)bar1 << 32);
    xue->xhc_mmio = xue->map_mmio(xue->xhc_mmio_phys, size);

    return 1;
}

/**
 * The first register of the debug capability (dbc) is found by traversing the
 * host controller's capability list (xcap) until a capability
 * with ID = 0xA is found.
 *
 * The xHCI capability list (xcap) begins at address
 * mmio + (HCCPARAMS1[31:16] << 2)
 */

struct dbc_reg;

static inline struct dbc_reg *xhc_find_dbc(struct xue *xue)
{
    uint8_t *mmio = xue->xhc_mmio;
    uint32_t *hccp1 = (uint32_t *)(mmio + 0x10);

    /**
     * Paranoid check against a zero value. The spec mandates that
     * at least one "supported protocol" capability must be implemented,
     * so this should always be false.
     */
    if ((*hccp1 & 0xFFFF0000) == 0) {
        return NULL;
    }

    uint32_t *xcap = (uint32_t *)(mmio + (((*hccp1 & 0xFFFF0000) >> 16) << 2));
    uint32_t next = (*xcap & 0xFF00) >> 8;
    uint32_t id = *xcap & 0xFF;

    /**
     * Table 7-1 of the xHCI spec states that 'next' is relative
     * to the current value of xcap and is a dword offset.
     */
    while (id != 0x0A && next) {
        xcap += next;
        id = *xcap & 0xFF;
        next = (*xcap & 0xFF00) >> 8;
    }

    if (id != 0x0A) {
        return NULL;
    }

    return (struct dbc_reg *)xcap;
}

#endif
