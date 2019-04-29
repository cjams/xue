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

#include <pci.h>
#include <stddef.h>
#include <stdio.h>
#include <xhc.h>

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

#define NR_DEV 32
#define NR_FUN 8

#define XHC_VENDOR 0x8086
#define XHC_DEV_SKYLK 0xA2AF
#define XHC_DEV_CANLK 0xA36D
#define XHC_CLASSC 0x000C0330

enum {
    pci_hdr_normal = 0x00,
    pci_hdr_pci_bridge = 0x01,
    pci_hdr_cardbus_bridge = 0x02,
    pci_hdr_normal_multi = 0x80 | pci_hdr_normal,
    pci_hdr_pci_bridge_multi = 0x80 | pci_hdr_pci_bridge,
    pci_hdr_cardbus_bridge_multi = 0x80 | pci_hdr_cardbus_bridge,
    pci_hdr_nonexistant = 0xFF
};

/* xhc device */
struct xhc g_xhc;

static inline unsigned int xhc_read_reg(unsigned int reg)
{
    return cf8_read_reg(g_xhc.cf8, reg);
}

static inline void xhc_write_reg(unsigned int reg, unsigned int val)
{
    cf8_write_reg(g_xhc.cf8, reg, val);
}

static int xhc_matches(unsigned int cf8)
{
    if (!cf8_exists(cf8)) {
        return 0;
    }

    switch (cf8_read_reg(cf8, 0)) {
    case (XHC_DEV_SKYLK << 16) | XHC_VENDOR:
    case (XHC_DEV_CANLK << 16) | XHC_VENDOR:
        break;
    default: {
            auto ven = (cf8_read_reg(cf8, 0) & 0x0000FFFF);
            auto dev = (cf8_read_reg(cf8, 0) & 0xFFFF0000) >> 16;
            printf("Unknown xHC PCI dev:ven (0x%x:0x%x)\n", dev, ven);
            return 0;
        }
    }

    switch (pci_hdr_type(cf8)) {
    case pci_hdr_normal:
    case pci_hdr_normal_multi:
        break;
    default:
        return 0;
    }

    return (cf8_read_reg(cf8, 2) >> 8) == XHC_CLASSC;
}

int xhc_find(void)
{
    for (int d = 0; d < NR_DEV; d++) {
        for (int f = 0; f < NR_FUN; f++) {
            unsigned int cf8 = bdf_to_cf8(0, d, f);

            if (xhc_matches(cf8)) {
                g_xhc.cf8 = bdf_to_cf8(0, d, f);
                printf("Located xHC device at %02x:%02x.%02x\n", 0, d, f);
                return 1;
            }
        }
    }

    printf("ERROR: Failed to locate xHC on bus 0\n");
    return 0;
}

int xhc_parse_bar(void)
{
    unsigned int bar0 = xhc_read_reg(4);
    unsigned int bar1 = xhc_read_reg(5);

    /* IO bars not allowed */
    if ((bar0 & 0x1) != 0) {
        return 0;
    }

    /* MMIO bar must be 64-bit */
    if (((bar0 & 0x6) >> 1) != 2) {
        return 0;
    }

    /* Parse the bar size */
    xhc_write_reg(4, 0xFFFFFFFF);
    unsigned int size = xhc_read_reg(4);
    size = ~(size & 0xFFFFFFF0) + 1U;
    xhc_write_reg(4, bar0);

    g_xhc.mmio_len = size;
    g_xhc.mmio_hpa = (bar0 & 0xFFFFFFF0) | ((unsigned long long)bar1 << 32);

    printf("    - mmio len: 0x%llx\n", g_xhc.mmio_len);
    printf("    - mmio hpa: 0x%llx\n", g_xhc.mmio_hpa);

    return 1;
}

int xhc_dump_hccparams1(void)
{
    if (!g_xhc.mmio) {
        return 0;
    }

    unsigned int *cap1
        = (unsigned int *)(g_xhc.mmio
                           + offsetof(struct xhc_cap_regs, hccparams1));
    printf("    - cap1: 0x%x\n", *cap1);

    unsigned int xecp_offd = (*cap1 & 0xFFFF0000) >> 16;
    unsigned int xecp_offb = xecp_offd << 2;
    printf("    - xECP offsetd: 0x%x\n", xecp_offd);
    printf("    - xECP phys: 0x%llx\n", g_xhc.mmio_hpa + xecp_offb);
    printf("    - xECP virt: 0x%llx\n", g_xhc.mmio + xecp_offb);

    unsigned int *xcap = g_xhc.mmio + xecp_offb;
    unsigned int i = 0, next = 0;
    do {
        printf("    - xcap[%d]: 0x%x\n", i++, *xcap);
        next = ((*xcap & 0xFF00) >> 8);
        xcap += next;
    } while (next);

    return 1;
}

/**
 * The first register of the debug capability (xdc) is found by traversing the
 * xHCI capability list (xcap) until a capability with ID = 0xA is found.
 *
 * The xHCI capability list (xcap) begins at address
 * mmio + (HCCPARAMS1[31:16] << 2)
 */
unsigned int *xhc_find_xdc_base(void)
{
    if (!g_xhc.mmio) {
        return (unsigned int *)0;
    }

    unsigned int *hccp1
        = (unsigned int *)(g_xhc.mmio
                           + offsetof(struct xhc_cap_regs, hccparams1));
    /**
     * Paranoid check against a zero value. The spec mandates that
     * at least one "supported protocol" capability must be implemented,
     * so this should always be false.
     */
    if ((*hccp1 & 0xFFFF0000) == 0) {
        return (unsigned int *)0;
    }

    unsigned int *xcap = g_xhc.mmio + (((*hccp1 & 0xFFFF0000) >> 16) << 2);
    unsigned int next = (*xcap & 0xFF00) >> 8;
    unsigned int id = *xcap & 0xFF;

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
        return (unsigned int *)0;
    }

    return xcap;
}
