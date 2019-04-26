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
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <stdio.h>
#include <pci.h>

/**
 * PCI constants
 */

#define NR_DEV 32
#define NR_FUN 8

#define XHC_VENDOR 0x8086
#define XHC_CLASSC 0x0C0330

enum {
    pci_hdr_normal               = 0x00,
    pci_hdr_pci_bridge           = 0x01,
    pci_hdr_cardbus_bridge       = 0x02,
    pci_hdr_normal_multi         = 0x80 | pci_hdr_normal,
    pci_hdr_pci_bridge_multi     = 0x80 | pci_hdr_pci_bridge,
    pci_hdr_cardbus_bridge_multi = 0x80 | pci_hdr_cardbus_bridge,
    pci_hdr_nonexistant          = 0xFF
};

/* xhc device */
struct xhc {
    unsigned long long cf8;
    unsigned long long mmio_size;
    unsigned long long mmio_phys;
} g_xhc;

static inline unsigned int xhc_read_reg(unsigned int reg)
{
    return cf8_read_reg(g_xhc.cf8, reg);
}

static inline void xhc_write_reg(unsigned int reg, unsigned int val)
{
    cf8_write_reg(g_xhc.cf8, reg, val);
}

static int matches_xhc(unsigned int cf8)
{
    if (!cf8_exists(cf8)) {
        return 0;
    }

    if ((cf8_read_reg(cf8, 0) & 0xFFFF) != XHC_VENDOR) {
        return 0;
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

/**
 * find_xhc
 *
 * Scan PCI bus 0 for the xhc device
 *
 */
int xhc_find(void)
{
    for (int d = 0; d < NR_DEV; d++) {
        for (int f = 0; f < NR_FUN; f++) {
            unsigned int cf8 = bdf_to_cf8(0, d, f);

            if (matches_xhc(cf8)) {
                g_xhc.cf8 = bdf_to_cf8(0, d, f);
                printf("Located xHC device at %02x:%02x.%02x\n", 0, d, f);
                return 1;
            }
        }
    }

    printf("ERROR: Failed to locate xHC on bus 0\n");
    return 0;
}

/**
 * According to the xHCI spec, section 5.2.1, an xhc must only
 * have one 64-bit MMIO bar
 */
int xhc_parse_mmio()
{
    unsigned int bar0 = xhc_read_reg(4);
    unsigned int bar1 = xhc_read_reg(5);

    printf("xhc_parse_mmio\n");

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

    g_xhc.mmio_size = size;
    g_xhc.mmio_phys = (bar0 & 0xFFFFFFF0) | ((unsigned long long)bar1 << 32);

    printf("    - mmio size: 0x%llx\n", g_xhc.mmio_size);
    printf("    - mmio phys: 0x%llx\n", g_xhc.mmio_phys);

    return 1;
}

void xue_init(void)
{
    printf("xue_init\n");
    if (!xhc_find()) {
        return;
    }

    if (!xhc_parse_mmio()) {
        return;
    }
}
