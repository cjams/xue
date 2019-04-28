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

/**
 * Common defines and interfaces for an xhc - eXtensible Host Controller
 */

#pragma pack(push, 1)

/* xhc device */
extern struct xhc {
    /* The PCI CONFIG_ADDR of the device */
    unsigned long long cf8;

    /* The size of the device's MMIO space */
    unsigned long long mmio_len;

    /* The host-physical address of the device' MMIO space */
    unsigned long long mmio_hpa;

    /* The virtual address of the device's MMIO space */
    unsigned char *mmio;
} g_xhc;

/**
 * struct xhc_cap_regs
 *
 * Each host controller has capability, operational, runtime, and
 * doorbell array registers. This struct defines the capability registers.
 */
struct xhc_cap_regs {
    unsigned char caplength;
    unsigned char rsvd0;
    unsigned short hciversion;
    unsigned int hcsparams1;
    unsigned int hcsparams2;
    unsigned int hcsparams3;
    unsigned int hccparams1;
    unsigned int dboff;
    unsigned int rtsoff;
    unsigned int hccparams2;
};

#pragma pack(pop)

/**
 * find_xhc
 *
 * Scan PCI bus 0 for the xhc device
 *
 * @return 1 on success, 0 otherwise
 */
int xhc_find(void);

/**
 * xhc_parse_bar
 *
 * According to the xHCI spec, section 5.2.1, an xhc must only
 * have one 64-bit MMIO bar
 *
 * @return 1 on success, 0 otherwise
 */
int xhc_parse_bar(void);

/**
 * xhc_dump_hccparams1
 *
 * Print the controller's HCCPARAMS1 capability register
 *
 * @return 1 on success, 0 otherwise
 */
int xhc_dump_hccparams1(void);

/**
 * The first register of the debug capability (xdc) is found by traversing the
 * host controller's capability list (xcap) until a capability
 * with ID = 0xA is found.
 *
 * The xHCI capability list (xcap) begins at address
 * mmio + (HCCPARAMS1[31:16] << 2)
 *
 * @return the base address of the xdc registers, if found. NULL otherwise.
 */
unsigned int *xhc_find_xdc_regs(void);

#endif
