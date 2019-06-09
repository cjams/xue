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

#ifndef XUE_H
#define XUE_H

#ifdef __cplusplus
extern "C" {
#endif

/* Linux */

#if defined(KERNEL) && defined(__linux__)
#include <linux/printk.h>
#include <linux/types.h>
#define xue_debug(...) printk(KERN_DEBUG "xue debug: " __VA_ARGS__)
#define xue_alert(...) printk(KERN_ALERT "xue alert: " __VA_ARGS__)
#define xue_error(...) printk(KERN_ERR "xue error: " __VA_ARGS__)
#endif

/* Windows */

#if defined(_WIN32)
#include <basetsd.h>
typedef INT8 int8_t;
typedef INT16 int16_t;
typedef INT32 int32_t;
typedef INT64 int64_t;
typedef UINT8 uint8_t;
typedef UINT16 uint16_t;
typedef UINT32 uint32_t;
typedef UINT64 uint64_t;
typedef UINT_PTR uintptr_t;
typedef INT_PTR intptr_t;

#define xue_debug(...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, \
                                  DPFLTR_INFO_LEVEL, "xue debug: " __VA_ARGS__)
#define xue_alert(...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, \
                                  DPFLTR_INFO_LEVEL, "xue alert: " __VA_ARGS__)
#define xue_error(...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, \
                                  DPFLTR_ERROR_LEVEL, "xue error: " __VA_ARGS__)
#endif

/* UEFI */

#if defined(KERNEL) && defined(EFI)
#include "efilib.h"
#define xue_debug(...) Print(L"xue debug: " __VA_ARGS__)
#define xue_alert(...) Print(L"xue alert: " __VA_ARGS__)
#define xue_error(...) Print(L"xue error: " __VA_ARGS__)
#endif

/* Bareflank */

#if defined(VMM)
#include <cstdio>
#define xue_debug(...) printf("xue debug: " __VA_ARGS__)
#define xue_alert(...) printf("xue alert: " __VA_ARGS__)
#define xue_error(...) printf("xue error: " __VA_ARGS__)
#endif

/* Supported xHC PCI configurations */
#define XUE_XHC_CLASSC 0xC0330
#define XUE_XHC_VEN_INTEL 0x8086
#define XUE_XHC_DEV_Z370 0xA2AF
#define XUE_XHC_DEV_Z390 0xA36D
#define XUE_XHC_DEV_WILDCAT_POINT 0x9CB1
#define XUE_XHC_DEV_SUNRISE_POINT 0x9D2F

/* DBC idVendor and idProduct */
#define XUE_DBC_VENDOR 0x1D6B
#define XUE_DBC_PRODUCT 0x0010
#define XUE_DBC_PROTOCOL 0x0000

/* DCCTRL fields */
#define XUE_CTRL_DCR 0
#define XUE_CTRL_HOT 2
#define XUE_CTRL_HIT 3
#define XUE_CTRL_DRC 4
#define XUE_CTRL_DCE 31

/* DCPORTSC fields */
#define XUE_PSC_PED 1
#define XUE_PSC_CSC 17
#define XUE_PSC_PRC 21
#define XUE_PSC_PLC 22
#define XUE_PSC_CEC 23

#define XUE_PSC_ACK_MASK \
    ((1UL << XUE_PSC_CSC) | (1UL << XUE_PSC_PRC) | \
     (1UL << XUE_PSC_PLC) | (1UL << XUE_PSC_CEC))

/******************************************************************************
 * TRB ring
 *
 * TRB rings are circular queues of TRBs shared between the xHC and the driver.
 * Each ring has one producer and one consumer. The DbC has one event
 * ring and two transfer rings; one IN and one OUT.
 *
 * The xHC hardware is the producer on the event ring, and the
 * driver is the consumer. This means that event TRBs are read-only from
 * the driver.
 *
 * OTOH, the driver is the producer of transfer TRBs on the two transfer
 * rings, so the driver enqueues transfers, and the hardware dequeues
 * them. The dequeue pointer of a transfer ring is read by the
 * driver by examining the latest transfer event TRB on the event ring. The
 * transfer event TRB contains the address of the transfer TRB that generated
 * the event.
 *
 * To make each transfer ring circular, the last TRB must be a link TRB, which
 * points to the beginning of the next queue. This implementation does not
 * support multiple segments, so each link TRB points back to the beginning of
 * its own segment.
 ******************************************************************************/

enum { xue_trb_norm = 1, xue_trb_tfre = 32, xue_trb_psce = 34 };
enum { xue_trb_cc_success = 1, xue_trb_cc_trb_err = 5 };
enum { xue_ep_bulk_out = 2, xue_ep_bulk_in = 6 };

#define XUE_PAGE_SIZE 4096
#define XUE_TRB_MAX_TFR (XUE_PAGE_SIZE << 4)
#define XUE_TRB_PER_PAGE (XUE_PAGE_SIZE / sizeof(struct xue_trb))

/* Defines the size in bytes of TRB rings as 2^XUE_TRB_RING_ORDER * 4096 */
#ifndef XUE_TRB_RING_ORDER
#define XUE_TRB_RING_ORDER 0
#endif
#define XUE_TRB_RING_CAP (XUE_TRB_PER_PAGE * (1ULL << XUE_TRB_RING_ORDER))

struct xue_trb_ring {
    struct xue_trb *trb; /* Array of TRBs */
    uint32_t enq; /* The offset of the enqueue ptr */
    uint32_t deq; /* The offset of the dequeue ptr */
    uint8_t cyc; /* Cycle state toggled on each wrap-around */
};

/* Defines the size in bytes of work rings as 2^XUE_WORK_RING_ORDER * 4096 */
#ifndef XUE_WORK_RING_ORDER
#define XUE_WORK_RING_ORDER 3
#endif
#define XUE_WORK_RING_CAP (XUE_PAGE_SIZE * (1ULL << XUE_WORK_RING_ORDER))

#if XUE_WORK_RING_CAP > XUE_TRB_MAX_TFR
#error "XUE_WORK_RING_ORDER must be at most 4"
#endif

struct xue_work_ring {
    uint8_t *buf;
    uint32_t enq;
    uint32_t deq;
    uint64_t phys;
};

#pragma pack(push, 1)

struct xue_trb {
    uint64_t params;
    uint32_t status;
    uint32_t ctrl;
};

struct xue_erst_segment {
    uint64_t base;
    uint16_t size;
    uint8_t rsvdz[6];
};

#define XUE_CTX_SIZE 16
#define XUE_CTX_BYTES (XUE_CTX_SIZE * 4)

struct xue_dbc_ctx {
    uint32_t info[XUE_CTX_SIZE];
    uint32_t ep_out[XUE_CTX_SIZE];
    uint32_t ep_in[XUE_CTX_SIZE];
};

struct xue_dbc_reg {
    uint32_t id;
    uint32_t db;
    uint32_t erstsz;
    uint32_t rsvdz;
    uint64_t erstba;
    uint64_t erdp;
    uint32_t ctrl;
    uint32_t st;
    uint32_t portsc;
    uint32_t rsvdp;
    uint64_t cp;
    uint32_t ddi1;
    uint32_t ddi2;
};

#pragma pack(pop)

struct xue_ops {
    /**
     * alloc_dma
     *
     * @param order - allocate 2^order pages suitable for read/write DMA
     * @return the allocated pages
     */
    void *(*alloc_dma)(uint64_t order);

    /**
     * free_dma (must be != NULL if alloc_dma != NULL)
     *
     * @param addr the base address of the pages to free
     * @param order the order of the set of pages to free
     */
    void (*free_dma)(void *addr, uint64_t order);

    /**
     * alloc_pages
     *
     * @param order - allocate 2^order pages
     * @return the allocated pages
     */
    void *(*alloc_pages)(uint64_t order);

    /**
     * free_pages (must be != NULL if alloc_page != NULL)
     *
     * @param addr the base address of the pages to free
     * @param order the order of the set of pages to free
     */
    void (*free_pages)(void *addr, uint64_t order);

    /**
     * map_xhc - map in the xHC MMIO region as UC memory
     *
     * @param phys the value from the xHC's BAR
     * @param size the number of bytes to map in
     * @return the mapped virtual address
     */
    void *(*map_xhc)(uint64_t phys, uint64_t size);

    /**
     * unmap_xhc
     *
     * @param virt the address to unmap
     */
    void (*unmap_xhc)(void *virt);

    /**
     * outd - write 32 bits to IO port
     *
     * @param port the port to write to
     * @param data the data to write
     */
    void (*outd)(uint32_t port, uint32_t data);

    /**
     * ind - read 32 bits from IO port
     *
     * @param port the port to read from
     * @return the data read from the port
     */
    uint32_t (*ind)(uint32_t port);

    /**
     * virt_to_phys - translate a virtual address to a physical address
     *
     * @param virt the virtual address to translate
     * @return the resulting physical address
     */
    uint64_t (*virt_to_phys)(const void *virt);

    /**
     * sfence - write memory barrier
     */
    void (*sfence)(void);
};

struct xue {
    struct xue_ops *ops;
    uint32_t xhc_cf8;

    uint64_t xhc_mmio_phys;
    uint64_t xhc_mmio_size;
    uint64_t xhc_dbc_offset;
    void *xhc_mmio;

    struct xue_dbc_reg *dbc_reg;
    struct xue_dbc_ctx *dbc_ctx;
    struct xue_erst_segment *dbc_erst;
    struct xue_trb_ring dbc_ering;
    struct xue_trb_ring dbc_oring;
    struct xue_trb_ring dbc_iring;
    struct xue_work_ring dbc_owork;
    char *dbc_str;
};

static inline void *xue_mset(void *dest, int c, uint64_t size)
{
    uint64_t i;
    char *d = (char *)dest;

    for (i = 0; i < size; i++) {
        d[i] = (char)c;
    }

    return dest;
}

static inline void *xue_mcpy(void *dest, const void *src, uint64_t size)
{
    uint64_t i;
    char *d = (char *)dest;
    const char *s = (const char *)src;

    for (i = 0; i < size; i++) {
        d[i] = s[i];
    }

    return dest;
}

static inline uint32_t xue_pci_read(struct xue *xue, uint32_t cf8, uint32_t reg)
{
    uint32_t addr = (cf8 & 0xFFFFFF03UL) | (reg << 2);
    xue->ops->outd(0xCF8, addr);
    return xue->ops->ind(0xCFC);
}

static inline void xue_pci_write(struct xue *xue, uint32_t cf8, uint32_t reg,
                                 uint32_t val)
{
    uint32_t addr = (cf8 & 0xFFFFFF03UL) | (reg << 2);
    xue->ops->outd(0xCF8, addr);
    xue->ops->outd(0xCFC, val);
}

static inline int xue_init_xhc(struct xue *xue)
{
    uint32_t bar0;
    uint64_t bar1, devfn;

    xue->xhc_cf8 = 0;

    /*
     * Search PCI bus 0 for the xHC. All the host controllers supported so far
     * are part of the chipset and are on bus 0.
     */
    for (devfn = 0; devfn < 256; devfn++) {
        uint32_t dev = (devfn & 0xF8) >> 3;
        uint32_t fun = devfn & 0x07;
        uint32_t cf8 = (1UL << 31) | (dev << 11) | (fun << 8);
        uint32_t hdr = (xue_pci_read(xue, cf8, 3) & 0xFF0000U) >> 16;

        switch (xue_pci_read(xue, cf8, 0)) {
        case (XUE_XHC_DEV_Z370 << 16) | XUE_XHC_VEN_INTEL:
        case (XUE_XHC_DEV_Z390 << 16) | XUE_XHC_VEN_INTEL:
        case (XUE_XHC_DEV_WILDCAT_POINT << 16) | XUE_XHC_VEN_INTEL:
        case (XUE_XHC_DEV_SUNRISE_POINT << 16) | XUE_XHC_VEN_INTEL:
            break;
        default:
            continue;
        }

        if (hdr == 0 || hdr == 0x80) {
            if ((xue_pci_read(xue, cf8, 2) >> 8) == XUE_XHC_CLASSC) {
                xue->xhc_cf8 = cf8;
                break;
            }
        }
    }

    if (!xue->xhc_cf8) {
        xue_error("Compatible xHC not found on bus 0");
        return 0;
    }

    /* ...we found it, so parse the BAR and map the registers */
    bar0 = xue_pci_read(xue, xue->xhc_cf8, 4);
    bar1 = xue_pci_read(xue, xue->xhc_cf8, 5);

    /* IO BARs not allowed; BAR must be 64-bit */
    if ((bar0 & 0x1) != 0 || ((bar0 & 0x6) >> 1) != 2) {
        return 0;
    }

    xue_pci_write(xue, xue->xhc_cf8, 4, 0xFFFFFFFF);
    xue->xhc_mmio_size = ~(xue_pci_read(xue, xue->xhc_cf8, 4) & 0xFFFFFFF0) + 1;
    xue_pci_write(xue, xue->xhc_cf8, 4, bar0);

    xue->xhc_mmio_phys = (bar0 & 0xFFFFFFF0) | (bar1 << 32);
    xue->xhc_mmio = xue->ops->map_xhc(xue->xhc_mmio_phys, xue->xhc_mmio_size);

    return 1;
}

/**
 * The first register of the debug capability (dbc) is found by traversing the
 * host controller's capability list (xcap) until a capability
 * with ID = 0xA is found. The xHCI capability list (xcap) begins at address
 * mmio + (HCCPARAMS1[31:16] << 2)
 */
static inline struct xue_dbc_reg *xue_xhc_find_dbc(struct xue *xue)
{
    uint32_t *xcap, next, id;
    uint8_t *mmio = (uint8_t *)xue->xhc_mmio;
    uint32_t *hccp1 = (uint32_t *)(mmio + 0x10);
    const uint32_t DBC_ID = 0xA;

    /**
     * Paranoid check against a zero value. The spec mandates that
     * at least one "supported protocol" capability must be implemented,
     * so this should always be false.
     */
    if ((*hccp1 & 0xFFFF0000) == 0) {
        return NULL;
    }

    xcap = (uint32_t *)(mmio + (((*hccp1 & 0xFFFF0000) >> 16) << 2));
    next = (*xcap & 0xFF00) >> 8;
    id = *xcap & 0xFF;

    /**
     * Table 7-1 of the spec states that 'next' is relative
     * to the current value of xcap and is a dword offset.
     */
    while (id != DBC_ID && next) {
        xcap += next;
        id = *xcap & 0xFF;
        next = (*xcap & 0xFF00) >> 8;
    }

    if (id != DBC_ID) {
        return NULL;
    }

    xue->xhc_dbc_offset = (uint64_t)xcap - (uint64_t)mmio;
    return (struct xue_dbc_reg *)xcap;
}

/**
 * Fields with the same interpretation for every TRB type (section 4.11.1).
 * These are the fields defined in the TRB template, minus the ENT bit. That
 * bit is the toggle cycle bit in link TRBs, so it shouldn't be in the
 * template.
 */
static inline uint32_t xue_trb_cyc(const struct xue_trb *trb)
{
    return trb->ctrl & 0x1;
}

static inline uint32_t xue_trb_type(const struct xue_trb *trb)
{
    return (trb->ctrl & 0xFC00) >> 10;
}

static inline void xue_trb_set_cyc(struct xue_trb *trb, uint32_t c)
{
    trb->ctrl &= ~0x1UL;
    trb->ctrl |= c;
}

static inline void xue_trb_set_type(struct xue_trb *trb, uint32_t t)
{
    trb->ctrl &= ~0xFC00UL;
    trb->ctrl |= (t << 10);
}

/* Fields for normal TRBs */
static inline void xue_trb_norm_set_buf(struct xue_trb *trb, uint64_t addr)
{
    trb->params = addr;
}

static inline void xue_trb_norm_set_len(struct xue_trb *trb, uint32_t len)
{
    trb->status &= ~0x1FFFFUL;
    trb->status |= len;
}

static inline void xue_trb_norm_set_ioc(struct xue_trb *trb)
{
    trb->ctrl |= 0x20;
}

/**
 * Fields for Transfer Event TRBs (see section 6.4.2.1). Note that event
 * TRBs are read-only from software
 */
static inline uint64_t xue_trb_tfre_ptr(const struct xue_trb *trb)
{
    return trb->params;
}

static inline uint32_t xue_trb_tfre_cc(const struct xue_trb *trb)
{
    return trb->status >> 24;
}

/* Fields for link TRBs (section 6.4.4.1) */
static inline void xue_trb_link_set_rsp(struct xue_trb *trb, uint64_t rsp)
{
    trb->params = rsp;
}

static inline void xue_trb_link_set_tc(struct xue_trb *trb)
{
    trb->ctrl |= 0x2;
}

static inline void xue_trb_ring_init(const struct xue *xue,
                                     struct xue_trb_ring *ring,
                                     int producer)
{
    xue_mset(ring->trb, 0, XUE_TRB_RING_CAP * sizeof(ring->trb[0]));

    ring->enq = 0;
    ring->deq = 0;
    ring->cyc = 1;

    /*
     * Producer implies transfer ring, so we have to place a
     * link TRB at the end that points back to trb[0]
     */
    if (producer) {
        struct xue_trb *link = &ring->trb[XUE_TRB_RING_CAP - 1];
        xue_trb_link_set_rsp(link, xue->ops->virt_to_phys(ring->trb));
        xue_trb_link_set_tc(link);
    }
}

static inline int xue_trb_ring_full(const struct xue_trb_ring *ring)
{
    return ((ring->enq + 1) & (XUE_TRB_RING_CAP - 1)) == ring->deq;
}

static inline int xue_work_ring_full(const struct xue_work_ring *ring)
{
    return ((ring->enq + 1) & (XUE_WORK_RING_CAP - 1)) == ring->deq;
}

static inline uint64_t xue_work_ring_size(const struct xue_work_ring *ring)
{
    if (ring->enq >= ring->deq) {
        return ring->enq - ring->deq;
    }

    return XUE_WORK_RING_CAP - ring->deq + ring->enq;
}

static inline void xue_push_trb(struct xue_trb_ring *ring, uint64_t dma,
                                uint64_t len)
{
    struct xue_trb trb;

    if (ring->enq == XUE_TRB_RING_CAP - 1) {
        ring->enq = 0;
        ring->cyc ^= 1;
    }

    trb.params = 0;
    trb.status = 0;
    trb.ctrl = 0;

    xue_trb_set_type(&trb, xue_trb_norm);
    xue_trb_set_cyc(&trb, ring->cyc);

    xue_trb_norm_set_buf(&trb, dma);
    xue_trb_norm_set_len(&trb, (uint32_t)len);
    xue_trb_norm_set_ioc(&trb);

    ring->trb[ring->enq++] = trb;
}

static inline int64_t xue_push_work(struct xue_work_ring *ring,
                                    const char *buf, int64_t len)
{
    int64_t i = 0;

    while (!xue_work_ring_full(ring) && i < len) {
        ring->buf[ring->enq] = buf[i++];
        ring->enq = (ring->enq + 1) & (XUE_WORK_RING_CAP - 1);
    }

    return i;
}

static inline void xue_pop_events(struct xue *xue)
{
    struct xue_trb_ring *er = &xue->dbc_ering;
    struct xue_trb_ring *tr = &xue->dbc_oring;
    struct xue_trb *event = &er->trb[er->deq];
    uint64_t erdp = xue->dbc_reg->erdp;

    while (xue_trb_cyc(event) == er->cyc) {
        switch (xue_trb_type(event)) {
        case xue_trb_tfre:
            if (xue_trb_tfre_cc(event) != xue_trb_cc_success) {
                break;
            }
            tr->deq = (xue_trb_tfre_ptr(event) & 0xFFF) >> sizeof(*event);
            break;
        case xue_trb_psce:
            xue->dbc_reg->portsc |= (XUE_PSC_ACK_MASK & xue->dbc_reg->portsc);
            break;
        default:
            break;
        }

        er->cyc = (er->deq == XUE_TRB_RING_CAP - 1) ? er->cyc ^ 1 : er->cyc;
        er->deq = (er->deq + 1) & (XUE_TRB_RING_CAP - 1);
        event = &er->trb[er->deq];
    }

    erdp &= ~0xFFFULL;
    erdp |= (er->deq << sizeof(*event));
    xue->ops->sfence();
    xue->dbc_reg->erdp = erdp;
}

static inline void xue_dbc_enable(struct xue *xue)
{
    xue->ops->sfence();
    xue->dbc_reg->ctrl |= (1UL << XUE_CTRL_DCE);
}

static inline void xue_set_ep_type(uint32_t *ep, uint32_t type)
{
    ep[1] &= ~0x38UL;
    ep[1] |= (type << 3);
}

/**
 * xue_init_dbc_ep
 *
 * Initializes the endpoint as specified in sections 7.6.3.2 and 7.6.9.2.
 * Each endpoint is Bulk, so MaxPStreams, LSA, HID, CErr, FE,
 * Interval, Mult, and Max ESIT Payload are all 0.
 *
 * Max packet size: 1024
 * Max burst size: debug mbs (in ctrl register)
 * EP type: 2 for OUT bulk, 6 for IN bulk
 * TR dequeue ptr: physical base address of transfer ring
 * Avg TRB length: software defined (see section 4.14.1.1)
 */
static inline void xue_init_dbc_ep(uint32_t *ep, uint64_t mbs,
                                   uint32_t type, uint64_t tr_phys)
{
    xue_mset(ep, 0, XUE_CTX_BYTES);
    xue_set_ep_type(ep, type);

    ep[1] |= (1024 << 16) | ((uint32_t)mbs << 8);
    ep[2] = (tr_phys & 0xFFFFFFFF) | 1;
    ep[3] = tr_phys >> 32;
    ep[4] = 3 * 1024;
}

/* Initialize the DbC info with USB string descriptor addresses */
static inline void xue_init_dbc_info(struct xue *xue, uint32_t *info)
{
    uint64_t *sda;

    /* clang-format off */
    const char usb_str[] = {
        6,  3, 9, 0, 4, 0,
        8,  3, 'A', 0, 'I', 0, 'S', 0,
        32, 3, 'x', 0, 'H', 0, 'C', 0, 'I', 0, ' ', 0,
               'D', 0, 'b', 0, 'C', 0, ' ', 0,
               'D', 0, 'r', 0, 'i', 0, 'v', 0, 'e', 0, 'r', 0,
        4, 3, '0', 0
    };
    /* clang-format on */

    xue_mcpy(xue->dbc_str, usb_str, sizeof(usb_str));

    sda = (uint64_t *)&info[0];
    sda[0] = xue->ops->virt_to_phys(xue->dbc_str);
    sda[1] = sda[0] + 6;
    sda[2] = sda[0] + 6 + 8;
    sda[3] = sda[0] + 6 + 8 + 32;
    info[8] = (4 << 24) | (32 << 16) | (8 << 8) | 6;
}

static inline void xue_reset_dbc(struct xue *xue)
{
    struct xue_dbc_reg *reg = xue->dbc_reg;

    reg->portsc &= ~(1UL << XUE_PSC_PED);
    xue->ops->sfence();
    reg->ctrl &= ~(1UL << XUE_CTRL_DCE);
    xue->ops->sfence();
}

static inline int xue_init_dbc(struct xue *xue)
{
    uint64_t erdp = 0, out = 0, in = 0, mbs = 0;
    struct xue_ops *op = xue->ops;
    struct xue_dbc_reg *reg = xue_xhc_find_dbc(xue);

    if (!reg) {
        return 0;
    }

    xue->dbc_reg = reg;
    xue_reset_dbc(xue);

    xue_trb_ring_init(xue, &xue->dbc_ering, 0);
    xue_trb_ring_init(xue, &xue->dbc_oring, 1);
    xue_trb_ring_init(xue, &xue->dbc_iring, 1);

    erdp = op->virt_to_phys(xue->dbc_ering.trb);
    if (!erdp) {
        return 0;
    }

    xue_mset(xue->dbc_erst, 0, sizeof(*xue->dbc_erst));
    xue->dbc_erst->base = erdp;
    xue->dbc_erst->size = XUE_TRB_RING_CAP;

    mbs = (reg->ctrl & 0xFF0000) >> 16;
    out = op->virt_to_phys(xue->dbc_oring.trb);
    in = op->virt_to_phys(xue->dbc_iring.trb);

    xue_mset(xue->dbc_ctx, 0, sizeof(*xue->dbc_ctx));
    xue_init_dbc_info(xue, xue->dbc_ctx->info);
    xue_init_dbc_ep(xue->dbc_ctx->ep_out, mbs, xue_ep_bulk_out, out);
    xue_init_dbc_ep(xue->dbc_ctx->ep_in, mbs, xue_ep_bulk_in, in);

    reg->erstsz = 1;
    reg->erstba = op->virt_to_phys(xue->dbc_erst);
    reg->erdp = erdp;
    reg->cp = op->virt_to_phys(xue->dbc_ctx);
    reg->ddi1 = (XUE_DBC_VENDOR << 16) | XUE_DBC_PROTOCOL;
    reg->ddi2 = XUE_DBC_PRODUCT;

    return 1;
}

static inline int xue_alloc_dbc(struct xue *xue)
{
    struct xue_ops *ops = xue->ops;

    if (!ops->alloc_pages) {
        ops->free_pages = NULL;
    } else {
        if (!ops->free_pages) {
            return 0;
        }

        xue->dbc_ctx = (struct xue_dbc_ctx *)ops->alloc_pages(0);
        if (!xue->dbc_ctx) {
            return 0;
        }

        xue->dbc_erst = (struct xue_erst_segment *)ops->alloc_pages(0);
        if (!xue->dbc_erst) {
            goto free_ctx;
        }
    }

    if (!ops->alloc_dma) {
        ops->free_dma = NULL;
        return 1;
    }

    if (!ops->free_dma) {
        goto free_erst;
    }

    xue->dbc_ering.trb = (struct xue_trb *)ops->alloc_dma(XUE_TRB_RING_ORDER);
    if (!xue->dbc_ering.trb) {
        goto free_erst;
    }

    xue->dbc_oring.trb = (struct xue_trb *)ops->alloc_dma(XUE_TRB_RING_ORDER);
    if (!xue->dbc_oring.trb) {
        goto free_etrb;
    }

    xue->dbc_iring.trb = (struct xue_trb *)ops->alloc_dma(XUE_TRB_RING_ORDER);
    if (!xue->dbc_iring.trb) {
        goto free_otrb;
    }

    xue->dbc_owork.buf = (uint8_t *)ops->alloc_dma(XUE_WORK_RING_ORDER);
    if (!xue->dbc_owork.buf) {
        goto free_itrb;
    }

    xue->dbc_str = (char *)ops->alloc_dma(0);
    if (!xue->dbc_str) {
        goto free_owrk;
    }

    return 1;

free_owrk:
    ops->free_dma(xue->dbc_owork.buf, XUE_WORK_RING_ORDER);
free_itrb:
    ops->free_dma(xue->dbc_iring.trb, XUE_TRB_RING_ORDER);
free_otrb:
    ops->free_dma(xue->dbc_oring.trb, XUE_TRB_RING_ORDER);
free_etrb:
    ops->free_dma(xue->dbc_ering.trb, XUE_TRB_RING_ORDER);
free_erst:
    ops->free_pages(xue->dbc_erst, 0);
free_ctx:
    ops->free_pages(xue->dbc_ctx, 0);

    return 0;
}

static inline void xue_free_dbc(struct xue *xue)
{
    struct xue_ops *ops = xue->ops;

    if (!ops->free_dma) {
        return;
    }
    ops->free_dma(xue->dbc_str, 0);
    ops->free_dma(xue->dbc_owork.buf, XUE_WORK_RING_ORDER);
    ops->free_dma(xue->dbc_iring.trb, XUE_TRB_RING_ORDER);
    ops->free_dma(xue->dbc_oring.trb, XUE_TRB_RING_ORDER);
    ops->free_dma(xue->dbc_ering.trb, XUE_TRB_RING_ORDER);

    if (!ops->free_pages) {
        return;
    }
    ops->free_pages(xue->dbc_erst, 0);
    ops->free_pages(xue->dbc_ctx, 0);
}

static inline int xue_open(struct xue *xue, struct xue_ops *ops)
{
    xue->ops = ops;

    if (!xue_init_xhc(xue)) {
        return 0;
    }

    if (!xue_alloc_dbc(xue)) {
        return 0;
    }

    if (!xue_init_dbc(xue)) {
        xue_free_dbc(xue);
        if (ops->unmap_xhc) {
            ops->unmap_xhc(xue->xhc_mmio);
        }
        return 0;
    }

    xue->dbc_owork.enq = 0;
    xue->dbc_owork.deq = 0;
    xue->dbc_owork.phys = ops->virt_to_phys(xue->dbc_owork.buf);

    xue_dbc_enable(xue);
    return 1;
}

static inline void xue_flush(struct xue *xue)
{
    struct xue_dbc_reg *reg = xue->dbc_reg;
    struct xue_trb_ring *out = &xue->dbc_oring;
    struct xue_work_ring *wrk = &xue->dbc_owork;

    xue_pop_events(xue);

    if (!(reg->ctrl & (1UL << XUE_CTRL_DCR))) {
        return;
    }

    if (reg->ctrl & (1UL << XUE_CTRL_DRC)) {
        reg->ctrl |= (1UL << XUE_CTRL_DRC);
        reg->portsc |= (1UL << XUE_PSC_PED);
        xue->ops->sfence();
    }

    if (xue_trb_ring_full(out)) {
        return;
    }

    if (wrk->enq > wrk->deq) {
        xue_push_trb(out, wrk->phys + wrk->deq, wrk->enq - wrk->deq);
        wrk->deq = wrk->enq;
    } else {
        xue_push_trb(out, wrk->phys + wrk->deq, XUE_WORK_RING_CAP - wrk->deq);
        wrk->deq = 0;
        if (wrk->enq > 0 && !xue_trb_ring_full(out)) {
            xue_push_trb(out, wrk->phys, wrk->enq);
            wrk->deq = wrk->enq;
        }
    }

    xue->ops->sfence();
    xue->dbc_reg->db &= 0xFFFF00FF;
}

static inline int64_t xue_write(struct xue *xue, const char *buf,
                                uint64_t size)
{
    int64_t ret;

    if (!buf || size <= 0) {
        return 0;
    }

    ret = xue_push_work(&xue->dbc_owork, buf, size);
    if (!ret) {
        return 0;
    }

    xue_flush(xue);
    return ret;
}

static inline int64_t xue_putc(struct xue *xue, char c)
{
    if (!xue_push_work(&xue->dbc_owork, &c, 1)) {
        return 0;
    }

    if (c == '\n') {
        xue_flush(xue);
    }

    return 1;
}

static inline void xue_dump(struct xue *xue)
{
    (void)xue;

    xue_debug("XUE DUMP:\n");
    xue_debug("    ctrl: 0x%x stat: 0x%x psc: 0x%x\n",
           xue->dbc_reg->ctrl,
           xue->dbc_reg->st,
           xue->dbc_reg->portsc);

    xue_debug("    id: 0x%x, db: 0x%x\n", xue->dbc_reg->id, xue->dbc_reg->db);
    xue_debug("    erstsz: %u, erstba: 0x%llx\n", xue->dbc_reg->erstsz, xue->dbc_reg->erstba);
    xue_debug("    erdp: 0x%llx, cp: 0x%llx\n", xue->dbc_reg->erdp, xue->dbc_reg->cp);
    xue_debug("    ddi1: 0x%x, ddi2: 0x%x\n", xue->dbc_reg->ddi1, xue->dbc_reg->ddi2);
    xue_debug("    erstba == virt_to_phys(erst): %d\n", xue->dbc_reg->erstba == xue->ops->virt_to_phys(xue->dbc_erst));
    xue_debug("    erdp == virt_to_phys(erst[0].base): %d\n", xue->dbc_reg->erdp == xue->dbc_erst[0].base);
    xue_debug("    cp == virt_to_phys(ctx): %d\n", xue->dbc_reg->cp == xue->ops->virt_to_phys(xue->dbc_ctx));
}

static inline void xue_close(struct xue *xue)
{
    xue_reset_dbc(xue);
    xue_free_dbc(xue);

    if (xue->ops->unmap_xhc) {
        xue->ops->unmap_xhc(xue->xhc_mmio);
    }
}

#ifdef __cplusplus
}
#endif
#endif
