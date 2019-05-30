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

// TODO: implement commented environs

///* --------------------------------------------------------------------------
///*/
///* Userspace */
///* --------------------------------------------------------------------------
///*/
//
//#if !defined(KERNEL) && !defined(_WIN32)
//#if defined(__cplusplus) && __has_include("cstdint")
//#include <cstdint>
//#else
//#include <stdint.h>
//#endif
//#endif

/* -------------------------------------------------------------------------- */
/* Linux Types                                                                */
/* -------------------------------------------------------------------------- */

#if defined(__linux__) && !defined(__XEN__)
#include <linux/printk.h>
#include <linux/types.h>
#endif

///* --------------------------------------------------------------------------
///*/
///* Windows Types */
///* --------------------------------------------------------------------------
///*/
//
//#if defined(_WIN32)
//#include <basetsd.h>
// typedef INT8 int8_t;
// typedef INT16 int16_t;
// typedef INT32 int32_t;
// typedef INT64 int64_t;
// typedef UINT8 uint8_t;
// typedef UINT16 uint16_t;
// typedef UINT32 uint32_t;
// typedef UINT64 uint64_t;
// typedef UINT_PTR uintptr_t;
// typedef INT_PTR intptr_t;
//#define PRId64 "lld"
//#endif
//
///* --------------------------------------------------------------------------
///*/
///* EFI Types */
///* --------------------------------------------------------------------------
///*/
//
//#if defined(KERNEL) && defined(EFI)
//#include "efi.h"
//#include "efilib.h"
//#define PRId64 "lld"
//#endif

#define XUE_PAGE_SIZE 4096

/* xHC PCI config */
#define XUE_XHC_CLASSC 0xC0330
#define XUE_XHC_VEN_INTEL 0x8086
#define XUE_XHC_DEV_SKYLK 0xA2AF
#define XUE_XHC_DEV_CANLK 0xA36D

/* USB configurations */
#define XUE_HOST_WIN10

#if defined(XUE_HOST_WIN10)
#define XUE_DBC_VENDOR 0x3495
#define XUE_DBC_PRODUCT 0x00E0
#else /* assume Linux host if not Windows */
#define XUE_DBC_VENDOR 0x1D6B
#define XUE_DBC_PRODUCT 0x0010
#endif

#define XUE_DBC_PROTOCOL 0x0000

#define XUE_CTX_SIZE 16
#define XUE_CTX_BYTES (XUE_CTX_SIZE * 4)

#define XUE_CTRL_DCR 0
#define XUE_CTRL_HOT 2
#define XUE_CTRL_HIT 3
#define XUE_CTRL_DRC 4
#define XUE_CTRL_DCE 31

#define XUE_PSC_PED 1
#define XUE_PSC_CSC 17
#define XUE_PSC_PRC 21
#define XUE_PSC_PLC 22
#define XUE_PSC_CEC 23

#define XUE_PSC_ACK_MASK \
    ((1UL << XUE_PSC_CSC) | (1UL << XUE_PSC_PRC) | \
     (1UL << XUE_PSC_PLC) | (1UL << XUE_PSC_CEC))

enum {
    /**
     * State after a hardware reset or assertion of HCRST. This state
     * transitions to "disconnected" after setting CTRL.DCE. Clearing CTRL.DCE
     * or setting USBCMD.HCRST takes the DbC from any state to this state.
     */
    xue_dbc_off,

    /**
     * Transitions to "enabled" once the port is successfully enumerated
     * by the host. When a disconnect is detected in any state other than
     * off, the DbC transitions to this state. Any time "disconnected" is
     * a source or destination state, the PORTSC.CSC bit is set to one.
     */
    xue_dbc_disconnected,

    /**
     * Host enumeration takes place while in this state. The DbC moves
     * to "configured" provided the host configuration is successful.
     *
     * If configuration fails due to an internal error, then this
     * transitions to "error"
     * If a LTSSM timeout occurs, then PORTSC.PLC is set and this
     * transitions to "disabled"
     * A tPortConfigurationTimeout sets PORTSC.CEC and transitions this
     * to "disabled"
     * If a hot or warm reset is detected, then this moves to "resetting"
     */
    xue_dbc_enabled,

    /**
     * Once in this state, the DbC is ready to send/recv data from its
     * two endpoints.
     *
     * If the host deconfigures the device, this moves to "enabled".
     * If the LTSSM timesout, this moves to "error" and set PORTSC.PLC
     * If a hot or warm reset is detected, this moves to "resetting"
     */
    xue_dbc_configured,

    /**
     * In this state while hot or warm reset is being signaled and
     * PORTSC.PED = 0, PORTSC.PR = 1.
     * Once reset is done, this moves to "enabled" with PORTSC.PED = 1
     * and PORTSC.PRC = 1
     */
    xue_dbc_resetting,

    /**
     * Writing 0 to PORTSC.PED will move to this state. This allows
     * the driver to disconnect from the host while maintaining ownership
     * of the root hub port we are using.
     *
     * Writing 1 to PORTSC.PED will move this state to "enabled"
     */
    xue_dbc_disabled,

    /**
     * Come here from "configured" or "enabled", and move to "resetting"
     * if a warm or hot reset is detected
     */
    xue_dbc_error
};

enum { xue_trb_norm = 1, xue_trb_tfre = 32, xue_trb_psce = 34 };
enum { xue_trb_cc_success = 1, xue_trb_cc_trb_err = 5 };
enum { xue_ep_bulk_out = 2, xue_ep_bulk_in = 6 };

/******************************************************************************
 * TRB ring
 *
 * TRB rings are circular queues of TRBs shared between the xHC and the driver.
 * Each ring has one producer and one consumer. The DbC has one event
 * ring and two transfer rings, one for each direction of transfer.
 *
 * The xHC hardware is the producer on the event ring, and the
 * driver is the consumer. This means that the event TRBs are read-only from
 * the driver.
 *
 * OTOH, the driver is the producer of all transfer TRBs on the two transfer
 * rings, so the driver enqueues transfers, and the hardware dequeues
 * transfers. The dequeue pointer of a transfer ring can be discovered in the
 * driver by examining the latest transfer event on the _event_ring_. The
 * transfer event TRB contains the address of the transfer TRB that generated
 * the event.
 *
 * To make each queue circular, the last TRB must be a link TRB, which points
 * to the beginning of the next queue. This implementation does not support
 * multiple segments, so each link TRB points back to the beginning of its
 * own segment.
 ******************************************************************************/

#define XUE_TRB_MAX_TFR (4096 << 4)
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

struct xue_ops {
    /**
     * alloc_pages (optional)
     *
     * @param order - allocate 2^order pages
     * @return the allocated pages
     */
    void *(*alloc_pages)(uint64_t order);

    /**
     * free_pages (must be != NULL if alloc_pages != NULL)
     *
     * @param addr the base address of the pages to free
     * @param order the order of the set of pages to free
     */
    void (*free_pages)(void *addr, uint64_t order);

    /**
     * map_xhc - map in the xHC MMIO region as UC memory
     *
     * @param phys the physical base address of the xHC
     * @param size the number of bytes to map in
     * @return the mapped virtual address
     */
    void *(*map_xhc)(uint64_t phys, uint64_t size);

    /**
     * unmap_xhc (optional)
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

    uint8_t *xhc_mmio;
    uint64_t xhc_mmio_phys;
    uint64_t xhc_mmio_size;
    uint64_t xhc_dbc_offset;
    uint32_t xhc_cf8;

    struct xue_dbc_reg *dbc_reg;
    struct xue_dbc_ctx *dbc_ctx;
    struct xue_erst_segment *dbc_erst;
    struct xue_trb_ring dbc_ering;
    struct xue_trb_ring dbc_oring;
    struct xue_trb_ring dbc_iring;
    struct xue_work_ring dbc_owork;
    char *dbc_str;
};

/******************************************************************************
 * eXtensible Host Controller (xhc)
 *
 * The DbC is an optional xHCI extended capability. Before the DbC can be used,
 * it needs to be found in the host controller's extended capability list. This
 * list resides in the controller's MMIO region, which in turn is referred to
 * by the 64-bit BAR in the controller's PCI config space.
 ******************************************************************************/

static inline uint32_t xue_xhc_read(struct xue *xue, uint32_t cf8, uint32_t reg)
{
    uint32_t addr = (cf8 & 0xFFFFFF03UL) | (reg << 2);
    xue->ops->outd(0xCF8, addr);
    return xue->ops->ind(0xCFC);
}

static inline void xue_xhc_write(struct xue *xue, uint32_t cf8, uint32_t reg,
                                 uint32_t val)
{
    uint32_t addr = (cf8 & 0xFFFFFF03UL) | (reg << 2);
    xue->ops->outd(0xCF8, addr);
    xue->ops->outd(0xCFC, val);
}

static inline void __xue_uart_putc(char c)
{
    __asm volatile(
        "movq $0x3f8, %%rdx\n\t"
        "movq %0, %%rax\n\t"
        "outb %%al, %%dx\n\t"
        :
        : "g"(c)
        : "cc"
    );
}

static inline int xue_xhc_init(struct xue *xue)
{
    uint32_t bar0;
    uint64_t bar1, devfn;

    xue->xhc_cf8 = 0;

    /* Search PCI bus 0 for the xHC... TODO: search on buses > 0 */
    for (devfn = 0; devfn < 256; devfn++) {
        uint32_t dev = (devfn & 0xF8) >> 3;
        uint32_t fun = devfn & 0x07;
        uint32_t cf8 = (1UL << 31) | (dev << 11) | (fun << 8);
        uint32_t hdr = (xue_xhc_read(xue, cf8, 3) & 0xFF0000U) >> 16;

        switch (xue_xhc_read(xue, cf8, 0)) {
        case (XUE_XHC_DEV_SKYLK << 16) | XUE_XHC_VEN_INTEL:
        case (XUE_XHC_DEV_CANLK << 16) | XUE_XHC_VEN_INTEL:
            break;
        default:
            continue;
        }

        if (hdr == 0 || hdr == 0x80) {
            if ((xue_xhc_read(xue, cf8, 2) >> 8) == XUE_XHC_CLASSC) {
                xue->xhc_cf8 = cf8;
                break;
            }
        }
    }

    if (!xue->xhc_cf8) {
        return 0;
    }

    /* ...we found it, so parse the BAR and map the registers */
    bar0 = xue_xhc_read(xue, xue->xhc_cf8, 4);
    bar1 = xue_xhc_read(xue, xue->xhc_cf8, 5);

    /* IO BARs not allowed; BAR must be 64-bit */
    if ((bar0 & 0x1) != 0 || ((bar0 & 0x6) >> 1) != 2) {
        return 0;
    }

    xue_xhc_write(xue, xue->xhc_cf8, 4, 0xFFFFFFFF);
    xue->xhc_mmio_size = ~(xue_xhc_read(xue, xue->xhc_cf8, 4) & 0xFFFFFFF0) + 1;
    xue_xhc_write(xue, xue->xhc_cf8, 4, bar0);

    xue->xhc_mmio_phys = (bar0 & 0xFFFFFFF0) | (bar1 << 32);
    xue->xhc_mmio =
        (uint8_t *)xue->ops->map_xhc(xue->xhc_mmio_phys, xue->xhc_mmio_size);

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

    xcap = (uint32_t *)(mmio + (((*hccp1 & 0xFFFF0000) >> 16) << 2));
    next = (*xcap & 0xFF00) >> 8;
    id = *xcap & 0xFF;

    /**
     * Table 7-1 of the spec states that 'next' is relative
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

    xue->xhc_dbc_offset = (uint64_t)xcap - (uint64_t)mmio;
    return (struct xue_dbc_reg *)xcap;
}

/**
 * Fields with the same interpretation for every TRB type (section 4.11.1).
 * These are the fields defined in the TRB template, minus the ENT bit. That
 * bit is the toggle cycle bit in link TRBs, so it shouldn't be in the
 * template.
 */
static inline uint32_t xue_trb_cyc(struct xue_trb *trb)
{
    return trb->ctrl & 0x1;
}

static inline uint32_t xue_trb_type(struct xue_trb *trb)
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
static inline uint64_t xue_trb_norm_buf(struct xue_trb *trb)
{
    return trb->params;
}

static inline uint32_t xue_trb_norm_inttgt(struct xue_trb *trb)
{
    return (trb->status & 0xFFC00000) >> 22;
}

static inline uint32_t xue_trb_norm_tdsz(struct xue_trb *trb)
{
    return (trb->status & 0x003E0000) >> 17;
}

static inline uint32_t xue_trb_norm_len(struct xue_trb *trb)
{
    return (trb->status & 0x0001FFFF);
}

static inline uint32_t xue_trb_norm_bei(struct xue_trb *trb)
{
    return (trb->ctrl & 0x200) >> 9;
}

static inline uint32_t xue_trb_norm_idt(struct xue_trb *trb)
{
    return (trb->ctrl & 0x40) >> 6;
}

static inline uint32_t xue_trb_norm_ioc(struct xue_trb *trb)
{
    return (trb->ctrl & 0x20) >> 5;
}

static inline uint32_t xue_trb_norm_ch(struct xue_trb *trb)
{
    return (trb->ctrl & 0x10) >> 4;
}

static inline uint32_t xue_trb_norm_ns(struct xue_trb *trb)
{
    return (trb->ctrl & 0x8) >> 3;
}

static inline uint32_t xue_trb_norm_isp(struct xue_trb *trb)
{
    return (trb->ctrl & 0x4) >> 2;
}

static inline uint32_t xue_trb_norm_ent(struct xue_trb *trb)
{
    return (trb->ctrl & 0x2) >> 1;
}

static inline void xue_trb_norm_set_buf(struct xue_trb *trb, uint64_t addr)
{
    trb->params = addr;
}

static inline void xue_trb_norm_set_len(struct xue_trb *trb, uint32_t len)
{
    trb->status &= ~0x1FFFFUL;
    trb->status |= len;
}

static inline void xue_trb_norm_set_chain(struct xue_trb *trb, int chain)
{
    trb->ctrl &= ~0x10UL;
    trb->ctrl |= (chain) ? 0x10UL : 0;
}

static inline void xue_trb_norm_set_ioc(struct xue_trb *trb)
{
    trb->ctrl |= 0x20;
}

static inline void xue_trb_norm_clear_ioc(struct xue_trb *trb)
{
    trb->ctrl &= ~0x20UL;
}

/**
 * Fields for Transfer Event TRBs (see section 6.4.2.1). Note that event
 * TRBs are read-only from software
 */
static inline uint64_t xue_trb_tfre_ptr(struct xue_trb *trb)
{
    return trb->params;
}

static inline uint32_t xue_trb_tfre_cc(struct xue_trb *trb)
{
    return trb->status >> 24;
}

static inline uint32_t xue_trb_tfre_tfrlen(struct xue_trb *trb)
{
    return trb->status & 0xFFFFFF;
}

static inline uint32_t xue_trb_tfre_slotid(struct xue_trb *trb)
{
    return trb->ctrl >> 24;
}

/* Endpoint ID */
static inline uint32_t xue_trb_tfre_epid(struct xue_trb *trb)
{
    return (trb->ctrl & 0x1F0000) >> 16;
}

/* Event data (immediate) */
static inline uint32_t xue_trb_tfre_ed(struct xue_trb *trb)
{
    return (trb->ctrl & 0x4) >> 2;
}

/* Fields for Port Status Change Event TRBs (see section 6.4.2.3) */
static inline uint32_t xue_trb_psce_portid(struct xue_trb *trb)
{
    return (trb->params & 0xFF000000) >> 24;
}

static inline uint32_t xue_trb_psce_cc(struct xue_trb *trb)
{
    return trb->status >> 24;
}

/* Fields for link TRBs (section 6.4.4.1) */
static inline uint64_t xue_trb_link_rsp(struct xue_trb *trb)
{
    return trb->params;
}

static inline uint32_t xue_trb_link_inttgt(struct xue_trb *trb)
{
    return trb->status >> 22;
}

static inline uint32_t xue_trb_link_tc(struct xue_trb *trb)
{
    return (trb->ctrl & 0x2) >> 1;
}

static inline uint32_t xue_trb_link_ch(struct xue_trb *trb)
{
    return (trb->ctrl & 0x10) >> 4;
}

static inline uint32_t xue_trb_link_ioc(struct xue_trb *trb)
{
    return (trb->ctrl & 0x20) >> 5;
}

static inline void xue_trb_link_set_rsp(struct xue_trb *trb, uint64_t rsp)
{
    trb->params = rsp;
}

static inline void xue_trb_link_set_tc(struct xue_trb *trb)
{
    trb->ctrl |= 0x2;
}

static inline void xue_trb_link_clear_tc(struct xue_trb *trb)
{
    trb->ctrl &= ~0x2UL;
}

static inline void xue_trb_link_set_ioc(struct xue_trb *trb)
{
    trb->ctrl |= 0x20;
}

static inline void xue_trb_link_clear_ioc(struct xue_trb *trb)
{
    trb->ctrl &= ~0x20UL;
}

static inline void xue_trb_ring_init(struct xue *xue, struct xue_trb_ring *ring,
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
    xue_trb_norm_set_len(&trb, len);
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


static inline int xue_dbc_is_enabled(struct xue *xue)
{
    return xue->dbc_reg->ctrl & (1UL << XUE_CTRL_DCE);
}

static inline void xue_dbc_enable(struct xue *xue)
{
    xue->ops->sfence();
    xue->dbc_reg->ctrl |= (1UL << XUE_CTRL_DCE);
}

static inline void xue_dbc_disable(struct xue *xue)
{
    xue->dbc_reg->ctrl &= ~(1UL << XUE_CTRL_DCE);
    xue->ops->sfence();
}

static inline uint32_t xue_ep_state(uint32_t *ep)
{
    return ep[0] & 0x7;
}

static inline uint32_t xue_ep_type(uint32_t *ep)
{
    return (ep[1] & 0x38) >> 3;
}

static inline void xue_set_ep_type(uint32_t *ep, uint32_t type)
{
    ep[1] &= ~0x38UL;
    ep[1] |= (type << 3);
}

/**
 * xue_dbc_init_ep
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
static inline void xue_dbc_init_ep(uint32_t *ep, uint64_t mbs,
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
static inline void xue_dbc_init_info(struct xue *xue, uint32_t *info)
{
    uint64_t *sda;

    const uint64_t st0len = 6;
    const uint64_t mfrlen = 8;
    const uint64_t prdlen = 32;
    const uint64_t serlen = 4;

    /* clang-format off */
    const char usb_str[] = {
        (char)st0len, 3, 9, 0, 4, 0,
        (char)mfrlen, 3, 'A', 0, 'I', 0, 'S', 0,
        (char)prdlen, 3, 'x', 0, 'H', 0, 'C', 0, 'I', 0, ' ', 0,
                         'D', 0, 'b', 0, 'C', 0, ' ', 0,
                         'D', 0, 'r', 0, 'i', 0, 'v', 0, 'e', 0, 'r', 0,
        (char)serlen, 3, '0', 0
    };
    /* clang-format on */

    xue_mcpy(xue->dbc_str, usb_str, sizeof(usb_str));

    sda = (uint64_t *)&info[0];
    sda[0] = xue->ops->virt_to_phys(xue->dbc_str);
    sda[1] = sda[0] + st0len;
    sda[2] = sda[0] + st0len + mfrlen;
    sda[3] = sda[0] + st0len + mfrlen + prdlen;
    info[8] = (serlen << 24) | (prdlen << 16) | (mfrlen << 8) | st0len;
}

static inline void xue_dbc_reset(struct xue *xue)
{
    struct xue_dbc_reg *reg = xue->dbc_reg;

    reg->portsc &= ~(1UL << XUE_PSC_PED);
    xue->ops->sfence();
    reg->ctrl &= ~(1UL << XUE_CTRL_DCE);
    xue->ops->sfence();
    reg->ctrl |= (1UL << XUE_CTRL_DRC);
}

static inline int xue_dbc_init(struct xue *xue)
{
    uint64_t erdp = 0, out = 0, in = 0, mbs = 0;
    struct xue_ops *op = xue->ops;
    struct xue_dbc_reg *reg = xue_xhc_find_dbc(xue);

    if (!reg) {
        return 0;
    }

    xue->dbc_reg = reg;
    xue_dbc_reset(xue);

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
    xue_dbc_init_info(xue, xue->dbc_ctx->info);
    xue_dbc_init_ep(xue->dbc_ctx->ep_out, mbs, xue_ep_bulk_out, out);
    xue_dbc_init_ep(xue->dbc_ctx->ep_in, mbs, xue_ep_bulk_in, in);

    reg->erstsz = 1;
    reg->erstba = op->virt_to_phys(xue->dbc_erst);
    reg->erdp = erdp;
    reg->cp = op->virt_to_phys(xue->dbc_ctx);
    reg->ddi1 = (XUE_DBC_VENDOR << 16) | XUE_DBC_PROTOCOL;
    reg->ddi2 = XUE_DBC_PRODUCT;

    return 1;
}

static inline int xue_dbc_alloc(struct xue *xue)
{
    struct xue_ops *ops = xue->ops;

    if (!ops->alloc_pages) {
        ops->free_pages = NULL;
        return 1;
    }

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

    xue->dbc_ering.trb = (struct xue_trb *)ops->alloc_pages(XUE_TRB_RING_ORDER);
    if (!xue->dbc_ering.trb) {
        goto free_erst;
    }

    xue->dbc_oring.trb = (struct xue_trb *)ops->alloc_pages(XUE_TRB_RING_ORDER);
    if (!xue->dbc_oring.trb) {
        goto free_etrb;
    }

    xue->dbc_iring.trb = (struct xue_trb *)ops->alloc_pages(XUE_TRB_RING_ORDER);
    if (!xue->dbc_iring.trb) {
        goto free_otrb;
    }

    xue->dbc_owork.buf = (uint8_t *)ops->alloc_pages(XUE_WORK_RING_ORDER);
    if (!xue->dbc_owork.buf) {
        goto free_itrb;
    }

    xue->dbc_str = (char *)ops->alloc_pages(0);
    if (!xue->dbc_str) {
        goto free_owrk;
    }

    return 1;

free_owrk:
    ops->free_pages(xue->dbc_owork.buf, 0);
free_itrb:
    ops->free_pages(xue->dbc_iring.trb, XUE_TRB_RING_ORDER);
free_otrb:
    ops->free_pages(xue->dbc_oring.trb, XUE_TRB_RING_ORDER);
free_etrb:
    ops->free_pages(xue->dbc_ering.trb, XUE_TRB_RING_ORDER);
free_erst:
    ops->free_pages(xue->dbc_erst, 0);
free_ctx:
    ops->free_pages(xue->dbc_ctx, 0);

    return 0;
}

static inline void xue_dbc_free(struct xue *xue)
{
    struct xue_ops *ops = xue->ops;
    if (!ops->free_pages) {
        return;
    }

    ops->free_pages(xue->dbc_str, 0);
    ops->free_pages(xue->dbc_owork.buf, XUE_WORK_RING_ORDER);
    ops->free_pages(xue->dbc_iring.trb, XUE_TRB_RING_ORDER);
    ops->free_pages(xue->dbc_oring.trb, XUE_TRB_RING_ORDER);
    ops->free_pages(xue->dbc_ering.trb, XUE_TRB_RING_ORDER);
    ops->free_pages(xue->dbc_erst, 0);
    ops->free_pages(xue->dbc_ctx, 0);
}

static inline int xue_open(struct xue *xue, struct xue_ops *ops)
{
    xue->ops = ops;

    /* After xue_xhc_init, the xHC's MMIO is mapped in */
    if (!xue_xhc_init(xue)) {
        return 0;
    }

    /* After xue_dbc_alloc, every virtual address is valid */
    if (!xue_dbc_alloc(xue)) {
        return 0;
    }

    if (!xue_dbc_init(xue)) {
        xue_dbc_free(xue);
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
#if defined(__linux__) || defined(__XEN__)
    printk("XUE DUMP:\n");
    printk("    ctrl: 0x%x stat: 0x%x psc: 0x%x\n",
           xue->dbc_reg->ctrl,
           xue->dbc_reg->st,
           xue->dbc_reg->portsc);

    printk("    id: 0x%x, db: 0x%x\n", xue->dbc_reg->id, xue->dbc_reg->db);
    printk("    erstsz: %u, erstba: 0x%lx\n", xue->dbc_reg->erstsz, xue->dbc_reg->erstba);
    printk("    erdp: 0x%lx, cp: 0x%lx\n", xue->dbc_reg->erdp, xue->dbc_reg->cp);
    printk("    ddi1: 0x%x, ddi2: 0x%x\n", xue->dbc_reg->ddi1, xue->dbc_reg->ddi2);
    printk("    erstba == virt_to_phys(erst): %d\n", xue->dbc_reg->erstba == xue->ops->virt_to_phys(xue->dbc_erst));
    printk("    erdp == virt_to_phys(erst[0].base): %d\n", xue->dbc_reg->erdp == xue->dbc_erst[0].base);
    printk("    cp == virt_to_phys(ctx): %d\n", xue->dbc_reg->cp == xue->ops->virt_to_phys(xue->dbc_ctx));
#endif
}

static inline void xue_close(struct xue *xue)
{
    xue_dbc_reset(xue);
    xue_dbc_free(xue);

    if (xue->ops->unmap_xhc) {
        xue->ops->unmap_xhc(xue->xhc_mmio);
    }
}

#ifdef __cplusplus
}
#endif
#endif
