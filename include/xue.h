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

#if defined(KERNEL) && defined(__linux__)
#include <linux/printk.h>
#include <linux/types.h>
#define PRId64 "lld"
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
#define XUE_RING_ALIGN XUE_PAGE_SIZE

/* xHC PCI config */
#define XUE_XHC_CLASSC 0xC0330
#define XUE_XHC_VENDOR 0x8086
#define XUE_XHC_DEV_SKYLAKE 0xA2AF
#define XUE_XHC_DEV_CANNONLAKE 0xA36D

/* DbC USB config */
#define XUE_DBC_VENDOR 0x1d6b
#define XUE_DBC_PRODUCT 0x0010
#define XUE_DBC_PROTOCOL 0x0000

#define DBC_CTX_DWORDS 16
#define DBC_CTX_BYTES (DBC_CTX_DWORDS * 4)

#define CTRL_DCR_SHIFT 0
#define CTRL_LSE_SHIFT 1
#define CTRL_HOT_SHIFT 2
#define CTRL_HIT_SHIFT 3
#define CTRL_DRC_SHIFT 4
#define CTRL_DCE_SHIFT 31

#define ST_ERNE_SHIFT 0
#define ST_SBR_SHIFT 1

#define PORTSC_CCS_SHIFT 0
#define PORTSC_PED_SHIFT 1
#define PORTSC_PR_SHIFT 4
#define PORTSC_PLS_SHIFT 5
#define PORTSC_CSC_SHIFT 17
#define PORTSC_PRC_SHIFT 21
#define PORTSC_PLC_SHIFT 22
#define PORTSC_CEC_SHIFT 23
#define PORTSC_PLS_MASK 0x1E0

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

enum { xue_trb_cc_success = 1, xue_trb_cc_trb_err = 5 };

enum {
    xue_trb_norm = 1,
    xue_trb_link = 6,
    xue_trb_tfre = 32,
    xue_trb_psce = 34
};

enum {
    xue_ep_disabled,
    xue_ep_running,
    xue_ep_halted,
    xue_ep_stopped,
    xue_ep_error,
    xue_ep_rsvd5,
    xue_ep_rsvd6,
    xue_ep_rsvd7
};

enum {
    xue_ep_not_valid,
    xue_ep_isoch_out,
    xue_ep_bulk_out,
    xue_ep_intr_out,
    xue_ep_ctrl,
    xue_ep_isoch_in,
    xue_ep_bulk_in,
    xue_ep_intr_in
};

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

#define XUE_TRB_MAX_LEN (4096 << 4)
#define XUE_TRB_PER_PAGE (XUE_PAGE_SIZE / sizeof(struct xue_trb))
#define XUE_PAGE_PER_SEG 1
#define XUE_SEG_PER_RING 1

struct xue_trb;

struct xue_trb_ring {
    struct xue_trb *trb; /* Array of TRBs */
    uint32_t size; /* Number of TRBs in the ring */
    uint32_t enq; /* The offset of the enqueue ptr */
    uint32_t deq; /* The offset of the dequeue ptr */
    uint32_t cycle; /* Cycle state toggled on each wrap-around */
};

/* Defines the size of the work ring as 2^XUE_WORK_ORDER 4K pages */
#ifndef XUE_WORK_ORDER
#define XUE_WORK_ORDER 3
#endif

struct xue_work_ring {
    uint8_t *buf;
    uint32_t enq;
    uint32_t order;
    uint64_t phys;
    uint32_t size;
};

#pragma pack(push, 1)

struct xue_trb {
    uint64_t params;
    uint32_t status;
    uint32_t ctrl;
};

struct xue_erst_segment {
    uint64_t base;
    uint16_t nr_trb;
    uint8_t rsvdz[6];
};

struct xue_dbc_ctx {
    uint32_t info[DBC_CTX_DWORDS];
    uint32_t ep_out[DBC_CTX_DWORDS];
    uint32_t ep_in[DBC_CTX_DWORDS];
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
     * memset - fill memory with a constant byte
     *
     * @param dest the destination buffer to fill
     * @param c the byte to fill with
     * @param size the number of bytes to fill
     * @return the destination buffer post-fill
     */
    void *(*memset)(void *dest, int c, uint64_t size);

    /**
     * memcpy - copy memory from src to dest
     *
     * @param dest the destination buffer
     * @param src the src buffer
     * @param size the number of bytes to copy from src into buffer
     * @return the destination buffer post-copy
     */
    void *(*memcpy)(void *dest, const void *src, uint64_t size);

    /**
     * alloc_pages - allocate virtually-contiguous 4KB pages
     *
     * @param order - allocate 2^order pages
     * @return the allocated pages
     */
    void *(*alloc_pages)(uint64_t order);

    /**
     * free_pages - release previously alloc_pages()'d page range
     *
     * @param addr the base address of the pages to free
     * @param order the order given to alloc_pages
     */
    void (*free_pages)(void *addr, uint64_t order);

    /**
     * map_mmio - map in uncacheable MMIO region
     *
     * @param phys the physical address to map in
     * @param size the number of bytes to map in
     * @return the virtual address
     */
    void *(*map_mmio)(uint64_t phys, uint64_t size);

    /**
     * unmap_mmio - release previously map_mmio()'d region
     *
     * @param virt the address to unmap
     */
    void (*unmap_mmio)(void *virt);

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
    void (*mfence)(void);
};

struct xue_string {
    char *buf;
    uint64_t len;
};

struct xue {
    struct xue_ops *ops;

    // xHC fields
    uint8_t *xhc_mmio;
    uint64_t xhc_mmio_phys;
    uint64_t xhc_mmio_size;
    uint64_t xhc_dbc_offset;
    uint32_t xhc_cf8;

    // DbC fields
    struct xue_dbc_reg *dbc_reg;
    struct xue_dbc_ctx *dbc_ctx;
    struct xue_erst_segment *dbc_erst;
    struct xue_trb_ring dbc_ering;
    struct xue_trb_ring dbc_oring;
    struct xue_trb_ring dbc_iring;
    struct xue_string dbc_strings;

    struct xue_work_ring out_work;
};

static inline void *xue_alloc_page(struct xue *xue)
{
    return xue->ops->alloc_pages(0);
}

static inline void xue_free_page(struct xue *xue, void *addr)
{
    return xue->ops->free_pages(addr, 0);
}

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
        case (XUE_XHC_DEV_SKYLAKE << 16) | XUE_XHC_VENDOR:
        case (XUE_XHC_DEV_CANNONLAKE << 16) | XUE_XHC_VENDOR:
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
        (uint8_t *)xue->ops->map_mmio(xue->xhc_mmio_phys, xue->xhc_mmio_size);

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
 * Transfer request blocks (TRBs) are the basic blocks on which all DbC (and
 * xHC) transactions occur. Each TRB is 16 bytes, with the first 8 bytes being
 * the TRB "parameters", next 4 bytes the "status" and the next 4 bytes the
 * "control".
 *
 * There are several different types of TRBs, each with their own
 * interpretation of the 16 bytes mentioned above and their own rules of use.
 */
static inline void xue_trb_init(struct xue_trb *trb)
{
    trb->params = 0;
    trb->status = 0;
    trb->ctrl = 0;
}

/**
 * Fields with the same interpretation for every TRB type (section 4.11.1).
 * These are the fields defined in the TRB template, minus the ENT bit. That
 * bit is the toggle cycle bit in link TRBs, so it shouldn't be in the
 * template.
 */
static inline uint32_t xue_trb_cycle(struct xue_trb *trb)
{
    return trb->ctrl & 0x1;
}

static inline uint32_t xue_trb_type(struct xue_trb *trb)
{
    return (trb->ctrl & 0xFC00) >> 10;
}

static inline void xue_trb_set_cycle(struct xue_trb *trb, uint32_t c)
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

static inline void xue_trb_norm_dump(struct xue_trb *trb)
{
    //    printf("normal    trb: cycle: %d type: %d buf: 0x%llx tgt: %u ",
    //           xue_trb_cycle(trb), xue_trb_type(trb), xue_trb_norm_buf(trb),
    //           xue_trb_norm_inttgt(trb));
    //    printf("tdsz: %u len: %u bei: %u idt: %u ioc: %u ch: %u ns: %u ",
    //           xue_trb_norm_tdsz(trb), xue_trb_norm_len(trb),
    //           xue_trb_norm_bei(trb), xue_trb_norm_idt(trb),
    //           xue_trb_norm_ioc(trb), xue_trb_norm_ch(trb),
    //           xue_trb_norm_ns(trb));
    //    printf("isp: %u ent: %u\n", xue_trb_norm_isp(trb),
    //    xue_trb_norm_ent(trb));
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

static inline void xue_trb_tfre_dump(struct xue_trb *trb)
{
    //    printf("tfr event trb: cycle: %d type: %d trbptr: 0x%llx code: %u ",
    //           trb_cycle(trb), trb_type(trb), xue_trb_tfre_ptr(trb),
    //           xue_trb_tfre_cc(trb));
    //
    //    printf("tfrlen: %u slotid: %u endpointid: %u ed: %u\n",
    //           xue_trb_tfre_tfrlen(trb), xue_trb_tfre_slotid(trb),
    //           xue_trb_tfre_epid(trb), xue_trb_tfre_ed(trb));
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

static inline void xue_trb_psce_dump(struct xue_trb *trb)
{
    //    printf("psc event trb: cycle: %d type: %d portid: %u code: %u\n",
    //           xue_trb_cycle(trb), xue_trb_type(trb),
    //           xue_trb_psce_portid(trb), xue_trb_psce_cc(trb));
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

static inline void xue_trb_link_dump(struct xue_trb *trb)
{
    //    printf("link      trb: cycle: %d type: %d rsp: 0x%llx tgt: %u ",
    //           xue_trb_cycle(trb), xue_trb_type(trb), xue_trb_link_rsp(trb),
    //           xue_trb_link_inttgt(trb));
    //    printf("ioc: %u ch: %u tc: %u ", xue_trb_link_ioc(trb),
    //           xue_trb_link_ch(trb), xue_trb_link_tc(trb));
}

static inline int xue_trb_ring_init(struct xue *xue, struct xue_trb_ring *ring,
                                    int producer)
{
    struct xue_ops *op;
    struct xue_trb *trb;

    op = xue->ops;
    trb = (struct xue_trb *)xue_alloc_page(xue);

    if (!trb) {
        return 0;
    }

    ring->size = XUE_TRB_PER_PAGE;
    op->memset(trb, 0, ring->size);

    ring->trb = trb;
    ring->enq = 0;
    ring->deq = 0;
    ring->cycle = 1;

    /*
     * Producer implies transfer ring, so we have to place a
     * link TRB at the end that points back to trb[0]
     */
    if (producer) {
        struct xue_trb *link = &trb[ring->size - 1];
        xue_trb_link_set_rsp(link, op->virt_to_phys(trb));
        xue_trb_link_set_tc(link);
    }

    return 1;
}

/**
 * Push a new work item on the OUT transfer ring. This is undefined for event
 * rings since they are read-only.
 *
 */
static inline void xue_push_out_trb(struct xue *xue, size_t size)
{
    struct xue_trb trb;
    struct xue_trb_ring *out;
    struct xue_work_ring *wrk;

    out = &xue->dbc_oring;
    wrk = &xue->out_work;

    if (out->enq == out->size - 1) {
        out->enq = 0;
        out->cycle ^= 1;
    }

    xue_trb_init(&trb);
    xue_trb_set_type(&trb, xue_trb_norm);
    xue_trb_set_cycle(&trb, out->cycle);

    xue_trb_norm_set_buf(&trb, wrk->phys + wrk->enq);
    xue_trb_norm_set_len(&trb, size);
    xue_trb_norm_set_ioc(&trb);

    out->trb[out->enq++] = trb;
}

static inline void xue_pop_events(struct xue *xue)
{
    struct xue_trb_ring *er = &xue->dbc_ering;
    struct xue_trb_ring *tr = &xue->dbc_oring;
    struct xue_trb *event = &er->trb[er->deq];
    uint64_t erdp = xue->dbc_reg->erdp;

    while (xue_trb_cycle(event) == er->cycle) {
        switch (xue_trb_type(event)) {
        case xue_trb_tfre:
            if (xue_trb_tfre_cc(event) != xue_trb_cc_success) {
                break;
            }
            tr->deq = (xue_trb_tfre_ptr(event) & 0xFFF) >> 4;
            break;
        case xue_trb_psce: {
            uint32_t mask =
                (1UL << PORTSC_CSC_SHIFT) | (1UL << PORTSC_PRC_SHIFT) |
                (1UL << PORTSC_PLC_SHIFT) | (1UL << PORTSC_CEC_SHIFT);
            uint32_t ack = mask & xue->dbc_reg->portsc;
            xue->dbc_reg->portsc |= ack;
            break;
        }
        default:
            break;
        }

        er->cycle = (er->deq == er->size - 1) ? er->cycle ^ 1 : er->cycle;
        er->deq = (er->deq + 1) & (er->size - 1);
        event = &er->trb[er->deq];
    }

    erdp &= ~0xFFFULL;
    erdp |= (er->deq << 4);
    xue->dbc_reg->erdp = erdp;
    xue->ops->mfence();
}

static inline int xue_dbc_is_enabled(struct xue *xue)
{
    return xue->dbc_reg->ctrl & (1UL << 31);
}

static inline void xue_dbc_enable(struct xue *xue)
{
    xue->dbc_reg->ctrl |= (1UL << 31);
}

static inline void xue_dbc_disable(struct xue *xue)
{
    xue->dbc_reg->ctrl &= ~(1UL << 31);
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
static inline void xue_dbc_init_ep(struct xue *xue, uint32_t *ep, uint32_t mbs,
                                   uint32_t type, uint64_t tr_phys)
{
    xue->ops->memset(ep, 0, DBC_CTX_BYTES);
    xue_set_ep_type(ep, type);

    ep[1] |= (1024 << 16) | (mbs << 8);
    ep[2] = (tr_phys & 0xFFFFFFFF) | 1;
    ep[3] = tr_phys >> 32;
    ep[4] = 3 * 1024;
}

/* Initialize the DbC info with USB string descriptor addresses */
static inline int xue_dbc_init_info(struct xue *xue, uint32_t *info)
{
    struct xue_ops *op = xue->ops;

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

    uint64_t *sda = (uint64_t *)&info[0];
    struct xue_string *str = &xue->dbc_strings;

    str->len = sizeof(usb_str);
    str->buf = (char *)xue_alloc_page(xue);
    if (!str->buf) {
        return 0;
    }

    op->memcpy(str->buf, usb_str, str->len);
    sda[0] = op->virt_to_phys(&str->buf[0]);
    sda[1] = sda[0] + st0len;
    sda[2] = sda[0] + st0len + mfrlen;
    sda[3] = sda[0] + st0len + mfrlen + prdlen;
    info[8] = (serlen << 24) | (prdlen << 16) | (mfrlen << 8) | st0len;

    return 1;
}

static inline int xue_dbc_init(struct xue *xue)
{
    uint32_t max_burst = 0;
    uint64_t erdp = 0, out = 0, in = 0;
    struct xue_ops *op = xue->ops;
    struct xue_dbc_reg *reg = xue_xhc_find_dbc(xue);
    struct xue_dbc_ctx *ctx = (struct xue_dbc_ctx *)xue_alloc_page(xue);
    struct xue_erst_segment *erst =
        (struct xue_erst_segment *)xue_alloc_page(xue);
    uint8_t *data = (uint8_t *)xue_alloc_page(xue);

    if (!reg || !ctx || !erst || !data) {
        return 0;
    }

    xue->dbc_reg = reg;

    xue_trb_ring_init(xue, &xue->dbc_ering, 0);
    xue_trb_ring_init(xue, &xue->dbc_oring, 1);
    xue_trb_ring_init(xue, &xue->dbc_iring, 1);

    erdp = op->virt_to_phys(xue->dbc_ering.trb);
    if (!erdp) {
        return 0;
    }

    op->memset(erst, 0, sizeof(*erst));
    erst->base = erdp;
    erst->nr_trb = XUE_PAGE_PER_SEG * XUE_TRB_PER_PAGE;
    xue->dbc_erst = erst;

    max_burst = (reg->ctrl & 0xFF0000) >> 16;
    out = op->virt_to_phys(xue->dbc_oring.trb);
    in = op->virt_to_phys(xue->dbc_iring.trb);

    op->memset(ctx, 0, sizeof(*ctx));
    xue_dbc_init_ep(xue, ctx->ep_out, max_burst, xue_ep_bulk_out, out);
    xue_dbc_init_ep(xue, ctx->ep_in, max_burst, xue_ep_bulk_in, in);
    xue_dbc_init_info(xue, ctx->info);
    xue->dbc_ctx = ctx;

    reg->erstsz = XUE_SEG_PER_RING;
    reg->erstba = op->virt_to_phys(erst);
    reg->erdp = erdp;
    reg->cp = op->virt_to_phys(ctx);
    reg->ddi1 = (XUE_DBC_VENDOR << 16) | XUE_DBC_PROTOCOL;
    reg->ddi2 = XUE_DBC_PRODUCT;

    xue_dbc_enable(xue);
    return 1;
}

static inline int xue_open(struct xue *xue, struct xue_ops *ops)
{
    struct xue_work_ring *wrk;
    xue->ops = ops;

    if (!xue_xhc_init(xue)) {
        return 0;
    }

    if (!xue_dbc_init(xue)) {
        return 0;
    }

    wrk = &xue->out_work;
    wrk->buf = (uint8_t *)xue_alloc_page(xue);
    if (!wrk->buf) {
        return 0;
    }

    wrk->enq = 0;
    wrk->order = XUE_WORK_ORDER;
    wrk->phys = ops->virt_to_phys(wrk->buf);
    wrk->size = XUE_PAGE_SIZE << wrk->order;

    return 1;
}

static inline void xue_close(struct xue *xue)
{
    xue_dbc_disable(xue);

    xue_free_page(xue, xue->dbc_strings.buf);
    xue_free_page(xue, xue->dbc_ering.trb);
    xue_free_page(xue, xue->dbc_oring.trb);
    xue_free_page(xue, xue->dbc_iring.trb);
    xue_free_page(xue, xue->dbc_erst);
    xue_free_page(xue, xue->dbc_ctx);
    xue_free_page(xue, xue->out_work.buf);

    xue->ops->unmap_mmio(xue->xhc_mmio);
}

static inline void xue_dump(void) {}

static inline int64_t xue_write(struct xue *xue, const uint8_t *data,
                                uint64_t size)
{
    struct xue_ops *ops;
    struct xue_trb_ring *out;
    struct xue_work_ring *wrk;

    xue_pop_events(xue);

    ops = xue->ops;
    out = &xue->dbc_oring;
    wrk = &xue->out_work;

    if (((out->enq + 1) & (out->size - 1)) == out->deq) {
        return 0;
    }

    size = (size > wrk->size) ? wrk->size : size;
    size = (size > XUE_TRB_MAX_LEN) ? XUE_TRB_MAX_LEN : size;

    if (size <= wrk->size - wrk->enq) {
        xue_push_out_trb(xue, size);
        ops->memcpy(&wrk->buf[wrk->enq], data, size);
        wrk->enq += size;
    } else {
        uint64_t nr = wrk->size - wrk->enq;
        xue_push_out_trb(xue, nr);
        ops->memcpy(&wrk->buf[wrk->enq], data, nr);
        wrk->enq = 0;

        if (((out->enq + 1) & (out->size - 1)) == out->deq) {
            size = nr;
            goto done;
        }

        xue_push_out_trb(xue, size - nr);
        ops->memcpy(&wrk->buf[wrk->enq], data + nr, size - nr);
        wrk->enq = size - nr;
    }

done:
    xue->ops->mfence();
    xue->dbc_reg->db &= 0xFFFF00FF;

    return size;
}

#ifdef __cplusplus
}
#endif
#endif
