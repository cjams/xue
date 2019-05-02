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
    dbc_off,

    /**
     * Transitions to "enabled" once the port is successfully enumerated
     * by the host. When a disconnect is detected in any state other than
     * off, the DbC transitions to this state. Any time "disconnected" is
     * a source or destination state, the PORTSC.CSC bit is set to one.
     */
    dbc_disconnected,

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
    dbc_enabled,

    /**
     * Once in this state, the DbC is ready to send/recv data from its
     * two endpoints.
     *
     * If the host deconfigures the device, this moves to "enabled".
     * If the LTSSM timesout, this moves to "error" and set PORTSC.PLC
     * If a hot or warm reset is detected, this moves to "resetting"
     */
    dbc_configured,

    /**
     * In this state while hot or warm reset is being signaled and
     * PORTSC.PED = 0, PORTSC.PR = 1.
     * Once reset is done, this moves to "enabled" with PORTSC.PED = 1
     * and PORTSC.PRC = 1
     */
    dbc_resetting,

    /**
     * Writing 0 to PORTSC.PED will move to this state. This allows
     * the driver to disconnect from the host while maintaining ownership
     * of the root hub port we are using.
     *
     * Writing 1 to PORTSC.PED will move this state to "enabled"
     */
    dbc_disabled,

    /**
     * Come here from "configured" or "enabled", and move to "resetting"
     * if a warm or hot reset is detected
     */
    dbc_error
};

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
    struct trb_ring *ering;
    struct trb_ring *oring;
    struct trb_ring *iring;
};

int dbc_init();
void dbc_dump();
void dbc_write(const char *data, unsigned int size);

int dbc_is_enabled();
void dbc_enable();
void dbc_disable();

void dbc_dump_regs(struct dbc_reg *reg);

#endif
