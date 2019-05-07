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

#ifndef XUE_PAGES
#define XUE_PAGES 8
#endif

#define XUE_PAGE_SIZE 4096
#define XUE_MEMORY (XUE_PAGES * XUE_PAGE_SIZE)

#include "types.h"

/**
 * struct xue_ops
 *
 * xue needs a few operations that are system-specific in order
 * to properly initialize the host controller and manage the
 * debug capability. The first thing users must provide before
 * using the xue API defined below is an instance of xue_ops
 * for their host system.
 */
struct xue_ops {
    void *(*memset)(void *dest, int c, size_t count);
    void *(*memcpy)(void *dest, const void *src, size_t count);
    void *(*malloc)(size_t count);

    /* Map UC */
    void *(*map_mmio)(uint64_t phys, size_t count);
    void (*free)(void *addr);
    void (*outd)(uint32_t port, uint32_t data);
    uint32_t (*ind)(uint32_t port);
    size_t (*virt_to_phys)(const void *virt);
};

struct dbc;

struct xue {
    struct xue_ops *ops;
    uint8_t *xhc_mmio;
    uint64_t xhc_mmio_phys;
    uint64_t xhc_mmio_size;
    uint32_t xhc_cf8;
    struct dbc *dbc;
};

static inline int xue_init(struct xue *xue, struct xue_ops *ops)
{
    xue->ops = ops;

    xhc_init(xue);
    dbc_init(xue);
}

void xue_disable(void);
void xue_dump(void);
void xue_write(const char *data, size_t count);
void xue_ack(void);

#endif
