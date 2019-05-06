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

#include <dbc.h>
#include <stdio.h>
#include <sys.h>
#include <xhc.h>
#include <xue/xue.h>

static void *xue_map_hpa(unsigned long long hpa, unsigned int len, int flags)
{
    if (!hpa || hpa & (XUE_PAGE_SIZE - 1)) {
        return (void *)0;
    }

    if (!len || len & (XUE_PAGE_SIZE - 1)) {
        return (void *)0;
    }

    return sys_map_hpa(hpa, len, flags);
}

static int xhc_init(void)
{
    static int done = 0;

    if (done) {
        return 1;
    }

    if (!find_xhc()) {
        return 0;
    }

    if (!xhc_parse_bar()) {
        return 0;
    }

    /* Can't dereference until we're sure we're in VMM context */
    char *mmio
        = (char *)xue_map_hpa(g_xhc.mmio_hpa, g_xhc.mmio_len, XUE_MEM_UC);

    if (!mmio) {
        return 0;
    }

    g_xhc.mmio = mmio;
    // xhc_dump_xcap_list();
    done = 1;

    return 1;
}

void xue_init(void)
{
    if (!xhc_init()) {
        printf("xhc_init failed!\n");
        return;
    }

    if (!dbc_init()) {
        printf("dbc_init failed!\n");
    }
}

void xue_disable(void)
{
    dbc_disable();
}

void xue_dump(void)
{
    dbc_dump();
}

void xue_write(const char *data, unsigned int size)
{
    dbc_write(data, size);
}

void xue_ack(void)
{
    dbc_ack();
}
