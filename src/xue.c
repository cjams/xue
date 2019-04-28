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

#include <sys.h>
#include <xdc.h>
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

void xue_init(void)
{
    if (!xhc_find()) {
        return;
    }

    if (!xhc_parse_bar()) {
        return;
    }

    /* Can't dereference until we're sure we're in VMM context */
    char *virt
        = (char *)xue_map_hpa(g_xhc.mmio_hpa, g_xhc.mmio_len, XUE_MEM_UC);
    if (!virt) {
        return;
    }

    g_xhc.mmio = virt;
    xhc_dump_hccparams1();

    g_xdc.regs = xhc_find_xdc_regs();
}
