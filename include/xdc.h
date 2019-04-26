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

#ifndef XUE_XDC_H
#define XUE_XDC_H

#pragma pack(push, 1)

struct xdc_regs {
    unsigned int id;             // base + 0x0
    unsigned int db;             // base + 0x4
    unsigned int erstsz;         // base + 0x8
    unsigned int rsvdz;
    unsigned long long erstba;   // base + 0x10
    unsigned long long erdp;     // base + 0x18
    unsigned int ctrl;           // base + 0x20
    unsigned int st;             // base + 0x24
    unsigned int portsc;         // base + 0x28
    unsigned int rsvdp;
    unsigned long long cp;       // base + 0x30
    unsigned int ddi1;           // base + 0x38
    unsigned int ddi2;           // base + 0x3C
};

extern struct xdc {
    struct xdc_regs *regs;
} g_xdc;

#pragma pack(pop)

#endif
