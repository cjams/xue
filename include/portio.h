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

#ifndef XUE_PORTIO_H
#define XUE_PORTIO_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

uint8_t _inb(uint16_t port);
uint16_t _inw(uint16_t port);
uint32_t _ind(uint16_t port);

void _insb(uint16_t port, uint64_t m8);
void _insw(uint16_t port, uint64_t m16);
void _insd(uint16_t port, uint64_t m32);

void _insbrep(uint16_t port, uint64_t m8, uint32_t count);
void _inswrep(uint16_t port, uint64_t m16, uint32_t count);
void _insdrep(uint16_t port, uint64_t m32, uint32_t count);

void _outb(uint16_t port, uint8_t val);
void _outw(uint16_t port, uint16_t val);
void _outd(uint16_t port, uint32_t val);

void _outsb(uint16_t port, uint64_t m8);
void _outsw(uint16_t port, uint64_t m16);
void _outsd(uint16_t port, uint64_t m32);

void _outsbrep(uint16_t port, uint64_t m8, uint32_t count);
void _outswrep(uint16_t port, uint64_t m16, uint32_t count);
void _outsdrep(uint16_t port, uint64_t m32, uint32_t count);

#ifdef __cplusplus
}
#endif
#endif
