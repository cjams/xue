;
; Copyright (C) 2019 Assured Information Security, Inc.
;
; Permission is hereby granted, free of charge, to any person obtaining a copy
; of this software and associated documentation files (the "Software"), to deal
; in the Software without restriction, including without limitation the rights
; to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
; copies of the Software, and to permit persons to whom the Software is
; furnished to do so, subject to the following conditions:
;
; The above copyright notice and this permission notice shall be included in all
; copies or substantial portions of the Software.
;
; THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
; IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
; FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
; AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
; LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
; OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
; SOFTWARE.

bits 64
default rel

section .text

global xue_inb
xue_inb:
    xor rax, rax
    mov rdx, rdi
    in al, dx
    ret

global xue_inw
xue_inw:
    xor rax, rax
    mov rdx, rdi
    in ax, dx
    ret

global xue_ind
xue_ind:
    xor rax, rax
    mov rdx, rdi
    in eax, dx
    ret

global xue_outb
xue_outb:
    mov rdx, rdi
    mov rax, rsi
    out dx, al
    xor rax, rax
    ret

global xue_outw
xue_outw:
    mov rdx, rdi
    mov rax, rsi
    out dx, ax
    xor rax, rax
    ret

global xue_outd
xue_outd:
    mov rdx, rdi
    mov rax, rsi
    out dx, eax
    xor rax, rax
    ret
