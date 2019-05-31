#!/usr/bin/python

#
# Copyright (C) 2019 Assured Information Security, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import usb.core

DBC_VEND = 0x3495
DBC_PROD = 0x00E0
DBC_IFACE = 0x00
DBC_EP_IN = 0x81
DBC_READ_SIZE = 0x40

# Find the DbC device
dbc = usb.core.find(idVendor=DBC_VEND, idProduct=DBC_PROD)
if dbc is None:
    raise ValueError('DbC not found')

# Unbind any kernel driver if necessary
#if dbc.is_kernel_driver_active(DBC_IFACE):
#    dbc.detach_kernel_driver(DBC_IFACE)

# Set the configuration
dbc.set_configuration()

# Read from the DbC
while 1:
    try:
        data = dbc.read(DBC_EP_IN, DBC_READ_SIZE)
        for c in data:
            print(chr(c), end="")
    except usb.core.USBError:
        pass