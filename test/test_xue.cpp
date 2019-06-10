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

#include <array>
#include <catch2/catch.hpp>
#include <cstdio>
#include <unordered_map>
#include <xue.h>

constexpr auto xhc_dev{1UL};
constexpr auto xhc_fun{0UL};
constexpr auto xhc_bdf{(1UL << 31) | (xhc_dev << 11) | (xhc_fun << 8)};
constexpr auto xhc_mmio_size = (1UL << 16);

uint32_t pci_bdf{};
uint32_t pci_reg{};

std::array<uint32_t, 4> known_xhc = {
    (XUE_XHC_DEV_Z370 << 16) | XUE_XHC_VEN_INTEL,
    (XUE_XHC_DEV_Z390 << 16) | XUE_XHC_VEN_INTEL,
    (XUE_XHC_DEV_WILDCAT_POINT << 16) | XUE_XHC_VEN_INTEL,
    (XUE_XHC_DEV_SUNRISE_POINT << 16) | XUE_XHC_VEN_INTEL
};

std::array<uint32_t, 64> xhc_cfg{};
std::array<uint8_t, xhc_mmio_size> xhc_mmio{};

static void outd(uint32_t port, uint32_t data)
{
    if (port == 0xCF8) {
        pci_bdf = data & 0xFFFFFF00;
        pci_reg = (data & 0xFC) >> 2;
        return;
    }

    if (port == 0xCFC) {
        if (pci_bdf != xhc_bdf) {
            return;
        }
        xhc_cfg.at(pci_reg) = data;
    }
}

static uint32_t ind(uint32_t port)
{
    if (port != 0xCFC || pci_bdf != xhc_bdf) {
        return 0;
    }

    return xhc_cfg.at(pci_reg);
}

static void *map_xhc(uint64_t phys, size_t size)
{
    (void)phys;
    (void)size;

    return (void *)xhc_mmio.data();
}

TEST_CASE("xue_open - invalid args")
{
    struct xue xue{};
    struct xue_ops ops{};

    CHECK(xue_open(NULL, NULL) == 0);
    CHECK(xue_open(&xue, NULL) == 0);
    CHECK(xue_open(NULL, &ops) == 0);
}

TEST_CASE("xue_open - init ops")
{
    struct xue xue{};
    struct xue_ops ops{};

    CHECK(xue_open(&xue, &ops) == 0);

    CHECK(xue.ops->alloc_dma == xue_sys_alloc_dma);
    CHECK(xue.ops->free_dma == xue_sys_free_dma);
    CHECK(xue.ops->alloc_pages == xue_sys_alloc_pages);
    CHECK(xue.ops->free_pages == xue_sys_free_pages);
    CHECK(xue.ops->map_xhc == xue_sys_map_xhc);
    CHECK(xue.ops->unmap_xhc == xue_sys_unmap_xhc);
    CHECK(xue.ops->outd == xue_sys_outd);
    CHECK(xue.ops->ind == xue_sys_ind);
    CHECK(xue.ops->virt_to_phys == xue_sys_virt_to_phys);
    CHECK(xue.ops->sfence == xue_sys_sfence);
}

TEST_CASE("xue_init_xhc - not found")
{
    struct xue xue{};
    struct xue_ops ops{};

    ops.ind = +[](uint32_t /*port*/) { return 0U; };
    xue_init_ops(&xue, &ops);

    CHECK(xue_init_xhc(&xue) == 0);
}

TEST_CASE("xue_init_xhc - invalid header")
{
    struct xue xue{};
    struct xue_ops ops{};

    ops.ind = ind;
    ops.outd = outd;
    xue_init_ops(&xue, &ops);

    xhc_cfg.at(3) = 0xFF0000;

    for (auto dev_ven : known_xhc) {
        xhc_cfg.at(0) = dev_ven;
        CHECK(xue_init_xhc(&xue) == 0);
    }
}

TEST_CASE("xue_init_xhc - invalid class code")
{
    struct xue xue{};
    struct xue_ops ops{};

    ops.ind = ind;
    ops.outd = outd;
    xue_init_ops(&xue, &ops);

    xhc_cfg.at(2) = (XUE_XHC_CLASSC << 8) + 1;
    xhc_cfg.at(3) = 0;

    for (auto dev_ven : known_xhc) {
        xhc_cfg.at(0) = dev_ven;
        CHECK(xue_init_xhc(&xue) == 0);
    }
}

TEST_CASE("xue_init_xhc - invalid BAR")
{
    struct xue xue{};
    struct xue_ops ops{};

    ops.ind = ind;
    ops.outd = outd;
    xue_init_ops(&xue, &ops);

    xhc_cfg.at(2) = (XUE_XHC_CLASSC << 8);
    xhc_cfg.at(3) = 0;

    xhc_cfg.at(4) = 1;
    for (auto dev_ven : known_xhc) {
        xhc_cfg.at(0) = dev_ven;
        CHECK(xue_init_xhc(&xue) == 0);
    }

    xhc_cfg.at(4) = 0;
    for (auto dev_ven : known_xhc) {
        xhc_cfg.at(0) = dev_ven;
        CHECK(xue_init_xhc(&xue) == 0);
    }
}

TEST_CASE("xue_init_xhc - success")
{
    struct xue xue{};
    struct xue_ops ops{};

    ops.ind = ind;
    ops.outd = outd;
    ops.map_xhc = map_xhc;

    xue_init_ops(&xue, &ops);

    xhc_cfg.at(2) = (XUE_XHC_CLASSC << 8);
    xhc_cfg.at(3) = 0;
    xhc_cfg.at(4) = 4;

    for (auto dev_ven : known_xhc) {
        xhc_cfg.at(0) = dev_ven;
        CHECK(xue_init_xhc(&xue) != 0);
    }
}

TEST_CASE("xue_mset")
{
    std::array<uint8_t, 16> a{};
    xue_mset(a.data(), 42, a.size());

    for (auto c : a) {
        CHECK(c == 42);
    }
}

TEST_CASE("xue_mcpy")
{
    std::array<uint8_t, 16> a{};
    std::array<uint8_t, 16> b{};

    for (auto &c : a) {
        c = 42;
    }

    for (auto c : b) {
        CHECK(c == 0);
    }

    xue_mcpy(b.data(), a.data(), b.size());

    for (auto c : b) {
        CHECK(c == 42);
    }
}
