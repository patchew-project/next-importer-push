/* Support for generating ACPI tables and passing them to Guests
 *
 * Copyright (C) 2008-2010  Kevin O'Connor <kevin@koconnor.net>
 * Copyright (C) 2006 Fabrice Bellard
 * Copyright (C) 2013 Red Hat Inc
 *
 * Author: Michael S. Tsirkin <mst@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License along
 * with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "qemu/cutils.h"
#include "qapi/error.h"

#include "exec/memory.h"
#include "hw/acpi/acpi.h"
#include "hw/acpi/aml-build.h"
#include "hw/acpi/bios-linker-loader.h"
#include "hw/acpi/generic_event_device.h"
#include "hw/acpi/utils.h"
#include "hw/boards.h"
#include "hw/i386/fw_cfg.h"
#include "hw/i386/microvm.h"
#include "hw/pci/pci.h"
#include "hw/pci/pcie_host.h"
#include "hw/virtio/virtio-mmio.h"

#include "acpi-common.h"
#include "acpi-microvm.h"

static void acpi_dsdt_add_virtio(Aml *scope,
                                 MicrovmMachineState *mms)
{
    gchar *separator;
    long int index;
    BusState *bus;
    BusChild *kid;

    bus = sysbus_get_default();
    QTAILQ_FOREACH(kid, &bus->children, sibling) {
        DeviceState *dev = kid->child;
        Object *obj = object_dynamic_cast(OBJECT(dev), TYPE_VIRTIO_MMIO);

        if (obj) {
            VirtIOMMIOProxy *mmio = VIRTIO_MMIO(obj);
            VirtioBusState *mmio_virtio_bus = &mmio->bus;
            BusState *mmio_bus = &mmio_virtio_bus->parent_obj;

            if (QTAILQ_EMPTY(&mmio_bus->children)) {
                continue;
            }
            separator = g_strrstr(mmio_bus->name, ".");
            if (!separator) {
                continue;
            }
            if (qemu_strtol(separator + 1, NULL, 10, &index) != 0) {
                continue;
            }

            uint32_t irq = mms->virtio_irq_base + index;
            hwaddr base = VIRTIO_MMIO_BASE + index * 512;
            hwaddr size = 512;

            Aml *dev = aml_device("VR%02u", (unsigned)index);
            aml_append(dev, aml_name_decl("_HID", aml_string("LNRO0005")));
            aml_append(dev, aml_name_decl("_UID", aml_int(index)));
            aml_append(dev, aml_name_decl("_CCA", aml_int(1)));

            Aml *crs = aml_resource_template();
            aml_append(crs, aml_memory32_fixed(base, size, AML_READ_WRITE));
            aml_append(crs,
                       aml_interrupt(AML_CONSUMER, AML_LEVEL, AML_ACTIVE_HIGH,
                                     AML_EXCLUSIVE, &irq, 1));
            aml_append(dev, aml_name_decl("_CRS", crs));
            aml_append(scope, dev);
        }
    }
}

static void acpi_dsdt_add_pci(Aml *scope, MicrovmMachineState *mms)
{
    Aml *method, *crs, *ifctx, *UUID, *ifctx1, *elsectx, *buf;
    int i, slot_no;
    hwaddr base_mmio = PCIE_MMIO_BASE;
    hwaddr size_mmio = PCIE_MMIO_SIZE;
    hwaddr base_ecam = PCIE_ECAM_BASE;
    hwaddr size_ecam = PCIE_ECAM_SIZE;
    int nr_pcie_buses = size_ecam / PCIE_MMCFG_SIZE_MIN;

    if (mms->pcie != ON_OFF_AUTO_ON) {
        return;
    }

    Aml *dev = aml_device("%s", "PCI0");
    aml_append(dev, aml_name_decl("_HID", aml_string("PNP0A08")));
    aml_append(dev, aml_name_decl("_CID", aml_string("PNP0A03")));
    aml_append(dev, aml_name_decl("_SEG", aml_int(0)));
    aml_append(dev, aml_name_decl("_BBN", aml_int(0)));
    aml_append(dev, aml_name_decl("_UID", aml_int(0)));
    aml_append(dev, aml_name_decl("_STR", aml_unicode("PCIe 0 Device")));
    aml_append(dev, aml_name_decl("_CCA", aml_int(1)));

    /* Declare the PCI Routing Table. */
    Aml *rt_pkg = aml_varpackage(PCI_SLOT_MAX * PCI_NUM_PINS);
    for (slot_no = 0; slot_no < PCI_SLOT_MAX; slot_no++) {
        for (i = 0; i < PCI_NUM_PINS; i++) {
            int gsi = (i + slot_no) % PCI_NUM_PINS;
            Aml *pkg = aml_package(4);
            aml_append(pkg, aml_int((slot_no << 16) | 0xFFFF));
            aml_append(pkg, aml_int(i));
            aml_append(pkg, aml_name("GSI%d", gsi));
            aml_append(pkg, aml_int(0));
            aml_append(rt_pkg, pkg);
        }
    }
    aml_append(dev, aml_name_decl("_PRT", rt_pkg));

    /* Create GSI link device */
    for (i = 0; i < PCI_NUM_PINS; i++) {
        uint32_t irqs =  PCIE_IRQ_BASE + i;
        Aml *dev_gsi = aml_device("GSI%d", i);
        aml_append(dev_gsi, aml_name_decl("_HID", aml_string("PNP0C0F")));
        aml_append(dev_gsi, aml_name_decl("_UID", aml_int(i)));
        crs = aml_resource_template();
        aml_append(crs,
                   aml_interrupt(AML_CONSUMER, AML_LEVEL, AML_ACTIVE_HIGH,
                                 AML_EXCLUSIVE, &irqs, 1));
        aml_append(dev_gsi, aml_name_decl("_PRS", crs));
        crs = aml_resource_template();
        aml_append(crs,
                   aml_interrupt(AML_CONSUMER, AML_LEVEL, AML_ACTIVE_HIGH,
                                 AML_EXCLUSIVE, &irqs, 1));
        aml_append(dev_gsi, aml_name_decl("_CRS", crs));
        method = aml_method("_SRS", 1, AML_NOTSERIALIZED);
        aml_append(dev_gsi, method);
        aml_append(dev, dev_gsi);
    }

    method = aml_method("_CBA", 0, AML_NOTSERIALIZED);
    aml_append(method, aml_return(aml_int(base_ecam)));
    aml_append(dev, method);

    method = aml_method("_CRS", 0, AML_NOTSERIALIZED);
    Aml *rbuf = aml_resource_template();
    aml_append(rbuf,
        aml_word_bus_number(AML_MIN_FIXED, AML_MAX_FIXED, AML_POS_DECODE,
                            0x0000, 0x0000, nr_pcie_buses - 1, 0x0000,
                            nr_pcie_buses));
    aml_append(rbuf,
        aml_dword_memory(AML_POS_DECODE, AML_MIN_FIXED, AML_MAX_FIXED,
                         AML_NON_CACHEABLE, AML_READ_WRITE, 0x0000, base_mmio,
                         base_mmio + size_mmio - 1, 0x0000, size_mmio));

    aml_append(method, aml_return(rbuf));
    aml_append(dev, method);

    /* Declare an _OSC (OS Control Handoff) method */
    aml_append(dev, aml_name_decl("SUPP", aml_int(0)));
    aml_append(dev, aml_name_decl("CTRL", aml_int(0)));
    method = aml_method("_OSC", 4, AML_NOTSERIALIZED);
    aml_append(method,
        aml_create_dword_field(aml_arg(3), aml_int(0), "CDW1"));

    /* PCI Firmware Specification 3.0
     * 4.5.1. _OSC Interface for PCI Host Bridge Devices
     * The _OSC interface for a PCI/PCI-X/PCI Express hierarchy is
     * identified by the Universal Unique IDentifier (UUID)
     * 33DB4D5B-1FF7-401C-9657-7441C03DD766
     */
    UUID = aml_touuid("33DB4D5B-1FF7-401C-9657-7441C03DD766");
    ifctx = aml_if(aml_equal(aml_arg(0), UUID));
    aml_append(ifctx,
        aml_create_dword_field(aml_arg(3), aml_int(4), "CDW2"));
    aml_append(ifctx,
        aml_create_dword_field(aml_arg(3), aml_int(8), "CDW3"));
    aml_append(ifctx, aml_store(aml_name("CDW2"), aml_name("SUPP")));
    aml_append(ifctx, aml_store(aml_name("CDW3"), aml_name("CTRL")));

    /*
     * Allow OS control for all 5 features:
     * PCIeHotplug SHPCHotplug PME AER PCIeCapability.
     */
    aml_append(ifctx, aml_and(aml_name("CTRL"), aml_int(0x1F),
                              aml_name("CTRL")));

    ifctx1 = aml_if(aml_lnot(aml_equal(aml_arg(1), aml_int(0x1))));
    aml_append(ifctx1, aml_or(aml_name("CDW1"), aml_int(0x08),
                              aml_name("CDW1")));
    aml_append(ifctx, ifctx1);

    ifctx1 = aml_if(aml_lnot(aml_equal(aml_name("CDW3"), aml_name("CTRL"))));
    aml_append(ifctx1, aml_or(aml_name("CDW1"), aml_int(0x10),
                              aml_name("CDW1")));
    aml_append(ifctx, ifctx1);

    aml_append(ifctx, aml_store(aml_name("CTRL"), aml_name("CDW3")));
    aml_append(ifctx, aml_return(aml_arg(3)));
    aml_append(method, ifctx);

    elsectx = aml_else();
    aml_append(elsectx, aml_or(aml_name("CDW1"), aml_int(4),
                               aml_name("CDW1")));
    aml_append(elsectx, aml_return(aml_arg(3)));
    aml_append(method, elsectx);
    aml_append(dev, method);

    method = aml_method("_DSM", 4, AML_NOTSERIALIZED);

    /* PCI Firmware Specification 3.0
     * 4.6.1. _DSM for PCI Express Slot Information
     * The UUID in _DSM in this context is
     * {E5C937D0-3553-4D7A-9117-EA4D19C3434D}
     */
    UUID = aml_touuid("E5C937D0-3553-4D7A-9117-EA4D19C3434D");
    ifctx = aml_if(aml_equal(aml_arg(0), UUID));
    ifctx1 = aml_if(aml_equal(aml_arg(2), aml_int(0)));
    uint8_t byte_list[1] = {1};
    buf = aml_buffer(1, byte_list);
    aml_append(ifctx1, aml_return(buf));
    aml_append(ifctx, ifctx1);
    aml_append(method, ifctx);

    byte_list[0] = 0;
    buf = aml_buffer(1, byte_list);
    aml_append(method, aml_return(buf));
    aml_append(dev, method);

    Aml *dev_res0 = aml_device("%s", "RES0");
    aml_append(dev_res0, aml_name_decl("_HID", aml_string("PNP0C02")));
    crs = aml_resource_template();
    aml_append(crs,
        aml_qword_memory(AML_POS_DECODE, AML_MIN_FIXED, AML_MAX_FIXED,
                         AML_NON_CACHEABLE, AML_READ_WRITE, 0x0000, base_ecam,
                         base_ecam + size_ecam - 1, 0x0000, size_ecam));
    aml_append(dev_res0, aml_name_decl("_CRS", crs));
    aml_append(dev, dev_res0);
    aml_append(scope, dev);
}

static void
build_dsdt_microvm(GArray *table_data, BIOSLinker *linker,
                   MicrovmMachineState *mms)
{
    X86MachineState *x86ms = X86_MACHINE(mms);
    Aml *dsdt, *sb_scope, *scope, *pkg;
    bool ambiguous;
    Object *isabus;

    isabus = object_resolve_path_type("", TYPE_ISA_BUS, &ambiguous);
    assert(isabus);
    assert(!ambiguous);

    dsdt = init_aml_allocator();

    /* Reserve space for header */
    acpi_data_push(dsdt->buf, sizeof(AcpiTableHeader));

    sb_scope = aml_scope("_SB");
    fw_cfg_add_acpi_dsdt(sb_scope, x86ms->fw_cfg);
    isa_build_aml(ISA_BUS(isabus), sb_scope);
    build_ged_aml(sb_scope, GED_DEVICE, x86ms->acpi_dev,
                  GED_MMIO_IRQ, AML_SYSTEM_MEMORY, GED_MMIO_BASE);
    acpi_dsdt_add_power_button(sb_scope);
    acpi_dsdt_add_virtio(sb_scope, mms);
    acpi_dsdt_add_pci(sb_scope, mms);
    aml_append(dsdt, sb_scope);

    /* ACPI 5.0: Table 7-209 System State Package */
    scope = aml_scope("\\");
    pkg = aml_package(4);
    aml_append(pkg, aml_int(ACPI_GED_SLP_TYP_S5));
    aml_append(pkg, aml_int(0)); /* ignored */
    aml_append(pkg, aml_int(0)); /* reserved */
    aml_append(pkg, aml_int(0)); /* reserved */
    aml_append(scope, aml_name_decl("_S5", pkg));
    aml_append(dsdt, scope);

    /* copy AML table into ACPI tables blob and patch header there */
    g_array_append_vals(table_data, dsdt->buf->data, dsdt->buf->len);
    build_header(linker, table_data,
        (void *)(table_data->data + table_data->len - dsdt->buf->len),
        "DSDT", dsdt->buf->len, 2, NULL, NULL);
    free_aml_allocator();
}

static void acpi_build_microvm(AcpiBuildTables *tables,
                               MicrovmMachineState *mms)
{
    MachineState *machine = MACHINE(mms);
    X86MachineState *x86ms = X86_MACHINE(mms);
    GArray *table_offsets;
    GArray *tables_blob = tables->table_data;
    unsigned dsdt, xsdt;
    AcpiFadtData pmfadt = {
        /* ACPI 5.0: 4.1 Hardware-Reduced ACPI */
        .rev = 5,
        .flags = ((1 << ACPI_FADT_F_HW_REDUCED_ACPI) |
                  (1 << ACPI_FADT_F_RESET_REG_SUP)),

        /* ACPI 5.0: 4.8.3.7 Sleep Control and Status Registers */
        .sleep_ctl = {
            .space_id = AML_AS_SYSTEM_MEMORY,
            .bit_width = 8,
            .address = GED_MMIO_BASE_REGS + ACPI_GED_REG_SLEEP_CTL,
        },
        .sleep_sts = {
            .space_id = AML_AS_SYSTEM_MEMORY,
            .bit_width = 8,
            .address = GED_MMIO_BASE_REGS + ACPI_GED_REG_SLEEP_STS,
        },

        /* ACPI 5.0: 4.8.3.6 Reset Register */
        .reset_reg = {
            .space_id = AML_AS_SYSTEM_MEMORY,
            .bit_width = 8,
            .address = GED_MMIO_BASE_REGS + ACPI_GED_REG_RESET,
        },
        .reset_val = ACPI_GED_RESET_VALUE,
    };

    table_offsets = g_array_new(false, true /* clear */,
                                        sizeof(uint32_t));
    bios_linker_loader_alloc(tables->linker,
                             ACPI_BUILD_TABLE_FILE, tables_blob,
                             64 /* Ensure FACS is aligned */,
                             false /* high memory */);

    dsdt = tables_blob->len;
    build_dsdt_microvm(tables_blob, tables->linker, mms);

    pmfadt.dsdt_tbl_offset = &dsdt;
    pmfadt.xdsdt_tbl_offset = &dsdt;
    acpi_add_table(table_offsets, tables_blob);
    build_fadt(tables_blob, tables->linker, &pmfadt, NULL, NULL);

    acpi_add_table(table_offsets, tables_blob);
    acpi_build_madt(tables_blob, tables->linker, X86_MACHINE(machine),
                    ACPI_DEVICE_IF(x86ms->acpi_dev), false);

    xsdt = tables_blob->len;
    build_xsdt(tables_blob, tables->linker, table_offsets, NULL, NULL);

    /* RSDP is in FSEG memory, so allocate it separately */
    {
        AcpiRsdpData rsdp_data = {
            /* ACPI 2.0: 5.2.4.3 RSDP Structure */
            .revision = 2, /* xsdt needs v2 */
            .oem_id = ACPI_BUILD_APPNAME6,
            .xsdt_tbl_offset = &xsdt,
            .rsdt_tbl_offset = NULL,
        };
        build_rsdp(tables->rsdp, tables->linker, &rsdp_data);
    }

    /* Cleanup memory that's no longer used. */
    g_array_free(table_offsets, true);
}

static void acpi_build_no_update(void *build_opaque)
{
    /* nothing, microvm tables don't change at runtime */
}

void acpi_setup_microvm(MicrovmMachineState *mms)
{
    X86MachineState *x86ms = X86_MACHINE(mms);
    AcpiBuildTables tables;

    assert(x86ms->fw_cfg);

    if (!x86_machine_is_acpi_enabled(x86ms)) {
        return;
    }

    acpi_build_tables_init(&tables);
    acpi_build_microvm(&tables, mms);

    /* Now expose it all to Guest */
    acpi_add_rom_blob(acpi_build_no_update, NULL,
                      tables.table_data,
                      ACPI_BUILD_TABLE_FILE,
                      ACPI_BUILD_TABLE_MAX_SIZE);
    acpi_add_rom_blob(acpi_build_no_update, NULL,
                      tables.linker->cmd_blob,
                      "etc/table-loader", 0);
    acpi_add_rom_blob(acpi_build_no_update, NULL,
                      tables.rsdp,
                      ACPI_BUILD_RSDP_FILE, 0);

    acpi_build_tables_cleanup(&tables, false);
}
