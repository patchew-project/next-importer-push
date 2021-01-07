/*
 * VT82C686B south bridge support
 *
 * Copyright (c) 2008 yajin (yajin@vm-kernel.org)
 * Copyright (c) 2009 chenming (chenming@rdc.faw.com.cn)
 * Copyright (c) 2010 Huacai Chen (zltjiangshi@gmail.com)
 * This code is licensed under the GNU GPL v2.
 *
 * Contributions after 2012-01-13 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#include "qemu/osdep.h"
#include "hw/isa/vt82c686.h"
#include "hw/pci/pci.h"
#include "hw/qdev-properties.h"
#include "hw/isa/isa.h"
#include "hw/isa/superio.h"
#include "hw/intc/i8259.h"
#include "hw/irq.h"
#include "hw/dma/i8257.h"
#include "hw/timer/i8254.h"
#include "hw/rtc/mc146818rtc.h"
#include "migration/vmstate.h"
#include "hw/isa/apm.h"
#include "hw/acpi/acpi.h"
#include "hw/i2c/pm_smbus.h"
#include "qapi/error.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "qemu/range.h"
#include "qemu/timer.h"
#include "exec/address-spaces.h"
#include "trace.h"

#define TYPE_VIA_PM "via-pm"
OBJECT_DECLARE_SIMPLE_TYPE(ViaPMState, VIA_PM)

struct ViaPMState {
    PCIDevice dev;
    MemoryRegion io;
    ACPIREGS ar;
    APMState apm;
    PMSMBus smb;
};

static void pm_io_space_update(ViaPMState *s)
{
    uint32_t pmbase = pci_get_long(s->dev.config + 0x48) & 0xff80UL;

    memory_region_transaction_begin();
    memory_region_set_address(&s->io, pmbase);
    memory_region_set_enabled(&s->io, s->dev.config[0x41] & BIT(7));
    memory_region_transaction_commit();
}

static void smb_io_space_update(ViaPMState *s)
{
    uint32_t smbase = pci_get_long(s->dev.config + 0x90) & 0xfff0UL;

    memory_region_transaction_begin();
    memory_region_set_address(&s->smb.io, smbase);
    memory_region_set_enabled(&s->smb.io, s->dev.config[0xd2] & BIT(0));
    memory_region_transaction_commit();
}

static int vmstate_acpi_post_load(void *opaque, int version_id)
{
    ViaPMState *s = opaque;

    pm_io_space_update(s);
    smb_io_space_update(s);
    return 0;
}

static const VMStateDescription vmstate_acpi = {
    .name = "vt82c686b_pm",
    .version_id = 1,
    .minimum_version_id = 1,
    .post_load = vmstate_acpi_post_load,
    .fields = (VMStateField[]) {
        VMSTATE_PCI_DEVICE(dev, ViaPMState),
        VMSTATE_UINT16(ar.pm1.evt.sts, ViaPMState),
        VMSTATE_UINT16(ar.pm1.evt.en, ViaPMState),
        VMSTATE_UINT16(ar.pm1.cnt.cnt, ViaPMState),
        VMSTATE_STRUCT(apm, ViaPMState, 0, vmstate_apm, APMState),
        VMSTATE_TIMER_PTR(ar.tmr.timer, ViaPMState),
        VMSTATE_INT64(ar.tmr.overflow_time, ViaPMState),
        VMSTATE_END_OF_LIST()
    }
};

static void pm_write_config(PCIDevice *d, uint32_t addr, uint32_t val, int len)
{
    ViaPMState *s = VIA_PM(d);

    trace_via_pm_write(addr, val, len);
    pci_default_write_config(d, addr, val, len);
    if (ranges_overlap(addr, len, 0x48, 4)) {
        uint32_t v = pci_get_long(s->dev.config + 0x48);
        pci_set_long(s->dev.config + 0x48, (v & 0xff80UL) | 1);
    }
    if (range_covers_byte(addr, len, 0x41)) {
        pm_io_space_update(s);
    }
    if (ranges_overlap(addr, len, 0x90, 4)) {
        uint32_t v = pci_get_long(s->dev.config + 0x90);
        pci_set_long(s->dev.config + 0x90, (v & 0xfff0UL) | 1);
    }
    if (range_covers_byte(addr, len, 0xd2)) {
        s->dev.config[0xd2] &= 0xf;
        smb_io_space_update(s);
    }
}

static void pm_io_write(void *op, hwaddr addr, uint64_t data, unsigned size)
{
    trace_via_pm_io_write(addr, data, size);
}

static uint64_t pm_io_read(void *op, hwaddr addr, unsigned size)
{
    trace_via_pm_io_read(addr, 0, size);
    return 0;
}

static const MemoryRegionOps pm_io_ops = {
    .read = pm_io_read,
    .write = pm_io_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .impl = {
        .min_access_size = 1,
        .max_access_size = 1,
    },
};

static void pm_update_sci(ViaPMState *s)
{
    int sci_level, pmsts;

    pmsts = acpi_pm1_evt_get_sts(&s->ar);
    sci_level = (((pmsts & s->ar.pm1.evt.en) &
                  (ACPI_BITMASK_RT_CLOCK_ENABLE |
                   ACPI_BITMASK_POWER_BUTTON_ENABLE |
                   ACPI_BITMASK_GLOBAL_LOCK_ENABLE |
                   ACPI_BITMASK_TIMER_ENABLE)) != 0);
    pci_set_irq(&s->dev, sci_level);
    /* schedule a timer interruption if needed */
    acpi_pm_tmr_update(&s->ar, (s->ar.pm1.evt.en & ACPI_BITMASK_TIMER_ENABLE) &&
                       !(pmsts & ACPI_BITMASK_TIMER_STATUS));
}

static void pm_tmr_timer(ACPIREGS *ar)
{
    ViaPMState *s = container_of(ar, ViaPMState, ar);
    pm_update_sci(s);
}

static void via_pm_reset(DeviceState *d)
{
    ViaPMState *s = VIA_PM(d);

    memset(s->dev.config + PCI_CONFIG_HEADER_SIZE, 0,
           PCI_CONFIG_SPACE_SIZE - PCI_CONFIG_HEADER_SIZE);
    /* Power Management IO base */
    pci_set_long(s->dev.config + 0x48, 1);
    /* SMBus IO base */
    pci_set_long(s->dev.config + 0x90, 1);

    pm_io_space_update(s);
    smb_io_space_update(s);
}

static void via_pm_realize(PCIDevice *dev, Error **errp)
{
    ViaPMState *s = VIA_PM(dev);

    pci_set_word(dev->config + PCI_STATUS, PCI_STATUS_FAST_BACK |
                 PCI_STATUS_DEVSEL_MEDIUM);

    pm_smbus_init(DEVICE(s), &s->smb, false);
    memory_region_add_subregion(pci_address_space_io(dev), 0, &s->smb.io);
    memory_region_set_enabled(&s->smb.io, false);

    apm_init(dev, &s->apm, NULL, s);

    memory_region_init_io(&s->io, OBJECT(dev), &pm_io_ops, s, "via-pm", 0x100);
    memory_region_add_subregion(pci_address_space_io(dev), 0, &s->io);
    memory_region_set_enabled(&s->io, false);

    acpi_pm_tmr_init(&s->ar, pm_tmr_timer, &s->io);
    acpi_pm1_evt_init(&s->ar, pm_tmr_timer, &s->io);
    acpi_pm1_cnt_init(&s->ar, &s->io, false, false, 2);
}

typedef struct via_pm_init_info {
    uint16_t device_id;
} ViaPMInitInfo;

static void via_pm_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);
    ViaPMInitInfo *info = data;

    k->realize = via_pm_realize;
    k->config_write = pm_write_config;
    k->vendor_id = PCI_VENDOR_ID_VIA;
    k->device_id = info->device_id;
    k->class_id = PCI_CLASS_BRIDGE_OTHER;
    k->revision = 0x40;
    dc->reset = via_pm_reset;
    /* Reason: part of VIA south bridge, does not exist stand alone */
    dc->user_creatable = false;
    dc->vmsd = &vmstate_acpi;
}

static const TypeInfo via_pm_info = {
    .name          = TYPE_VIA_PM,
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(ViaPMState),
    .abstract      = true,
    .interfaces = (InterfaceInfo[]) {
        { INTERFACE_CONVENTIONAL_PCI_DEVICE },
        { },
    },
};

static const ViaPMInitInfo vt82c686b_pm_init_info = {
    .device_id = PCI_DEVICE_ID_VIA_ACPI,
};

static const TypeInfo vt82c686b_pm_info = {
    .name          = TYPE_VT82C686B_PM,
    .parent        = TYPE_VIA_PM,
    .class_init    = via_pm_class_init,
    .class_data    = (void *)&vt82c686b_pm_init_info,
};

static const ViaPMInitInfo vt8231_pm_init_info = {
    .device_id = 0x8235,
};

static const TypeInfo vt8231_pm_info = {
    .name          = TYPE_VT8231_PM,
    .parent        = TYPE_VIA_PM,
    .class_init    = via_pm_class_init,
    .class_data    = (void *)&vt8231_pm_init_info,
};


#define TYPE_VIA_SUPERIO "via-superio"
OBJECT_DECLARE_SIMPLE_TYPE(ViaSuperIOState, VIA_SUPERIO)

struct ViaSuperIOState {
    ISASuperIODevice superio;
    uint8_t regs[0x100];
    const MemoryRegionOps *io_ops;
    MemoryRegion io;
    MemoryRegion *serial_io[SUPERIO_MAX_SERIAL_PORTS];
};

static inline void via_superio_io_enable(ViaSuperIOState *s, bool enable)
{
    memory_region_set_enabled(&s->io, enable);
}

static MemoryRegion *find_subregion(ISADevice *d, MemoryRegion *parent,
                                    int offs)
{
    MemoryRegion *subregion, *mr = NULL;

    QTAILQ_FOREACH(subregion, &parent->subregions, subregions_link) {
        if (subregion->addr == offs) {
            mr = subregion;
            break;
        }
    }
    return mr;
}

static void via_superio_realize(DeviceState *d, Error **errp)
{
    ViaSuperIOState *s = VIA_SUPERIO(d);
    ISASuperIOClass *ic = ISA_SUPERIO_GET_CLASS(s);
    int i;

    assert(s->io_ops);
    ic->parent_realize(d, errp);
    if (*errp) {
        return;
    }
    /* Grab io regions of serial devices so we can control them */
    for (i = 0; i < ic->serial.count; i++) {
        ISADevice *sd = s->superio.serial[i];
        MemoryRegion *io = isa_address_space_io(sd);
        MemoryRegion *mr = find_subregion(sd, io, sd->ioport_id);
        if (!mr) {
            error_setg(errp, "Could not get io region for serial %d", i);
            return;
        }
        s->serial_io[i] = mr;
    }

    memory_region_init_io(&s->io, OBJECT(d), s->io_ops, s, "via-superio", 2);
    memory_region_set_enabled(&s->io, false);
    /* The floppy also uses 0x3f0 and 0x3f1 but this seems to work anyway */
    memory_region_add_subregion(isa_address_space_io(ISA_DEVICE(s)), 0x3f0,
                                &s->io);
}

static uint64_t via_superio_cfg_read(void *opaque, hwaddr addr, unsigned size)
{
    ViaSuperIOState *sc = opaque;
    uint8_t idx = sc->regs[0];
    uint8_t val = sc->regs[idx];

    if (addr == 0) {
        return idx;
    }
    if (addr == 1 && idx == 0) {
        val = 0; /* reading reg 0 where we store index value */
    }
    trace_via_superio_read(idx, val);
    return val;
}

static void via_superio_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    ISASuperIOClass *sc = ISA_SUPERIO_CLASS(klass);

    sc->parent_realize = dc->realize;
    dc->realize = via_superio_realize;
}

static const TypeInfo via_superio_info = {
    .name          = TYPE_VIA_SUPERIO,
    .parent        = TYPE_ISA_SUPERIO,
    .instance_size = sizeof(ViaSuperIOState),
    .class_size    = sizeof(ISASuperIOClass),
    .class_init    = via_superio_class_init,
    .abstract      = true,
};

#define TYPE_VT82C686B_SUPERIO "vt82c686b-superio"

static void vt82c686b_superio_cfg_write(void *opaque, hwaddr addr,
                                        uint64_t data, unsigned size)
{
    ViaSuperIOState *sc = opaque;
    uint8_t idx = sc->regs[0];

    if (addr == 0) { /* config index register */
        sc->regs[0] = data;
        return;
    }

    /* config data register */
    trace_via_superio_write(idx, data);
    switch (idx) {
    case 0x00 ... 0xdf:
    case 0xe4:
    case 0xe5:
    case 0xe9 ... 0xed:
    case 0xf3:
    case 0xf5:
    case 0xf7:
    case 0xf9 ... 0xfb:
    case 0xfd ... 0xff:
        /* ignore write to read only registers */
        return;
    case 0xe2: /* Function select */
    {
        data &= 0x1f;
        if (data & BIT(2)) { /* Serial port 1 enable */
            ISADevice *dev = sc->superio.serial[0];
            if (!memory_region_is_mapped(sc->serial_io[0])) {
                memory_region_add_subregion(isa_address_space_io(dev),
                                            dev->ioport_id, sc->serial_io[0]);
            }
        } else {
            MemoryRegion *io = isa_address_space_io(sc->superio.serial[0]);
            if (memory_region_is_mapped(sc->serial_io[0])) {
                memory_region_del_subregion(io, sc->serial_io[0]);
            }
        }
        if (data & BIT(3)) { /* Serial port 2 enable */
            ISADevice *dev = sc->superio.serial[1];
            if (!memory_region_is_mapped(sc->serial_io[1])) {
                memory_region_add_subregion(isa_address_space_io(dev),
                                            dev->ioport_id, sc->serial_io[1]);
            }
        } else {
            MemoryRegion *io = isa_address_space_io(sc->superio.serial[1]);
            if (memory_region_is_mapped(sc->serial_io[1])) {
                memory_region_del_subregion(io, sc->serial_io[1]);
            }
        }
        break;
    }
    case 0xe7: /* Serial port 1 io base address */
    {
        data &= 0xfe;
        sc->superio.serial[0]->ioport_id = data << 2;
        if (memory_region_is_mapped(sc->serial_io[0])) {
            memory_region_set_address(sc->serial_io[0], data << 2);
        }
        break;
    }
    case 0xe8: /* Serial port 2 io base address */
    {
        data &= 0xfe;
        sc->superio.serial[1]->ioport_id = data << 2;
        if (memory_region_is_mapped(sc->serial_io[1])) {
            memory_region_set_address(sc->serial_io[1], data << 2);
        }
        break;
    }
    default:
        qemu_log_mask(LOG_UNIMP,
                      "via_superio_cfg: unimplemented register 0x%x\n", idx);
        break;
    }
    sc->regs[idx] = data;
}

static const MemoryRegionOps vt82c686b_superio_cfg_ops = {
    .read = via_superio_cfg_read,
    .write = vt82c686b_superio_cfg_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .impl = {
        .min_access_size = 1,
        .max_access_size = 1,
    },
};

static void vt82c686b_superio_reset(DeviceState *dev)
{
    ViaSuperIOState *s = VIA_SUPERIO(dev);

    memset(s->regs, 0, sizeof(s->regs));
    /* Device ID */
    vt82c686b_superio_cfg_write(s, 0, 0xe0, 1);
    vt82c686b_superio_cfg_write(s, 1, 0x3c, 1);
    /* Function select - all disabled */
    vt82c686b_superio_cfg_write(s, 0, 0xe2, 1);
    vt82c686b_superio_cfg_write(s, 1, 0x03, 1);
    /* Floppy ctrl base addr */
    vt82c686b_superio_cfg_write(s, 0, 0xe3, 1);
    vt82c686b_superio_cfg_write(s, 1, 0xfc, 1);
    /* Parallel port base addr */
    vt82c686b_superio_cfg_write(s, 0, 0xe6, 1);
    vt82c686b_superio_cfg_write(s, 1, 0xde, 1);
    /* Serial port 1 base addr */
    vt82c686b_superio_cfg_write(s, 0, 0xe7, 1);
    vt82c686b_superio_cfg_write(s, 1, 0xfe, 1);
    /* Serial port 2 base addr */
    vt82c686b_superio_cfg_write(s, 0, 0xe8, 1);
    vt82c686b_superio_cfg_write(s, 1, 0xbe, 1);

    vt82c686b_superio_cfg_write(s, 0, 0, 1);
}

static void vt82c686b_superio_init(Object *obj)
{
    VIA_SUPERIO(obj)->io_ops = &vt82c686b_superio_cfg_ops;
}

static void vt82c686b_superio_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    ISASuperIOClass *sc = ISA_SUPERIO_CLASS(klass);

    dc->reset = vt82c686b_superio_reset;
    sc->serial.count = 2;
    sc->parallel.count = 1;
    sc->ide.count = 0; /* emulated by via-ide */
    sc->floppy.count = 1;
}

static const TypeInfo vt82c686b_superio_info = {
    .name          = TYPE_VT82C686B_SUPERIO,
    .parent        = TYPE_VIA_SUPERIO,
    .instance_size = sizeof(ViaSuperIOState),
    .instance_init = vt82c686b_superio_init,
    .class_size    = sizeof(ISASuperIOClass),
    .class_init    = vt82c686b_superio_class_init,
};


OBJECT_DECLARE_SIMPLE_TYPE(VT82C686BISAState, VT82C686B_ISA)

struct VT82C686BISAState {
    PCIDevice dev;
    qemu_irq cpu_intr;
    ViaSuperIOState *via_sio;
};

static void via_isa_request_i8259_irq(void *opaque, int irq, int level)
{
    VT82C686BISAState *s = opaque;
    qemu_set_irq(s->cpu_intr, level);
}

static void vt82c686b_write_config(PCIDevice *d, uint32_t addr,
                                   uint32_t val, int len)
{
    VT82C686BISAState *s = VT82C686B_ISA(d);

    trace_via_isa_write(addr, val, len);
    pci_default_write_config(d, addr, val, len);
    if (addr == 0x85) {
        /* BIT(1): enable or disable superio config io ports */
        via_superio_io_enable(s->via_sio, val & BIT(1));
    }
}

static const VMStateDescription vmstate_via = {
    .name = "vt82c686b",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (VMStateField[]) {
        VMSTATE_PCI_DEVICE(dev, VT82C686BISAState),
        VMSTATE_END_OF_LIST()
    }
};

static void vt82c686b_isa_reset(DeviceState *dev)
{
    VT82C686BISAState *s = VT82C686B_ISA(dev);
    uint8_t *pci_conf = s->dev.config;

    pci_set_long(pci_conf + PCI_CAPABILITY_LIST, 0x000000c0);
    pci_set_word(pci_conf + PCI_COMMAND, PCI_COMMAND_IO | PCI_COMMAND_MEMORY |
                 PCI_COMMAND_MASTER | PCI_COMMAND_SPECIAL);
    pci_set_word(pci_conf + PCI_STATUS, PCI_STATUS_DEVSEL_MEDIUM);

    pci_conf[0x48] = 0x01; /* Miscellaneous Control 3 */
    pci_conf[0x4a] = 0x04; /* IDE interrupt Routing */
    pci_conf[0x4f] = 0x03; /* DMA/Master Mem Access Control 3 */
    pci_conf[0x50] = 0x2d; /* PnP DMA Request Control */
    pci_conf[0x59] = 0x04;
    pci_conf[0x5a] = 0x04; /* KBC/RTC Control*/
    pci_conf[0x5f] = 0x04;
    pci_conf[0x77] = 0x10; /* GPIO Control 1/2/3/4 */
}

static void vt82c686b_realize(PCIDevice *d, Error **errp)
{
    VT82C686BISAState *s = VT82C686B_ISA(d);
    DeviceState *dev = DEVICE(d);
    ISABus *isa_bus;
    qemu_irq *isa_irq;
    int i;

    qdev_init_gpio_out(dev, &s->cpu_intr, 1);
    isa_irq = qemu_allocate_irqs(via_isa_request_i8259_irq, s, 1);
    isa_bus = isa_bus_new(dev, get_system_memory(), pci_address_space_io(d),
                          &error_fatal);
    isa_bus_irqs(isa_bus, i8259_init(isa_bus, *isa_irq));
    i8254_pit_init(isa_bus, 0x40, 0, NULL);
    i8257_dma_init(isa_bus, 0);
    s->via_sio = VIA_SUPERIO(isa_create_simple(isa_bus,
                                               TYPE_VT82C686B_SUPERIO));
    mc146818_rtc_init(isa_bus, 2000, NULL);

    for (i = 0; i < PCI_CONFIG_HEADER_SIZE; i++) {
        if (i < PCI_COMMAND || i >= PCI_REVISION_ID) {
            d->wmask[i] = 0;
        }
    }
}

static void via_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

    k->realize = vt82c686b_realize;
    k->config_write = vt82c686b_write_config;
    k->vendor_id = PCI_VENDOR_ID_VIA;
    k->device_id = PCI_DEVICE_ID_VIA_ISA_BRIDGE;
    k->class_id = PCI_CLASS_BRIDGE_ISA;
    k->revision = 0x40;
    dc->reset = vt82c686b_isa_reset;
    dc->desc = "ISA bridge";
    dc->vmsd = &vmstate_via;
    /*
     * Reason: part of VIA VT82C686 southbridge, needs to be wired up,
     * e.g. by mips_fuloong2e_init()
     */
    dc->user_creatable = false;
}

static const TypeInfo via_info = {
    .name          = TYPE_VT82C686B_ISA,
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(VT82C686BISAState),
    .class_init    = via_class_init,
    .interfaces = (InterfaceInfo[]) {
        { INTERFACE_CONVENTIONAL_PCI_DEVICE },
        { },
    },
};


static void vt82c686b_register_types(void)
{
    type_register_static(&via_pm_info);
    type_register_static(&vt82c686b_pm_info);
    type_register_static(&vt8231_pm_info);
    type_register_static(&via_superio_info);
    type_register_static(&vt82c686b_superio_info);
    type_register_static(&via_info);
}

type_init(vt82c686b_register_types)
