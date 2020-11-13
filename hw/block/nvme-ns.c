/*
 * QEMU NVM Express Virtual Namespace
 *
 * Copyright (c) 2019 CNEX Labs
 * Copyright (c) 2020 Samsung Electronics
 *
 * Authors:
 *  Klaus Jensen      <k.jensen@samsung.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2. See the
 * COPYING file in the top-level directory.
 *
 */

#include "qemu/osdep.h"
#include "qemu/units.h"
#include "qemu/cutils.h"
#include "qemu/log.h"
#include "hw/block/block.h"
#include "hw/pci/pci.h"
#include "sysemu/sysemu.h"
#include "sysemu/block-backend.h"
#include "qapi/error.h"
#include "crypto/random.h"

#include "hw/qdev-properties.h"
#include "hw/qdev-core.h"

#include "trace.h"
#include "nvme.h"
#include "nvme-ns.h"

static void nvme_ns_init(NvmeNamespace *ns)
{
    NvmeIdNs *id_ns = &ns->id_ns;
    int lba_index = NVME_ID_NS_FLBAS_INDEX(ns->id_ns.flbas);

    if (blk_get_flags(ns->blkconf.blk) & BDRV_O_UNMAP) {
        ns->id_ns.dlfeat = 0x9;
    }

    id_ns->lbaf[lba_index].ds = 31 - clz32(ns->blkconf.logical_block_size);

    id_ns->nsze = cpu_to_le64(nvme_ns_nlbas(ns));

    ns->csi = NVME_CSI_NVM;
    ns->attached = true;

    /* no thin provisioning */
    id_ns->ncap = id_ns->nsze;
    id_ns->nuse = id_ns->ncap;
}

static int nvme_ns_init_blk(NvmeCtrl *n, NvmeNamespace *ns, Error **errp)
{
    if (!blkconf_blocksizes(&ns->blkconf, errp)) {
        return -1;
    }

    if (!blkconf_apply_backend_options(&ns->blkconf,
                                       blk_is_read_only(ns->blkconf.blk),
                                       false, errp)) {
        return -1;
    }

    ns->size = blk_getlength(ns->blkconf.blk);
    if (ns->size < 0) {
        error_setg_errno(errp, -ns->size, "could not get blockdev size");
        return -1;
    }

    if (blk_enable_write_cache(ns->blkconf.blk)) {
        n->features.vwc = 0x1;
    }

    return 0;
}

static int nvme_calc_zone_geometry(NvmeNamespace *ns, Error **errp)
{
    uint64_t zone_size, zone_cap;
    uint32_t nz, lbasz = ns->blkconf.logical_block_size;

    if (ns->params.zone_size_bs) {
        zone_size = ns->params.zone_size_bs;
    } else {
        zone_size = NVME_DEFAULT_ZONE_SIZE;
    }
    if (ns->params.zone_cap_bs) {
        zone_cap = ns->params.zone_cap_bs;
    } else {
        zone_cap = zone_size;
    }
    if (zone_cap > zone_size) {
        error_setg(errp, "zone capacity %luB exceeds zone size %luB",
                   zone_cap, zone_size);
        return -1;
    }
    if (zone_size < lbasz) {
        error_setg(errp, "zone size %luB too small, must be at least %uB",
                   zone_size, lbasz);
        return -1;
    }
    if (zone_cap < lbasz) {
        error_setg(errp, "zone capacity %luB too small, must be at least %uB",
                   zone_cap, lbasz);
        return -1;
    }
    ns->zone_size = zone_size / lbasz;
    ns->zone_capacity = zone_cap / lbasz;

    nz = DIV_ROUND_UP(ns->size / lbasz, ns->zone_size);
    ns->num_zones = nz;
    ns->zone_array_size = sizeof(NvmeZone) * nz;
    ns->zone_size_log2 = 0;
    if (is_power_of_2(ns->zone_size)) {
        ns->zone_size_log2 = 63 - clz64(ns->zone_size);
    }

    /* Make sure that the values of all ZNS properties are sane */
    if (ns->params.max_open_zones > nz) {
        error_setg(errp,
                   "max_open_zones value %u exceeds the number of zones %u",
                   ns->params.max_open_zones, nz);
        return -1;
    }
    if (ns->params.max_active_zones > nz) {
        error_setg(errp,
                   "max_active_zones value %u exceeds the number of zones %u",
                   ns->params.max_active_zones, nz);
        return -1;
    }

    if (ns->params.zd_extension_size) {
        if (ns->params.zd_extension_size & 0x3f) {
            error_setg(errp,
                "zone descriptor extension size must be a multiple of 64B");
            return -1;
        }
        if ((ns->params.zd_extension_size >> 6) > 0xff) {
            error_setg(errp, "zone descriptor extension size is too large");
            return -1;
        }
    }

    if (ns->params.max_open_zones < nz) {
        if (ns->params.nr_offline_zones > nz - ns->params.max_open_zones) {
            error_setg(errp, "offline_zones value %u is too large",
                ns->params.nr_offline_zones);
            return -1;
        }
        if (ns->params.nr_rdonly_zones >
            nz - ns->params.max_open_zones - ns->params.nr_offline_zones) {
            error_setg(errp, "rdonly_zones value %u is too large",
                ns->params.nr_rdonly_zones);
            return -1;
        }
    }

    return 0;
}

static void nvme_init_zone_state(NvmeNamespace *ns)
{
    uint64_t start = 0, zone_size = ns->zone_size;
    uint64_t capacity = ns->num_zones * zone_size;
    NvmeZone *zone;
    uint32_t rnd;
    int i;
    uint16_t zs;

    ns->zone_array = g_malloc0(ns->zone_array_size);
    if (ns->params.zd_extension_size) {
        ns->zd_extensions = g_malloc0(ns->params.zd_extension_size *
                                      ns->num_zones);
    }

    QTAILQ_INIT(&ns->exp_open_zones);
    QTAILQ_INIT(&ns->imp_open_zones);
    QTAILQ_INIT(&ns->closed_zones);
    QTAILQ_INIT(&ns->full_zones);

    zone = ns->zone_array;
    for (i = 0; i < ns->num_zones; i++, zone++) {
        if (start + zone_size > capacity) {
            zone_size = capacity - start;
        }
        zone->d.zt = NVME_ZONE_TYPE_SEQ_WRITE;
        nvme_set_zone_state(zone, NVME_ZONE_STATE_EMPTY);
        zone->d.za = 0;
        zone->d.zcap = ns->zone_capacity;
        zone->d.zslba = start;
        zone->d.wp = start;
        zone->w_ptr = start;
        start += zone_size;
    }

    /* If required, make some zones Offline or Read Only */

    for (i = 0; i < ns->params.nr_offline_zones; i++) {
        do {
            qcrypto_random_bytes(&rnd, sizeof(rnd), NULL);
            rnd %= ns->num_zones;
        } while (rnd < ns->params.max_open_zones);
        zone = &ns->zone_array[rnd];
        zs = nvme_get_zone_state(zone);
        if (zs != NVME_ZONE_STATE_OFFLINE) {
            nvme_set_zone_state(zone, NVME_ZONE_STATE_OFFLINE);
        } else {
            i--;
        }
    }

    for (i = 0; i < ns->params.nr_rdonly_zones; i++) {
        do {
            qcrypto_random_bytes(&rnd, sizeof(rnd), NULL);
            rnd %= ns->num_zones;
        } while (rnd < ns->params.max_open_zones);
        zone = &ns->zone_array[rnd];
        zs = nvme_get_zone_state(zone);
        if (zs != NVME_ZONE_STATE_OFFLINE &&
            zs != NVME_ZONE_STATE_READ_ONLY) {
            nvme_set_zone_state(zone, NVME_ZONE_STATE_READ_ONLY);
        } else {
            i--;
        }
    }
}

static int nvme_zoned_init_ns(NvmeCtrl *n, NvmeNamespace *ns, int lba_index,
                              Error **errp)
{
    NvmeIdNsZoned *id_ns_z;

    if (nvme_calc_zone_geometry(ns, errp) != 0) {
        return -1;
    }

    nvme_init_zone_state(ns);

    id_ns_z = g_malloc0(sizeof(NvmeIdNsZoned));

    /* MAR/MOR are zeroes-based, 0xffffffff means no limit */
    id_ns_z->mar = cpu_to_le32(ns->params.max_active_zones - 1);
    id_ns_z->mor = cpu_to_le32(ns->params.max_open_zones - 1);
    id_ns_z->zoc = 0;
    id_ns_z->ozcs = ns->params.cross_zone_read ? 0x01 : 0x00;

    id_ns_z->lbafe[lba_index].zsze = cpu_to_le64(ns->zone_size);
    id_ns_z->lbafe[lba_index].zdes =
        ns->params.zd_extension_size >> 6; /* Units of 64B */

    ns->csi = NVME_CSI_ZONED;
    ns->id_ns.nsze = cpu_to_le64(ns->zone_size * ns->num_zones);
    ns->id_ns.ncap = cpu_to_le64(ns->zone_capacity * ns->num_zones);
    ns->id_ns.nuse = ns->id_ns.ncap;

    ns->id_ns_zoned = id_ns_z;

    return 0;
}

static void nvme_clear_zone(NvmeNamespace *ns, NvmeZone *zone)
{
    uint8_t state;

    zone->w_ptr = zone->d.wp;
    state = nvme_get_zone_state(zone);
    if (zone->d.wp != zone->d.zslba ||
        (zone->d.za & NVME_ZA_ZD_EXT_VALID)) {
        if (state != NVME_ZONE_STATE_CLOSED) {
            trace_pci_nvme_clear_ns_close(state, zone->d.zslba);
            nvme_set_zone_state(zone, NVME_ZONE_STATE_CLOSED);
        }
        nvme_aor_inc_active(ns);
        QTAILQ_INSERT_HEAD(&ns->closed_zones, zone, entry);
    } else {
        trace_pci_nvme_clear_ns_reset(state, zone->d.zslba);
        nvme_set_zone_state(zone, NVME_ZONE_STATE_EMPTY);
    }
}

/*
 * Close all the zones that are currently open.
 */
static void nvme_zoned_ns_shutdown(NvmeNamespace *ns)
{
    NvmeZone *zone, *next;

    QTAILQ_FOREACH_SAFE(zone, &ns->closed_zones, entry, next) {
        QTAILQ_REMOVE(&ns->closed_zones, zone, entry);
        nvme_aor_dec_active(ns);
        nvme_clear_zone(ns, zone);
    }
    QTAILQ_FOREACH_SAFE(zone, &ns->imp_open_zones, entry, next) {
        QTAILQ_REMOVE(&ns->imp_open_zones, zone, entry);
        nvme_aor_dec_open(ns);
        nvme_aor_dec_active(ns);
        nvme_clear_zone(ns, zone);
    }
    QTAILQ_FOREACH_SAFE(zone, &ns->exp_open_zones, entry, next) {
        QTAILQ_REMOVE(&ns->exp_open_zones, zone, entry);
        nvme_aor_dec_open(ns);
        nvme_aor_dec_active(ns);
        nvme_clear_zone(ns, zone);
    }

    assert(ns->nr_open_zones == 0);
}

static int nvme_ns_check_constraints(NvmeNamespace *ns, Error **errp)
{
    if (!ns->blkconf.blk) {
        error_setg(errp, "block backend not configured");
        return -1;
    }

    return 0;
}

int nvme_ns_setup(NvmeCtrl *n, NvmeNamespace *ns, Error **errp)
{
    if (nvme_ns_check_constraints(ns, errp)) {
        return -1;
    }

    if (nvme_ns_init_blk(n, ns, errp)) {
        return -1;
    }

    nvme_ns_init(ns);
    if (ns->params.zoned) {
        if (nvme_zoned_init_ns(n, ns, 0, errp) != 0) {
            return -1;
        }
    }

    if (nvme_register_namespace(n, ns, errp)) {
        return -1;
    }

    return 0;
}

void nvme_ns_drain(NvmeNamespace *ns)
{
    blk_drain(ns->blkconf.blk);
}

void nvme_ns_flush(NvmeNamespace *ns)
{
    blk_flush(ns->blkconf.blk);
}

void nvme_ns_shutdown(NvmeNamespace *ns)
{
    if (ns->params.zoned) {
        nvme_zoned_ns_shutdown(ns);
    }
}

void nvme_ns_cleanup(NvmeNamespace *ns)
{
    if (ns->params.zoned) {
        g_free(ns->id_ns_zoned);
        g_free(ns->zone_array);
        g_free(ns->zd_extensions);
    }
}

static void nvme_ns_realize(DeviceState *dev, Error **errp)
{
    NvmeNamespace *ns = NVME_NS(dev);
    BusState *s = qdev_get_parent_bus(dev);
    NvmeCtrl *n = NVME(s->parent);
    Error *local_err = NULL;

    if (nvme_ns_setup(n, ns, &local_err)) {
        error_propagate_prepend(errp, local_err,
                                "could not setup namespace: ");
        return;
    }
}

static Property nvme_ns_props[] = {
    DEFINE_BLOCK_PROPERTIES(NvmeNamespace, blkconf),
    DEFINE_PROP_UINT32("nsid", NvmeNamespace, params.nsid, 0),
    DEFINE_PROP_UUID("uuid", NvmeNamespace, params.uuid),
    DEFINE_PROP_BOOL("zoned", NvmeNamespace, params.zoned, false),
    DEFINE_PROP_SIZE("zoned.zsze", NvmeNamespace, params.zone_size_bs,
                     NVME_DEFAULT_ZONE_SIZE),
    DEFINE_PROP_SIZE("zoned.zcap", NvmeNamespace, params.zone_cap_bs, 0),
    DEFINE_PROP_BOOL("zoned.cross_read", NvmeNamespace,
                     params.cross_zone_read, false),
    DEFINE_PROP_UINT32("zoned.max_active", NvmeNamespace,
                       params.max_active_zones, 0),
    DEFINE_PROP_UINT32("zoned.max_open", NvmeNamespace,
                       params.max_open_zones, 0),
    DEFINE_PROP_UINT32("zoned.descr_ext_size", NvmeNamespace,
                       params.zd_extension_size, 0),
    DEFINE_PROP_UINT32("zoned.offline_zones", NvmeNamespace,
                       params.nr_offline_zones, 0),
    DEFINE_PROP_UINT32("zoned.rdonly_zones", NvmeNamespace,
                       params.nr_rdonly_zones, 0),
    DEFINE_PROP_END_OF_LIST(),
};

static void nvme_ns_class_init(ObjectClass *oc, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);

    set_bit(DEVICE_CATEGORY_STORAGE, dc->categories);

    dc->bus_type = TYPE_NVME_BUS;
    dc->realize = nvme_ns_realize;
    device_class_set_props(dc, nvme_ns_props);
    dc->desc = "Virtual NVMe namespace";
}

static void nvme_ns_instance_init(Object *obj)
{
    NvmeNamespace *ns = NVME_NS(obj);
    char *bootindex = g_strdup_printf("/namespace@%d,0", ns->params.nsid);

    device_add_bootindex_property(obj, &ns->bootindex, "bootindex",
                                  bootindex, DEVICE(obj));

    g_free(bootindex);
}

static const TypeInfo nvme_ns_info = {
    .name = TYPE_NVME_NS,
    .parent = TYPE_DEVICE,
    .class_init = nvme_ns_class_init,
    .instance_size = sizeof(NvmeNamespace),
    .instance_init = nvme_ns_instance_init,
};

static void nvme_ns_register_types(void)
{
    type_register_static(&nvme_ns_info);
}

type_init(nvme_ns_register_types)
