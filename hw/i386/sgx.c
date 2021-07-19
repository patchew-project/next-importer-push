/*
 * SGX common code
 *
 * Copyright (C) 2021 Intel Corporation
 *
 * Authors:
 *   Yang Zhong<yang.zhong@intel.com>
 *   Sean Christopherson <sean.j.christopherson@intel.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */
#include "qemu/osdep.h"
#include "hw/i386/pc.h"
#include "hw/i386/sgx-epc.h"
#include "hw/mem/memory-device.h"
#include "monitor/qdev.h"
#include "qapi/error.h"
#include "exec/address-spaces.h"

int sgx_epc_get_section(int section_nr, uint64_t *addr, uint64_t *size)
{
    PCMachineState *pcms = PC_MACHINE(qdev_get_machine());
    SGXEPCDevice *epc;

    if (pcms->sgx_epc.size == 0 || pcms->sgx_epc.nr_sections <= section_nr) {
        return 1;
    }

    epc = pcms->sgx_epc.sections[section_nr];

    *addr = epc->addr;
    *size = memory_device_get_region_size(MEMORY_DEVICE(epc), &error_fatal);

    return 0;
}

static int sgx_epc_set_property(void *opaque, const char *name,
                                const char *value, Error **errp)
{
    Object *obj = opaque;
    Error *err = NULL;

    object_property_parse(obj, name, value, &err);
    if (err != NULL) {
        error_propagate(errp, err);
        return -1;
    }
    return 0;
}

void pc_machine_init_sgx_epc(PCMachineState *pcms)
{
    SGXEPCState *sgx_epc = &pcms->sgx_epc;
    X86MachineState *x86ms = X86_MACHINE(pcms);
    Error *err = NULL;
    SgxEPCList *list = NULL;
    Object *obj;

    memset(sgx_epc, 0, sizeof(SGXEPCState));
    sgx_epc->base = 0x100000000ULL + x86ms->above_4g_mem_size;

    memory_region_init(&sgx_epc->mr, OBJECT(pcms), "sgx-epc", UINT64_MAX);
    memory_region_add_subregion(get_system_memory(), sgx_epc->base,
                                &sgx_epc->mr);

    for (list = x86ms->sgx_epc_list; list; list = list->next) {
        obj = object_new("sgx-epc");

        /* set the memdev link with memory backend */
        sgx_epc_set_property(obj, SGX_EPC_MEMDEV_PROP, list->value->memdev,
                             &err);
        object_property_set_bool(obj, "realized", true, &err);
        object_unref(obj);
    }

    if ((sgx_epc->base + sgx_epc->size) < sgx_epc->base) {
        error_report("Size of all 'sgx-epc' =0x%"PRIu64" causes EPC to wrap",
                     sgx_epc->size);
        exit(EXIT_FAILURE);
    }

    memory_region_set_size(&sgx_epc->mr, sgx_epc->size);
}
