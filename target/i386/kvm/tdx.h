#ifndef QEMU_I386_TDX_H
#define QEMU_I386_TDX_H

#include "qom/object.h"
#include "qapi/error.h"
#include "exec/confidential-guest-support.h"

typedef struct TdxFirmwareEntry {
    uint32_t data_offset;
    uint32_t data_len;
    uint64_t address;
    uint64_t size;
    uint32_t type;
    uint32_t attributes;

    MemoryRegion *mr;
    void *mem_ptr;
} TdxFirmwareEntry;

typedef struct TdxFirmware {
    const char *file_name;
    uint64_t file_size;

    /* metadata */
    uint32_t nr_entries;
    TdxFirmwareEntry *entries;
} TdxFirmware;

#define for_each_fw_entry(fw, e)                                        \
    for (e = (fw)->entries; e != (fw)->entries + (fw)->nr_entries; e++)

#define TYPE_TDX_GUEST "tdx-guest"
#define TDX_GUEST(obj)     \
    OBJECT_CHECK(TdxGuest, (obj), TYPE_TDX_GUEST)

typedef struct TdxGuestClass {
    ConfidentialGuestSupportClass parent_class;
} TdxGuestClass;

typedef struct TdxGuest {
    ConfidentialGuestSupport parent_obj;

    QemuMutex lock;

    bool initialized;
    bool debug;
    uint8_t mrconfigid[48];     /* sha348 digest */
    uint8_t mrowner[48];        /* sha348 digest */
    uint8_t mrownerconfig[48];  /* sha348 digest */

    TdxFirmware fw;
} TdxGuest;

int tdx_kvm_init(ConfidentialGuestSupport *cgs, Error **errp);
void tdx_get_supported_cpuid(KVMState *s, uint32_t function,
                             uint32_t index, int reg, uint32_t *ret);

#endif
