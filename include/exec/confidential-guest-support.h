/*
 * QEMU Confidential Guest support
 *   This interface describes the common pieces between various
 *   schemes for protecting guest memory or other state against a
 *   compromised hypervisor.  This includes memory encryption (AMD's
 *   SEV and Intel's MKTME) or special protection modes (PEF on POWER,
 *   or PV on s390x).
 *
 * Copyright: David Gibson, Red Hat Inc. 2020
 *
 * Authors:
 *  David Gibson <david@gibson.dropbear.id.au>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * later.  See the COPYING file in the top-level directory.
 *
 */
#ifndef QEMU_CONFIDENTIAL_GUEST_SUPPORT_H
#define QEMU_CONFIDENTIAL_GUEST_SUPPORT_H

#ifndef CONFIG_USER_ONLY

#include "qom/object.h"

#define TYPE_CONFIDENTIAL_GUEST_SUPPORT "confidential-guest-support"
#define CONFIDENTIAL_GUEST_SUPPORT(obj)                                    \
    OBJECT_CHECK(ConfidentialGuestSupport, (obj),                          \
                 TYPE_CONFIDENTIAL_GUEST_SUPPORT)
#define CONFIDENTIAL_GUEST_SUPPORT_CLASS(klass)                            \
    OBJECT_CLASS_CHECK(ConfidentialGuestSupportClass, (klass),             \
                       TYPE_CONFIDENTIAL_GUEST_SUPPORT)
#define CONFIDENTIAL_GUEST_SUPPORT_GET_CLASS(obj)                          \
    OBJECT_GET_CLASS(ConfidentialGuestSupportClass, (obj),                 \
                     TYPE_CONFIDENTIAL_GUEST_SUPPORT)

struct ConfidentialGuestSupport {
    Object parent;
};

typedef struct ConfidentialGuestSupportClass {
    ObjectClass parent;
} ConfidentialGuestSupportClass;

#endif /* !CONFIG_USER_ONLY */

#endif /* QEMU_CONFIDENTIAL_GUEST_SUPPORT_H */
