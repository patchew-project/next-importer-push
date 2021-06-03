/*
 * QEMU TCG support -- s390x vector floating point instruction support
 *
 * Copyright (C) 2019 Red Hat Inc
 *
 * Authors:
 *   David Hildenbrand <david@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */
#include "qemu/osdep.h"
#include "qemu-common.h"
#include "cpu.h"
#include "internal.h"
#include "vec.h"
#include "tcg_s390x.h"
#include "tcg/tcg-gvec-desc.h"
#include "exec/exec-all.h"
#include "exec/helper-proto.h"
#include "fpu/softfloat.h"

#define VIC_INVALID         0x1
#define VIC_DIVBYZERO       0x2
#define VIC_OVERFLOW        0x3
#define VIC_UNDERFLOW       0x4
#define VIC_INEXACT         0x5

/* returns the VEX. If the VEX is 0, there is no trap */
static uint8_t check_ieee_exc(CPUS390XState *env, uint8_t enr, bool XxC,
                              uint8_t *vec_exc)
{
    uint8_t vece_exc = 0, trap_exc;
    unsigned qemu_exc;

    /* Retrieve and clear the softfloat exceptions */
    qemu_exc = env->fpu_status.float_exception_flags;
    if (qemu_exc == 0) {
        return 0;
    }
    env->fpu_status.float_exception_flags = 0;

    vece_exc = s390_softfloat_exc_to_ieee(qemu_exc);

    /* Add them to the vector-wide s390x exception bits */
    *vec_exc |= vece_exc;

    /* Check for traps and construct the VXC */
    trap_exc = vece_exc & env->fpc >> 24;
    if (trap_exc) {
        if (trap_exc & S390_IEEE_MASK_INVALID) {
            return enr << 4 | VIC_INVALID;
        } else if (trap_exc & S390_IEEE_MASK_DIVBYZERO) {
            return enr << 4 | VIC_DIVBYZERO;
        } else if (trap_exc & S390_IEEE_MASK_OVERFLOW) {
            return enr << 4 | VIC_OVERFLOW;
        } else if (trap_exc & S390_IEEE_MASK_UNDERFLOW) {
            return enr << 4 | VIC_UNDERFLOW;
        } else if (!XxC) {
            g_assert(trap_exc & S390_IEEE_MASK_INEXACT);
            /* inexact has lowest priority on traps */
            return enr << 4 | VIC_INEXACT;
        }
    }
    return 0;
}

static void handle_ieee_exc(CPUS390XState *env, uint8_t vxc, uint8_t vec_exc,
                            uintptr_t retaddr)
{
    if (vxc) {
        /* on traps, the fpc flags are not updated, instruction is suppressed */
        tcg_s390_vector_exception(env, vxc, retaddr);
    }
    if (vec_exc) {
        /* indicate exceptions for all elements combined */
        env->fpc |= vec_exc << 16;
    }
}

static float64 s390_vec_read_float64(const S390Vector *v, uint8_t enr)
{
    return make_float64(s390_vec_read_element64(v, enr));
}

static void s390_vec_write_float64(S390Vector *v, uint8_t enr, float64 data)
{
    return s390_vec_write_element64(v, enr, data);
}

typedef float64 (*vop64_2_fn)(float64 a, float_status *s);
static void vop64_2(S390Vector *v1, const S390Vector *v2, CPUS390XState *env,
                    bool s, bool XxC, uint8_t erm, vop64_2_fn fn,
                    uintptr_t retaddr)
{
    uint8_t vxc, vec_exc = 0;
    S390Vector tmp = {};
    int i, old_mode;

    old_mode = s390_swap_bfp_rounding_mode(env, erm);
    for (i = 0; i < 2; i++) {
        const float64 a = s390_vec_read_float64(v2, i);

        s390_vec_write_float64(&tmp, i, fn(a, &env->fpu_status));
        vxc = check_ieee_exc(env, i, XxC, &vec_exc);
        if (s || vxc) {
            break;
        }
    }
    s390_restore_bfp_rounding_mode(env, old_mode);
    handle_ieee_exc(env, vxc, vec_exc, retaddr);
    *v1 = tmp;
}

static float64 vcdg64(float64 a, float_status *s)
{
    return int64_to_float64(a, s);
}

static float64 vcdlg64(float64 a, float_status *s)
{
    return uint64_to_float64(a, s);
}

static float64 vcgd64(float64 a, float_status *s)
{
    if (float64_is_any_nan(a)) {
        return INT64_MIN;
    }
    return float64_to_int64(a, s);
}

static float64 vclgd64(float64 a, float_status *s)
{
    if (float64_is_any_nan(a)) {
        return 0;
    }
    return float64_to_uint64(a, s);
}

#define DEF_GVEC_VOP2_FN(NAME, FN, BITS)                                       \
void HELPER(gvec_##NAME##BITS)(void *v1, const void *v2, CPUS390XState *env,   \
                               uint32_t desc)                                  \
{                                                                              \
    const uint8_t erm = extract32(simd_data(desc), 4, 4);                      \
    const uint8_t se = extract32(simd_data(desc), 3, 1);                       \
    const bool XxC = extract32(simd_data(desc), 2, 1);                         \
                                                                               \
    vop##BITS##_2(v1, v2, env, se, XxC, erm, FN, GETPC());                     \
}

#define DEF_GVEC_VOP2_64(NAME)                                                 \
DEF_GVEC_VOP2_FN(NAME, NAME##64, 64)

#define DEF_GVEC_VOP2(NAME, OP)                                                \
DEF_GVEC_VOP2_FN(NAME, float64_##OP, 64)

DEF_GVEC_VOP2_64(vcdg)
DEF_GVEC_VOP2_64(vcdlg)
DEF_GVEC_VOP2_64(vcgd)
DEF_GVEC_VOP2_64(vclgd)
DEF_GVEC_VOP2(vfi, round_to_int)
DEF_GVEC_VOP2(vfsq, sqrt)

typedef float64 (*vop64_3_fn)(float64 a, float64 b, float_status *s);
static void vop64_3(S390Vector *v1, const S390Vector *v2, const S390Vector *v3,
                    CPUS390XState *env, bool s, vop64_3_fn fn,
                    uintptr_t retaddr)
{
    uint8_t vxc, vec_exc = 0;
    S390Vector tmp = {};
    int i;

    for (i = 0; i < 2; i++) {
        const float64 a = s390_vec_read_float64(v2, i);
        const float64 b = s390_vec_read_float64(v3, i);

        s390_vec_write_float64(&tmp, i, fn(a, b, &env->fpu_status));
        vxc = check_ieee_exc(env, i, false, &vec_exc);
        if (s || vxc) {
            break;
        }
    }
    handle_ieee_exc(env, vxc, vec_exc, retaddr);
    *v1 = tmp;
}

#define DEF_GVEC_VOP3(NAME, OP)                                                \
void HELPER(gvec_##NAME##64)(void *v1, const void *v2, const void *v3,         \
                             CPUS390XState *env, uint32_t desc)                \
{                                                                              \
    const bool se = extract32(simd_data(desc), 3, 1);                          \
                                                                               \
    vop64_3(v1, v2, v3, env, se, float64_##OP, GETPC());                       \
}

DEF_GVEC_VOP3(vfa, add)
DEF_GVEC_VOP3(vfs, sub)
DEF_GVEC_VOP3(vfd, div)
DEF_GVEC_VOP3(vfm, mul)

static int wfc64(const S390Vector *v1, const S390Vector *v2,
                 CPUS390XState *env, bool signal, uintptr_t retaddr)
{
    /* only the zero-indexed elements are compared */
    const float64 a = s390_vec_read_element64(v1, 0);
    const float64 b = s390_vec_read_element64(v2, 0);
    uint8_t vxc, vec_exc = 0;
    int cmp;

    if (signal) {
        cmp = float64_compare(a, b, &env->fpu_status);
    } else {
        cmp = float64_compare_quiet(a, b, &env->fpu_status);
    }
    vxc = check_ieee_exc(env, 0, false, &vec_exc);
    handle_ieee_exc(env, vxc, vec_exc, retaddr);

    return float_comp_to_cc(env, cmp);
}

void HELPER(gvec_wfc64)(const void *v1, const void *v2, CPUS390XState *env,
                        uint32_t desc)
{
    env->cc_op = wfc64(v1, v2, env, false, GETPC());
}

void HELPER(gvec_wfk64)(const void *v1, const void *v2, CPUS390XState *env,
                        uint32_t desc)
{
    env->cc_op = wfc64(v1, v2, env, true, GETPC());
}

typedef bool (*vfc64_fn)(float64 a, float64 b, float_status *status);
static int vfc64(S390Vector *v1, const S390Vector *v2, const S390Vector *v3,
                 CPUS390XState *env, bool s, vfc64_fn fn, uintptr_t retaddr)
{
    uint8_t vxc, vec_exc = 0;
    S390Vector tmp = {};
    int match = 0;
    int i;

    for (i = 0; i < 2; i++) {
        const float64 a = s390_vec_read_float64(v2, i);
        const float64 b = s390_vec_read_float64(v3, i);

        /* swap the order of the parameters, so we can use existing functions */
        if (fn(b, a, &env->fpu_status)) {
            match++;
            s390_vec_write_element64(&tmp, i, -1ull);
        }
        vxc = check_ieee_exc(env, i, false, &vec_exc);
        if (s || vxc) {
            break;
        }
    }

    handle_ieee_exc(env, vxc, vec_exc, retaddr);
    *v1 = tmp;
    if (match) {
        return s || match == 2 ? 0 : 1;
    }
    return 3;
}

#define DEF_GVEC_VFC_B(NAME, OP, BITS)                                         \
void HELPER(gvec_##NAME##BITS)(void *v1, const void *v2, const void *v3,       \
                               CPUS390XState *env, uint32_t desc)              \
{                                                                              \
    const bool se = extract32(simd_data(desc), 3, 1);                          \
    vfc##BITS##_fn fn = float##BITS##_##OP##_quiet;                            \
                                                                               \
    vfc##BITS(v1, v2, v3, env, se, fn, GETPC());                               \
}                                                                              \
                                                                               \
void HELPER(gvec_##NAME##BITS##_cc)(void *v1, const void *v2, const void *v3,  \
                                    CPUS390XState *env, uint32_t desc)         \
{                                                                              \
    const bool se = extract32(simd_data(desc), 3, 1);                          \
    vfc##BITS##_fn fn = float##BITS##_##OP##_quiet;                            \
                                                                               \
    env->cc_op = vfc##BITS(v1, v2, v3, env, se, fn, GETPC());                  \
}

#define DEF_GVEC_VFC(NAME, OP)                                                 \
DEF_GVEC_VFC_B(NAME, OP, 64)

DEF_GVEC_VFC(vfce, eq)
DEF_GVEC_VFC(vfch, lt)
DEF_GVEC_VFC(vfche, le)

void HELPER(gvec_vfll32)(void *v1, const void *v2, CPUS390XState *env,
                         uint32_t desc)
{
    const bool s = extract32(simd_data(desc), 3, 1);
    uint8_t vxc, vec_exc = 0;
    S390Vector tmp = {};
    int i;

    for (i = 0; i < 2; i++) {
        /* load from even element */
        const float32 a = s390_vec_read_element32(v2, i * 2);
        const uint64_t ret = float32_to_float64(a, &env->fpu_status);

        s390_vec_write_element64(&tmp, i, ret);
        /* indicate the source element */
        vxc = check_ieee_exc(env, i * 2, false, &vec_exc);
        if (s || vxc) {
            break;
        }
    }
    handle_ieee_exc(env, vxc, vec_exc, GETPC());
    *(S390Vector *)v1 = tmp;
}

void HELPER(gvec_vflr64)(void *v1, const void *v2, CPUS390XState *env,
                         uint32_t desc)
{
    const uint8_t erm = extract32(simd_data(desc), 4, 4);
    const bool s = extract32(simd_data(desc), 3, 1);
    const bool XxC = extract32(simd_data(desc), 2, 1);
    uint8_t vxc, vec_exc = 0;
    S390Vector tmp = {};
    int i, old_mode;

    old_mode = s390_swap_bfp_rounding_mode(env, erm);
    for (i = 0; i < 2; i++) {
        float64 a = s390_vec_read_element64(v2, i);
        uint32_t ret = float64_to_float32(a, &env->fpu_status);

        /* place at even element */
        s390_vec_write_element32(&tmp, i * 2, ret);
        /* indicate the source element */
        vxc = check_ieee_exc(env, i, XxC, &vec_exc);
        if (s || vxc) {
            break;
        }
    }
    s390_restore_bfp_rounding_mode(env, old_mode);
    handle_ieee_exc(env, vxc, vec_exc, GETPC());
    *(S390Vector *)v1 = tmp;
}

static void vfma64(S390Vector *v1, const S390Vector *v2, const S390Vector *v3,
                   const S390Vector *v4, CPUS390XState *env, bool s, int flags,
                   uintptr_t retaddr)
{
    uint8_t vxc, vec_exc = 0;
    S390Vector tmp = {};
    int i;

    for (i = 0; i < 2; i++) {
        const float64 a = s390_vec_read_float64(v2, i);
        const float64 b = s390_vec_read_float64(v3, i);
        const float64 c = s390_vec_read_float64(v4, i);
        const float64 ret = float64_muladd(a, b, c, flags, &env->fpu_status);

        s390_vec_write_float64(&tmp, i, ret);
        vxc = check_ieee_exc(env, i, false, &vec_exc);
        if (s || vxc) {
            break;
        }
    }
    handle_ieee_exc(env, vxc, vec_exc, retaddr);
    *v1 = tmp;
}

#define DEF_GVEC_VFMA_B(NAME, FLAGS, BITS)                                     \
void HELPER(gvec_##NAME##BITS)(void *v1, const void *v2, const void *v3,       \
                               const void *v4, CPUS390XState *env,             \
                               uint32_t desc)                                  \
{                                                                              \
    const bool se = extract32(simd_data(desc), 3, 1);                          \
                                                                               \
    vfma##BITS(v1, v2, v3, v4, env, se, FLAGS, GETPC());                       \
}

#define DEF_GVEC_VFMA(NAME, FLAGS)                                             \
    DEF_GVEC_VFMA_B(NAME, FLAGS, 64)

DEF_GVEC_VFMA(vfma, 0)
DEF_GVEC_VFMA(vfms, float_muladd_negate_c)

void HELPER(gvec_vftci64)(void *v1, const void *v2, CPUS390XState *env,
                          uint32_t desc)
{
    const uint16_t i3 = extract32(simd_data(desc), 4, 12);
    const bool s = extract32(simd_data(desc), 3, 1);
    int i, match = 0;

    for (i = 0; i < 2; i++) {
        const float64 a = s390_vec_read_float64(v2, i);

        if (float64_dcmask(env, a) & i3) {
            match++;
            s390_vec_write_element64(v1, i, -1ull);
        } else {
            s390_vec_write_element64(v1, i, 0);
        }
        if (s) {
            break;
        }
    }

    if (match == 2 || (s && match)) {
        env->cc_op = 0;
    } else if (match) {
        env->cc_op = 1;
    } else {
        env->cc_op = 3;
    }
}
