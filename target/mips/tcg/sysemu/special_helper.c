/*
 *  QEMU MIPS emulation: Special opcode helpers
 *
 *  Copyright (c) 2004-2005 Jocelyn Mayer
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/helper-proto.h"
#include "exec/exec-all.h"
#include "internal.h"

/* Specials */
target_ulong helper_di(CPUMIPSState *env)
{
    target_ulong t0 = env->CP0_Status;

    env->CP0_Status = t0 & ~(1 << CP0St_IE);
    return t0;
}

target_ulong helper_ei(CPUMIPSState *env)
{
    target_ulong t0 = env->CP0_Status;

    env->CP0_Status = t0 | (1 << CP0St_IE);
    return t0;
}

static void debug_pre_eret(CPUMIPSState *env)
{
    if (qemu_loglevel_mask(CPU_LOG_EXEC)) {
        qemu_log("ERET: PC " TARGET_FMT_lx " EPC " TARGET_FMT_lx,
                env->active_tc.PC, env->CP0_EPC);
        if (env->CP0_Status & (1 << CP0St_ERL)) {
            qemu_log(" ErrorEPC " TARGET_FMT_lx, env->CP0_ErrorEPC);
        }
        if (env->hflags & MIPS_HFLAG_DM) {
            qemu_log(" DEPC " TARGET_FMT_lx, env->CP0_DEPC);
        }
        qemu_log("\n");
    }
}

static void debug_post_eret(CPUMIPSState *env)
{
    if (qemu_loglevel_mask(CPU_LOG_EXEC)) {
        qemu_log("  =>  PC " TARGET_FMT_lx " EPC " TARGET_FMT_lx,
                env->active_tc.PC, env->CP0_EPC);
        if (env->CP0_Status & (1 << CP0St_ERL)) {
            qemu_log(" ErrorEPC " TARGET_FMT_lx, env->CP0_ErrorEPC);
        }
        if (env->hflags & MIPS_HFLAG_DM) {
            qemu_log(" DEPC " TARGET_FMT_lx, env->CP0_DEPC);
        }
        switch (cpu_mmu_index(env, false)) {
        case 3:
            qemu_log(", ERL\n");
            break;
        case MIPS_HFLAG_UM:
            qemu_log(", UM\n");
            break;
        case MIPS_HFLAG_SM:
            qemu_log(", SM\n");
            break;
        case MIPS_HFLAG_KM:
            qemu_log("\n");
            break;
        default:
            cpu_abort(env_cpu(env), "Invalid MMU mode!\n");
            break;
        }
    }
}

static void set_pc(CPUMIPSState *env, target_ulong error_pc)
{
    env->active_tc.PC = error_pc & ~(target_ulong)1;
    if (error_pc & 1) {
        env->hflags |= MIPS_HFLAG_M16;
    } else {
        env->hflags &= ~(MIPS_HFLAG_M16);
    }
}

bool mips_io_recompile_replay_branch(CPUState *cs, const TranslationBlock *tb)
{
    MIPSCPU *cpu = MIPS_CPU(cs);
    CPUMIPSState *env = &cpu->env;

    if ((env->hflags & MIPS_HFLAG_BMASK) != 0
        && env->active_tc.PC != tb->pc) {
        env->active_tc.PC -= (env->hflags & MIPS_HFLAG_B16 ? 2 : 4);
        env->hflags &= ~MIPS_HFLAG_BMASK;
        return true;
    }
    return false;
}

static inline void exception_return(CPUMIPSState *env)
{
    debug_pre_eret(env);
    if (env->CP0_Status & (1 << CP0St_ERL)) {
        set_pc(env, env->CP0_ErrorEPC);
        env->CP0_Status &= ~(1 << CP0St_ERL);
    } else {
        set_pc(env, env->CP0_EPC);
        env->CP0_Status &= ~(1 << CP0St_EXL);
    }
    compute_hflags(env);
    debug_post_eret(env);
}

void helper_eret(CPUMIPSState *env)
{
    exception_return(env);
    env->CP0_LLAddr = 1;
    env->lladdr = 1;
}

void helper_eretnc(CPUMIPSState *env)
{
    exception_return(env);
}

void helper_deret(CPUMIPSState *env)
{
    debug_pre_eret(env);

    env->hflags &= ~MIPS_HFLAG_DM;
    compute_hflags(env);

    set_pc(env, env->CP0_DEPC);

    debug_post_eret(env);
}
