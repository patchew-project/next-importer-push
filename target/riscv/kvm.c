/*
 * RISC-V implementation of KVM hooks
 *
 * Copyright (c) 2020 Huawei Technologies Co., Ltd
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2 or later, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include <sys/ioctl.h>

#include <linux/kvm.h>

#include "qemu-common.h"
#include "qemu/timer.h"
#include "qemu/error-report.h"
#include "qemu/main-loop.h"
#include "sysemu/sysemu.h"
#include "sysemu/kvm.h"
#include "sysemu/kvm_int.h"
#include "cpu.h"
#include "trace.h"
#include "hw/pci/pci.h"
#include "exec/memattrs.h"
#include "exec/address-spaces.h"
#include "hw/boards.h"
#include "hw/irq.h"
#include "qemu/log.h"
#include "hw/loader.h"
#include "kvm_riscv.h"
#include "sbi_ecall_interface.h"
#include "chardev/char-fe.h"
#include "sysemu/runstate.h"

static __u64 kvm_riscv_reg_id(__u64 type, __u64 idx)
{
    __u64 id = KVM_REG_RISCV | type | idx;

#if defined(TARGET_RISCV32)
    id |= KVM_REG_SIZE_U32;
#elif defined(TARGET_RISCV64)
    id |= KVM_REG_SIZE_U64;
#endif
    return id;
}

#define RISCV_CORE_REG(name)  kvm_riscv_reg_id(KVM_REG_RISCV_CORE, \
                 KVM_REG_RISCV_CORE_REG(name))

#define RISCV_CSR_REG(name)  kvm_riscv_reg_id(KVM_REG_RISCV_CSR, \
                 KVM_REG_RISCV_CSR_REG(name))

#define RISCV_TIMER_REG(name)  kvm_riscv_reg_id(KVM_REG_RISCV_TIMER, \
                 KVM_REG_RISCV_TIMER_REG(name))

#define RISCV_FP_F_REG(idx)  kvm_riscv_reg_id(KVM_REG_RISCV_FP_F, idx)

#define RISCV_FP_D_REG(idx)  kvm_riscv_reg_id(KVM_REG_RISCV_FP_D, idx)

static int kvm_riscv_get_regs_core(CPUState *cs)
{
    int ret = 0;
    int i;
    target_ulong reg;
    CPURISCVState *env = &RISCV_CPU(cs)->env;

    ret = kvm_get_one_reg(cs, RISCV_CORE_REG(regs.pc), &reg);
    if (ret) {
        return ret;
    }
    env->pc = reg;

    for (i = 1; i < 32; i++) {
        __u64 id = kvm_riscv_reg_id(KVM_REG_RISCV_CORE, i);
        ret = kvm_get_one_reg(cs, id, &reg);
        if (ret) {
            return ret;
        }
        env->gpr[i] = reg;
    }

    return ret;
}

static int kvm_riscv_put_regs_core(CPUState *cs)
{
    int ret = 0;
    int i;
    target_ulong reg;
    CPURISCVState *env = &RISCV_CPU(cs)->env;

    reg = env->pc;
    ret = kvm_set_one_reg(cs, RISCV_CORE_REG(regs.pc), &reg);
    if (ret) {
        return ret;
    }

    for (i = 1; i < 32; i++) {
        __u64 id = kvm_riscv_reg_id(KVM_REG_RISCV_CORE, i);
        reg = env->gpr[i];
        ret = kvm_set_one_reg(cs, id, &reg);
        if (ret) {
            return ret;
        }
    }

    return ret;
}

static int kvm_riscv_get_regs_csr(CPUState *cs)
{
    int ret = 0;
    target_ulong reg;
    CPURISCVState *env = &RISCV_CPU(cs)->env;

    ret = kvm_get_one_reg(cs, RISCV_CSR_REG(sstatus), &reg);
    if (ret) {
        return ret;
    }
    env->mstatus = reg;

    ret = kvm_get_one_reg(cs, RISCV_CSR_REG(sie), &reg);
    if (ret) {
        return ret;
    }
    env->mie = reg;

    ret = kvm_get_one_reg(cs, RISCV_CSR_REG(stvec), &reg);
    if (ret) {
        return ret;
    }
    env->stvec = reg;

    ret = kvm_get_one_reg(cs, RISCV_CSR_REG(sscratch), &reg);
    if (ret) {
        return ret;
    }
    env->sscratch = reg;

    ret = kvm_get_one_reg(cs, RISCV_CSR_REG(sepc), &reg);
    if (ret) {
        return ret;
    }
    env->sepc = reg;

    ret = kvm_get_one_reg(cs, RISCV_CSR_REG(scause), &reg);
    if (ret) {
        return ret;
    }
    env->scause = reg;

    ret = kvm_get_one_reg(cs, RISCV_CSR_REG(stval), &reg);
    if (ret) {
        return ret;
    }
    env->sbadaddr = reg;

    ret = kvm_get_one_reg(cs, RISCV_CSR_REG(sip), &reg);
    if (ret) {
        return ret;
    }
    env->mip = reg;

    ret = kvm_get_one_reg(cs, RISCV_CSR_REG(satp), &reg);
    if (ret) {
        return ret;
    }
    env->satp = reg;

    return ret;
}

static int kvm_riscv_put_regs_csr(CPUState *cs)
{
    int ret = 0;
    target_ulong reg;
    CPURISCVState *env = &RISCV_CPU(cs)->env;

    reg = env->mstatus;
    ret = kvm_set_one_reg(cs, RISCV_CSR_REG(sstatus), &reg);
    if (ret) {
        return ret;
    }

    reg = env->mie;
    ret = kvm_set_one_reg(cs, RISCV_CSR_REG(sie), &reg);
    if (ret) {
        return ret;
    }

    reg = env->stvec;
    ret = kvm_set_one_reg(cs, RISCV_CSR_REG(stvec), &reg);
    if (ret) {
        return ret;
    }

    reg = env->sscratch;
    ret = kvm_set_one_reg(cs, RISCV_CSR_REG(sscratch), &reg);
    if (ret) {
        return ret;
    }

    reg = env->sepc;
    ret = kvm_set_one_reg(cs, RISCV_CSR_REG(sepc), &reg);
    if (ret) {
        return ret;
    }

    reg = env->scause;
    ret = kvm_set_one_reg(cs, RISCV_CSR_REG(scause), &reg);
    if (ret) {
        return ret;
    }

    reg = env->sbadaddr;
    ret = kvm_set_one_reg(cs, RISCV_CSR_REG(stval), &reg);
    if (ret) {
        return ret;
    }

    reg = env->mip;
    ret = kvm_set_one_reg(cs, RISCV_CSR_REG(sip), &reg);
    if (ret) {
        return ret;
    }

    reg = env->satp;
    ret = kvm_set_one_reg(cs, RISCV_CSR_REG(satp), &reg);
    if (ret) {
        return ret;
    }

    return ret;
}


static int kvm_riscv_get_regs_fp(CPUState *cs)
{
    int ret = 0;
    int i;
    CPURISCVState *env = &RISCV_CPU(cs)->env;

    if (riscv_has_ext(env, RVD)) {
        uint64_t reg;
        for (i = 0; i < 32; i++) {
            ret = kvm_get_one_reg(cs, RISCV_FP_D_REG(i), &reg);
            if (ret) {
                return ret;
            }
            env->fpr[i] = reg;
        }
        return ret;
    }

    if (riscv_has_ext(env, RVF)) {
        uint32_t reg;
        for (i = 0; i < 32; i++) {
            ret = kvm_get_one_reg(cs, RISCV_FP_F_REG(i), &reg);
            if (ret) {
                return ret;
            }
            env->fpr[i] = reg;
        }
        return ret;
    }

    return ret;
}

static int kvm_riscv_put_regs_fp(CPUState *cs)
{
    int ret = 0;
    int i;
    CPURISCVState *env = &RISCV_CPU(cs)->env;

    if (riscv_has_ext(env, RVD)) {
        uint64_t reg;
        for (i = 0; i < 32; i++) {
            reg = env->fpr[i];
            ret = kvm_set_one_reg(cs, RISCV_FP_D_REG(i), &reg);
            if (ret) {
                return ret;
            }
        }
        return ret;
    }

    if (riscv_has_ext(env, RVF)) {
        uint32_t reg;
        for (i = 0; i < 32; i++) {
            reg = env->fpr[i];
            ret = kvm_set_one_reg(cs, RISCV_FP_F_REG(i), &reg);
            if (ret) {
                return ret;
            }
        }
        return ret;
    }

    return ret;
}

static void kvm_riscv_get_regs_timer(CPUState *cs)
{
    int ret;
    uint64_t reg;
    CPURISCVState *env = &RISCV_CPU(cs)->env;

    if (env->kvm_timer_dirty) {
        return;
    }

    ret = kvm_get_one_reg(cs, RISCV_TIMER_REG(time), &reg);
    if (ret) {
        abort();
    }
    env->kvm_timer_time = reg;

    ret = kvm_get_one_reg(cs, RISCV_TIMER_REG(compare), &reg);
    if (ret) {
        abort();
    }
    env->kvm_timer_compare = reg;

    ret = kvm_get_one_reg(cs, RISCV_TIMER_REG(state), &reg);
    if (ret) {
        abort();
    }
    env->kvm_timer_state = reg;

    env->kvm_timer_dirty = true;
}

static void kvm_riscv_put_regs_timer(CPUState *cs)
{
    int ret;
    uint64_t reg;
    CPURISCVState *env = &RISCV_CPU(cs)->env;

    if (!env->kvm_timer_dirty) {
        return;
    }

    reg = env->kvm_timer_time;
    ret = kvm_set_one_reg(cs, RISCV_TIMER_REG(time), &reg);
    if (ret) {
        abort();
    }

    reg = env->kvm_timer_compare;
    ret = kvm_set_one_reg(cs, RISCV_TIMER_REG(compare), &reg);
    if (ret) {
        abort();
    }

    /*
     * To set register of RISCV_TIMER_REG(state) will occur a error from KVM
     * on env->kvm_timer_state == 0, It's better to adapt in KVM, but it
     * doesn't matter that adaping in QEMU now.
     * TODO If KVM changes, adapt here.
     */
    if (env->kvm_timer_state) {
        reg = env->kvm_timer_state;
        ret = kvm_set_one_reg(cs, RISCV_TIMER_REG(state), &reg);
        if (ret) {
            abort();
        }
    }

    env->kvm_timer_dirty = false;
}

const KVMCapabilityInfo kvm_arch_required_capabilities[] = {
    KVM_CAP_LAST_INFO
};

int kvm_arch_get_registers(CPUState *cs)
{
    int ret = 0;

    ret = kvm_riscv_get_regs_core(cs);
    if (ret) {
        return ret;
    }

    ret = kvm_riscv_get_regs_csr(cs);
    if (ret) {
        return ret;
    }

    ret = kvm_riscv_get_regs_fp(cs);
    if (ret) {
        return ret;
    }

    return ret;
}

int kvm_arch_put_registers(CPUState *cs, int level)
{
    int ret = 0;
    RISCVCPU *cpu = RISCV_CPU(cs);
    CPURISCVState *env = &cpu->env;

    ret = kvm_riscv_put_regs_core(cs);
    if (ret) {
        return ret;
    }

    ret = kvm_riscv_put_regs_csr(cs);
    if (ret) {
        return ret;
    }

    ret = kvm_riscv_put_regs_fp(cs);
    if (ret) {
        return ret;
    }

    if (env->frequency) {
        ret = kvm_set_one_reg(cs, RISCV_TIMER_REG(frequency), &env->frequency);
    }

    return ret;
}

int kvm_arch_release_virq_post(int virq)
{
    return 0;
}

int kvm_arch_fixup_msi_route(struct kvm_irq_routing_entry *route,
                             uint64_t address, uint32_t data, PCIDevice *dev)
{
    return 0;
}

int kvm_arch_destroy_vcpu(CPUState *cs)
{
    return 0;
}

unsigned long kvm_arch_vcpu_id(CPUState *cpu)
{
    return cpu->cpu_index;
}

static void kvm_riscv_vm_state_change(void *opaque, int running, RunState state)
{
    CPUState *cs = opaque;

    if (running) {
        kvm_riscv_put_regs_timer(cs);
    } else {
        kvm_riscv_get_regs_timer(cs);
    }
}

void kvm_arch_init_irq_routing(KVMState *s)
{
}

int kvm_arch_init_vcpu(CPUState *cs)
{
    int ret = 0;
    target_ulong isa;
    RISCVCPU *cpu = RISCV_CPU(cs);
    CPURISCVState *env = &cpu->env;
    __u64 id;

    qemu_add_vm_change_state_handler(kvm_riscv_vm_state_change, cs);

    id = kvm_riscv_reg_id(KVM_REG_RISCV_CONFIG, KVM_REG_RISCV_CONFIG_REG(isa));
    ret = kvm_get_one_reg(cs, id, &isa);
    if (ret) {
        return ret;
    }
    env->misa = isa;

    /*
     * Synchronize vcpu's frequency with KVM. If vcpu's frequency is specified
     * by cpu option 'frequency', this will be set to KVM. Otherwise, vcpu's
     * frequency will follow KVM.
     */
    if (env->user_frequency) {
        ret = kvm_set_one_reg(cs, RISCV_TIMER_REG(frequency), &env->frequency);
    } else {
        ret = kvm_get_one_reg(cs, RISCV_TIMER_REG(frequency), &env->frequency);
    }

    return ret;
}

int kvm_arch_msi_data_to_gsi(uint32_t data)
{
    abort();
}

int kvm_arch_add_msi_route_post(struct kvm_irq_routing_entry *route,
                                int vector, PCIDevice *dev)
{
    return 0;
}

int kvm_arch_init(MachineState *ms, KVMState *s)
{
    return 0;
}

int kvm_arch_irqchip_create(KVMState *s)
{
    return 0;
}

int kvm_arch_process_async_events(CPUState *cs)
{
    return 0;
}

void kvm_arch_pre_run(CPUState *cs, struct kvm_run *run)
{
}

MemTxAttrs kvm_arch_post_run(CPUState *cs, struct kvm_run *run)
{
    return MEMTXATTRS_UNSPECIFIED;
}

bool kvm_arch_stop_on_emulation_error(CPUState *cs)
{
    return true;
}

static int kvm_riscv_handle_sbi(struct kvm_run *run)
{
    int ret = 0;
    unsigned char ch;
    switch (run->riscv_sbi.extension_id) {
    case SBI_EXT_0_1_CONSOLE_PUTCHAR:
        ch = run->riscv_sbi.args[0];
        qemu_chr_fe_write(serial_hd(0)->be, &ch, sizeof(ch));
        break;
    case SBI_EXT_0_1_CONSOLE_GETCHAR:
        ret = qemu_chr_fe_read_all(serial_hd(0)->be, &ch, sizeof(ch));
        if (ret == sizeof(ch)) {
            run->riscv_sbi.args[0] = ch;
        } else {
            run->riscv_sbi.args[0] = -1;
        }
        break;
    default:
        qemu_log_mask(LOG_UNIMP,
                      "%s: un-handled SBI EXIT, specific reasons is %lu\n",
                      __func__, run->riscv_sbi.extension_id);
        ret = -1;
        break;
    }
    return ret;
}

int kvm_arch_handle_exit(CPUState *cs, struct kvm_run *run)
{
    int ret = 0;
    switch (run->exit_reason) {
    case KVM_EXIT_RISCV_SBI:
        ret = kvm_riscv_handle_sbi(run);
        break;
    default:
        qemu_log_mask(LOG_UNIMP, "%s: un-handled exit reason %d\n",
                      __func__, run->exit_reason);
        ret = -1;
        break;
    }
    return ret;
}

void kvm_riscv_reset_vcpu(RISCVCPU *cpu)
{
    CPURISCVState *env = &cpu->env;

    if (!kvm_enabled()) {
        return;
    }
    env->pc = cpu->env.kernel_addr;
    env->gpr[10] = kvm_arch_vcpu_id(CPU(cpu)); /* a0 */
    env->gpr[11] = cpu->env.fdt_addr;          /* a1 */
    env->satp = 0;
}

void kvm_riscv_set_irq(RISCVCPU *cpu, int irq, int level)
{
    int ret;
    unsigned virq = level ? KVM_INTERRUPT_SET : KVM_INTERRUPT_UNSET;

    if (irq != IRQ_S_EXT) {
        return;
    }

    if (!kvm_enabled()) {
        return;
    }

    ret = kvm_vcpu_ioctl(CPU(cpu), KVM_INTERRUPT, &virq);
    if (ret < 0) {
        perror("Set irq failed");
        abort();
    }
}
