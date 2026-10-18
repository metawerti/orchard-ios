/*
 * Copyright (C) 2014 - Linaro
 * Author: Rob Herring <rob.herring@linaro.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qemu/atomic.h"
#include "qemu/bswap.h"
#include "exec/cputlb.h"
#include "cpu.h"
#include "helper.h"
#include "kvm-consts.h"
#include "qemu/main-loop.h"
#include "system/runstate.h"
#include "internals.h"
#include "arm-powerctl.h"
#include "target/arm/multiprocessing.h"
#include "target/arm/trace.h"

#define MACPAD_CAL_MAX_FRAMES 12
#define MACPAD_CAL_MAX_RESETS 8U
#define MACPAD_CAL_ENTRY_WORDS 48

typedef struct MacpadCalFrameDiagnostic {
    const char *stage;
    const char *read_error;
    /* Read request start; the cache reader does not report partial progress. */
    uint64_t read_addr;
    uint64_t caller_start;
    bool caller_start_valid;
    bool caller_read;
    int mismatch_index;
    uint32_t actual;
    uint32_t expected;
    uint32_t mask;
    bool string_read[2];
    bool string_match[2];
} MacpadCalFrameDiagnostic;

static bool macpad_cal_add_signed(uint64_t base, int64_t delta,
                                  uint64_t *result)
{
    if (delta < 0) {
        uint64_t magnitude = (uint64_t)(-(delta + 1)) + 1;

        if (base < magnitude) {
            return false;
        }
        *result = base - magnitude;
    } else {
        uint64_t magnitude = (uint64_t)delta;

        if (base > UINT64_MAX - magnitude) {
            return false;
        }
        *result = base + magnitude;
    }
    return true;
}

/* A different caller layout is a calibration miss, not permission to guess. */
static const char *macpad_cal_halt_site(CPUState *cs, uint64_t raw_lr,
                                      uint32_t words[16],
                                      MacpadCalFrameDiagnostic *diag)
{
    static const uint32_t expected[16] = {
        0xd503237f, 0xa9be4ff4, 0xa9017bfd, 0x910043fd,
        0x7100001f, 0x1a9f07f3, 0xf0ff9b28, 0x91128508,
        0xf0ff9b29, 0x9112b929, 0x9a880120, 0x97fbd329,
        0xaa1303e0, 0x52800001, 0x9415c857, 0x14000000,
    };
    static const uint32_t masks[16] = {
        0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
        0xffffffff, 0xffffffff, 0x9f00001f, 0xffc003ff,
        0x9f00001f, 0xffc003ff, 0xffffffff, 0xfc000000,
        0xffffffff, 0xffffffff, 0xfc000000, 0xffffffff,
    };
    static const char messages[2][13] = {
        "MACH Reboot\n", "CPU halted\n",
    };
    static const size_t message_lengths[2] = {
        sizeof("MACH Reboot\n"), sizeof("CPU halted\n"),
    };
    uint8_t raw[64];
    uint64_t start;
    const char *error;

    diag->stage = "lr";
    if ((raw_lr & 3) || raw_lr < 0x3c || raw_lr > UINT64_MAX - 4) {
        return "raw_lr_invalid";
    }
    start = raw_lr - 0x3c;
    diag->caller_start = start;
    diag->caller_start_valid = true;
    diag->stage = "caller_read";
    diag->read_addr = start;
    error = tcg_debug_read_cached_ram(cs, start, raw, sizeof(raw), true);
    if (error) {
        diag->read_error = error;
        return error;
    }
    diag->caller_read = true;
    diag->stage = "instruction_validation";
    for (unsigned int i = 0; i < 16; i++) {
        words[i] = ldl_le_p(raw + i * 4);
        if ((words[i] & masks[i]) != (expected[i] & masks[i])) {
            diag->mismatch_index = i;
            diag->actual = words[i];
            diag->expected = expected[i];
            diag->mask = masks[i];
            return "signature_mismatch";
        }
    }
    for (unsigned int message = 0; message < 2; message++) {
        unsigned int adrp_index = message ? 8 : 6;
        uint32_t adrp = words[adrp_index];
        uint32_t add = words[adrp_index + 1];
        uint64_t adrp_pc = start + adrp_index * 4;
        uint64_t string_addr;
        int64_t imm21;
        char actual[13];

        diag->stage = message ? "string1_address" : "string0_address";
        diag->read_addr = 0;
        imm21 = (((adrp >> 5) & 0x7ffff) << 2) | ((adrp >> 29) & 3);
        if (imm21 & (INT64_C(1) << 20)) {
            imm21 -= INT64_C(1) << 21;
        }
        if (!macpad_cal_add_signed(adrp_pc & ~UINT64_C(0xfff),
                                   imm21 * 4096, &string_addr) ||
            !macpad_cal_add_signed(string_addr, (add >> 10) & 0xfff,
                                   &string_addr)) {
            return "message_address_invalid";
        }
        diag->stage = message ? "string1_read" : "string0_read";
        diag->read_addr = string_addr;
        error = tcg_debug_read_cached_ram(cs, string_addr, actual,
                                          message_lengths[message], false);
        if (error) {
            diag->read_error = error;
            return error;
        }
        diag->string_read[message] = true;
        diag->stage = message ? "string1_validation" : "string0_validation";
        if (memcmp(actual, messages[message], message_lengths[message])) {
            return "message_mismatch";
        }
        diag->string_match[message] = true;
    }
    diag->stage = "validated";
    return NULL;
}

/* The caller provides count * 9 + 1 bytes. */
static void macpad_cal_format_words(char *out, const uint32_t *words,
                                    unsigned int count)
{
    if (!count) {
        out[0] = '\0';
        return;
    }
    for (unsigned int i = 0; i < count; i++) {
        snprintf(out + i * 9, 10, "%08" PRIx32 " ", words[i]);
    }
    out[count * 9 - 1] = '\0';
}

static void macpad_calibrate_restart(ARMCPU *cpu, const uint64_t *frame_lr,
                                     int frame_count)
{
    static unsigned int samples;
    CPUState *cs = CPU(cpu);
    CPUARMState *env = &cpu->env;
    unsigned int sample;
    unsigned int previous;
    unsigned int matches = 0;
    unsigned int read_failures = 0;
    uint64_t selected_lr = 0;
    uint64_t call_pc = 0;
    uint64_t destination = 0;
    uint32_t selected_words[16] = { 0 };
    uint32_t words[16];
    uint32_t entry[MACPAD_CAL_ENTRY_WORDS];
    uint32_t bl = 0;
    uint8_t raw_bl[4];
    int selected_index = -1;
    int64_t displacement;
    int64_t host_us;
    const char *phase = "scan";
    const char *result = "no_match";
    const char *last_reject = "none";
    const char *error;
    MacpadCalFrameDiagnostic diag;
    bool captured = false;
    char tag[128];
    char caller_hex[16 * 9 + 1];
    char entry_hex[MACPAD_CAL_ENTRY_WORDS * 9 + 1];

    /* Observer-lifetime sample budget, not a guest boot/session identifier. */
    sample = qatomic_read(&samples);
    for (;;) {
        if (sample >= MACPAD_CAL_MAX_RESETS) {
            return;
        }
        previous = qatomic_cmpxchg(&samples, sample, sample + 1);
        if (previous == sample) {
            sample++;
            break;
        }
        sample = previous;
    }
    host_us = g_get_monotonic_time();
    snprintf(tag, sizeof(tag),
             "MACPAD_RESET_CAL v=2 scope=observer pid=%ld sample=%u",
             (long)getpid(), sample);

    if (!is_a64(env)) {
        result = "unsupported_aarch32";
        goto report;
    }
    if (!frame_lr || frame_count < 0 ||
        frame_count > MACPAD_CAL_MAX_FRAMES) {
        result = "frame_count_invalid";
        goto report;
    }
    for (int i = 0; i < frame_count; i++) {
        memset(&diag, 0, sizeof(diag));
        diag.stage = "start";
        diag.mismatch_index = -1;
        error = macpad_cal_halt_site(cs, frame_lr[i], words, &diag);
        if (error) {
            last_reject = error;
            if (strncmp(error, "read_", 5) == 0) {
                read_failures++;
            }
            error_report(
                "%s phase=frame frame=%d cpu=%d raw_lr=0x%" PRIx64
                " caller_start_valid=%u caller_start=0x%" PRIx64
                " stage=%s result=reject read_error=%s read_addr=0x%" PRIx64
                " caller_read=%u mismatch_index=%d actual=%08" PRIx32
                " expected=%08" PRIx32 " mask=%08" PRIx32
                " string0_read=%u string0_match=%u"
                " string1_read=%u string1_match=%u",
                tag, i, cs->cpu_index, frame_lr[i],
                diag.caller_start_valid, diag.caller_start, diag.stage,
                diag.read_error ? diag.read_error : "none", diag.read_addr,
                diag.caller_read, diag.mismatch_index, diag.actual,
                diag.expected, diag.mask, diag.string_read[0],
                diag.string_match[0], diag.string_read[1],
                diag.string_match[1]);
            continue;
        }
        error_report(
            "%s phase=frame frame=%d cpu=%d"
            " raw_lr=0x%" PRIx64 " caller_start_valid=%u"
            " caller_start=0x%" PRIx64
            " stage=%s result=validated caller_read=%u"
            " mismatch_index=%d string0_read=%u string0_match=%u"
            " string1_read=%u string1_match=%u",
            tag, i, cs->cpu_index, frame_lr[i], diag.caller_start_valid,
            diag.caller_start, diag.stage, diag.caller_read,
            diag.mismatch_index, diag.string_read[0], diag.string_match[0],
            diag.string_read[1], diag.string_match[1]);
        matches++;
        if (matches == 1) {
            selected_index = i;
            selected_lr = frame_lr[i];
            memcpy(selected_words, words, sizeof(selected_words));
        }
    }
    if (matches != 1) {
        result = matches ? "ambiguous" : "no_match";
        selected_index = -1;
        selected_lr = 0;
        goto report;
    }

    phase = "bl";
    call_pc = selected_lr - 4;
    error = tcg_debug_read_cached_ram(cs, call_pc, raw_bl,
                                      sizeof(raw_bl), true);
    if (error) {
        result = error;
        goto report;
    }
    bl = ldl_le_p(raw_bl);
    if ((bl & 0xfc000000) != 0x94000000) {
        result = "not_bl";
        goto report;
    }
    if (bl != selected_words[14]) {
        result = "bl_changed";
        goto report;
    }
    displacement = bl & 0x03ffffff;
    if (displacement & (INT64_C(1) << 25)) {
        displacement -= INT64_C(1) << 26;
    }
    displacement *= 4;
    phase = "destination";
    if (!macpad_cal_add_signed(call_pc, displacement, &destination) ||
        !destination || (destination & 3) ||
        (destination >= selected_lr - 0x3c &&
         destination < selected_lr + 4)) {
        result = "destination_invalid";
        goto report;
    }

    phase = "entry";
    error = tcg_debug_read_cached_ram(cs, destination, entry,
                                      sizeof(entry), true);
    if (error) {
        result = error;
        goto report;
    }
    for (unsigned int i = 0; i < MACPAD_CAL_ENTRY_WORDS; i++) {
        entry[i] = le32_to_cpu(entry[i]);
    }
    result = "captured";
    captured = true;

report:
    error_report(
        "%s result=%s phase=%s design=ipa8-cal2 base=e4d5bbc "
        "read_mode=cached_tlb host_us=%" PRId64
        " cpu=%d psci_pc=0x%" PRIx64
        " frames=%d matches=%u read_failures=%u last_reject=%s "
        "frame=%d raw_lr=0x%" PRIx64 " call_pc=0x%" PRIx64
        " bl=%08" PRIx32 " destination=0x%" PRIx64
        " bytes=%u identity=unverified",
        tag, result, phase, host_us, cs->cpu_index, env->pc,
        frame_count, matches, read_failures, last_reject,
        selected_index, selected_lr, call_pc, bl, destination,
        captured ? (unsigned int)sizeof(entry) : 0U);
    if (matches == 1) {
        macpad_cal_format_words(caller_hex, selected_words, 16);
        error_report("%s phase=caller start=0x%" PRIx64
                     " bytes=64 words=%s",
                     tag, selected_lr - 0x3c, caller_hex);
    }
    if (captured) {
        macpad_cal_format_words(entry_hex, entry, MACPAD_CAL_ENTRY_WORDS);
        error_report("%s phase=entry start=0x%" PRIx64
                     " bytes=192 words=%s", tag, destination, entry_hex);
    }
}

bool arm_is_psci_call(ARMCPU *cpu, int excp_type)
{
    /*
     * Return true if the exception type matches the configured PSCI conduit.
     * This is called before the SMC/HVC instruction is executed, to decide
     * whether we should treat it as a PSCI call or with the architecturally
     * defined behaviour for an SMC or HVC (which might be UNDEF or trap
     * to EL2 or to EL3).
     */

    switch (excp_type) {
    case EXCP_HVC:
        if (cpu->psci_conduit != QEMU_PSCI_CONDUIT_HVC) {
            return false;
        }
        break;
    case EXCP_SMC:
        if (cpu->psci_conduit != QEMU_PSCI_CONDUIT_SMC) {
            return false;
        }
        break;
    default:
        return false;
    }

    return true;
}

void arm_handle_psci_call(ARMCPU *cpu)
{
    /*
     * This function partially implements the logic for dispatching Power State
     * Coordination Interface (PSCI) calls (as described in ARM DEN 0022D.b),
     * to the extent required for bringing up and taking down secondary cores,
     * and for handling reset and poweroff requests.
     * Additional information about the calling convention used is available in
     * the document 'SMC Calling Convention' (ARM DEN 0028)
     */
    CPUARMState *env = &cpu->env;
    uint64_t param[4];
    uint64_t context_id, mpidr;
    uint64_t entry;
    int32_t ret = 0;
    int i;

    for (i = 0; i < 4; i++) {
        /*
         * All PSCI functions take explicit 32-bit or native int sized
         * arguments so we can simply zero-extend all arguments regardless
         * of which exact function we are about to call.
         */
        param[i] = is_a64(env) ? env->xregs[i] : env->regs[i];
    }
    trace_arm_psci_call(param[0], param[1], param[2], param[3],
                        arm_cpu_mp_affinity(cpu));

    if ((param[0] & QEMU_PSCI_0_2_64BIT) && !is_a64(env)) {
        ret = QEMU_PSCI_RET_NOT_SUPPORTED;
        goto err;
    }

    switch (param[0]) {
        CPUState *target_cpu_state;
        ARMCPU *target_cpu;

    case QEMU_PSCI_0_2_FN_PSCI_VERSION:
        ret = QEMU_PSCI_VERSION_1_1;
        break;
    case QEMU_PSCI_0_2_FN_MIGRATE_INFO_TYPE:
        ret = QEMU_PSCI_0_2_RET_TOS_MIGRATION_NOT_REQUIRED; /* No trusted OS */
        break;
    case QEMU_PSCI_0_2_FN_AFFINITY_INFO:
    case QEMU_PSCI_0_2_FN64_AFFINITY_INFO:
        mpidr = param[1];

        switch (param[2]) {
        case 0:
            target_cpu_state = arm_get_cpu_by_id(mpidr);
            if (!target_cpu_state) {
                ret = QEMU_PSCI_RET_INVALID_PARAMS;
                break;
            }
            target_cpu = ARM_CPU(target_cpu_state);

            g_assert(bql_locked());
            ret = target_cpu->power_state;
            break;
        default:
            /* Everything above affinity level 0 is always on. */
            ret = 0;
        }
        break;
    case QEMU_PSCI_0_2_FN_SYSTEM_RESET:
    {
        uint64_t fp = env->xregs[29];
        uint64_t lr = env->xregs[30];
        uint64_t sp = env->xregs[31];
        uint64_t frame_at[12] = { 0 };
        uint64_t frame_next[12] = { 0 };
        uint64_t frame_lr[12] = { 0 };
        int frame_count = 0;
        const char *frame_stop = "initial_invalid";

        /*
         * DEBUG: Capture a bounded best-effort AArch64 frame chain at the
         * instant the guest requests PSCI SYSTEM_RESET.
         *
         * Do not modify or canonicalize/PAC-strip guest addresses here.
         * Raw values are more useful for post-run comparison.
         *
         * Stop rather than guess if the chain becomes unreadable, unaligned,
         * non-increasing, or makes an implausibly large jump. This is an
         * observer only; it must never change reset behaviour.
         */
        if (is_a64(env) &&
            fp != 0 &&
            (fp & 0xf) == 0 &&
            fp >= sp &&
            fp - sp <= (1ULL << 20)) {
            uint64_t walk_fp = fp;

            frame_stop = "max_frames";
            for (int i = 0; i < 12; i++) {
                uint64_t pair[2] = { 0, 0 };

                if (cpu_memory_rw_debug(
                        CPU(cpu), walk_fp, pair, sizeof(pair), false) != 0) {
                    frame_stop = "read_fail";
                    break;
                }

                frame_at[i] = walk_fp;
                frame_next[i] = pair[0];
                frame_lr[i] = pair[1];
                frame_count++;

                if (pair[0] == 0) {
                    frame_stop = "zero";
                    break;
                }
                if ((pair[0] & 0xf) != 0) {
                    frame_stop = "unaligned";
                    break;
                }
                if (pair[0] <= walk_fp) {
                    frame_stop = "non_increasing";
                    break;
                }
                if (pair[0] - walk_fp > (1ULL << 20)) {
                    frame_stop = "jump_limit";
                    break;
                }

                walk_fp = pair[0];
            }
        }

        error_report(
            "MACPAD_RESET_TRACE stage=psci_system_reset "
            "cpu=%d pc=0x%" PRIx64 " smc_pc=0x%" PRIx64 " el=%d "
            "sp=0x%" PRIx64 " fp=0x%" PRIx64 " lr=0x%" PRIx64 " "
            "frame_count=%d frame_stop=%s "
            "x0=0x%" PRIx64 " x1=0x%" PRIx64
            " x2=0x%" PRIx64 " x3=0x%" PRIx64,
            CPU(cpu)->cpu_index,
            env->pc,
            env->pc - 4,
            arm_current_el(env),
            sp, fp, lr,
            frame_count, frame_stop,
            param[0], param[1], param[2], param[3]);

        for (int i = 0; i < frame_count; i++) {
            error_report(
                "MACPAD_RESET_FRAME index=%d at_fp=0x%" PRIx64
                " next_fp=0x%" PRIx64 " lr=0x%" PRIx64,
                i, frame_at[i], frame_next[i], frame_lr[i]);
        }


        /*
         * MACPAD: Read-only executable fingerprints at the final guest reset.
         * One HVC site plus the saved frame return addresses.
         * This runs only after the guest has requested SYSTEM_RESET.
         */
        for (int probe_index = -1;
             probe_index < frame_count;
             probe_index++) {
            uint64_t probe = probe_index < 0
                ? env->pc - 4
                : frame_lr[probe_index];
            uint32_t words[8] = { 0 };
            int rc = -1;

            if (probe >= 16 && (probe & 3) == 0) {
                rc = cpu_memory_rw_debug(
                    CPU(cpu), probe - 16,
                    words, sizeof(words), false);
            }

            if (rc != 0) {
                error_report(
                    "MACPAD_RESET_CODE index=%d addr=0x%" PRIx64
                    " read_fail=%d",
                    probe_index, probe, rc);
                continue;
            }

            error_report(
                "MACPAD_RESET_CODE index=%d addr=0x%" PRIx64
                " window_start=0x%" PRIx64
                " words=%08" PRIx32 " %08" PRIx32
                " %08" PRIx32 " %08" PRIx32
                " %08" PRIx32 " %08" PRIx32
                " %08" PRIx32 " %08" PRIx32,
                probe_index, probe, probe - 16,
                words[0], words[1], words[2], words[3],
                words[4], words[5], words[6], words[7]);
        }

        macpad_calibrate_restart(cpu, frame_lr, frame_count);

#ifdef CONFIG_TCG
        arm_ipa9_log_reset_summary(env);
#endif
        qemu_system_reset_request(SHUTDOWN_CAUSE_GUEST_RESET);
        /* QEMU reset and shutdown are async requests, but PSCI
         * mandates that we never return from the reset/shutdown
         * call, so power the CPU off now so it doesn't execute
         * anything further.
         */
        goto cpu_off;
    }
    case QEMU_PSCI_0_2_FN_SYSTEM_OFF:
        qemu_system_shutdown_request(SHUTDOWN_CAUSE_GUEST_SHUTDOWN);
        goto cpu_off;
    case QEMU_PSCI_0_1_FN_CPU_ON:
    case QEMU_PSCI_0_2_FN_CPU_ON:
    case QEMU_PSCI_0_2_FN64_CPU_ON:
    {
        /* The PSCI spec mandates that newly brought up CPUs start
         * in the highest exception level which exists and is enabled
         * on the calling CPU. Since the QEMU PSCI implementation is
         * acting as a "fake EL3" or "fake EL2" firmware, this for us
         * means that we want to start at the highest NS exception level
         * that we are providing to the guest.
         * The execution mode should be that which is currently in use
         * by the same exception level on the calling CPU.
         * The CPU should be started with the context_id value
         * in x0 (if AArch64) or r0 (if AArch32).
         */
        int target_el = arm_feature(env, ARM_FEATURE_EL2) ? 2 : 1;
        bool target_aarch64 = arm_el_is_aa64(env, target_el);

        mpidr = param[1];
        entry = param[2];
        context_id = param[3];
        ret = arm_set_cpu_on(mpidr, entry, context_id,
                             target_el, target_aarch64);
        break;
    }
    case QEMU_PSCI_0_1_FN_CPU_OFF:
    case QEMU_PSCI_0_2_FN_CPU_OFF:
        goto cpu_off;
    case QEMU_PSCI_0_1_FN_CPU_SUSPEND:
    case QEMU_PSCI_0_2_FN_CPU_SUSPEND:
    case QEMU_PSCI_0_2_FN64_CPU_SUSPEND:
        /* Affinity levels are not supported in QEMU */
        if (param[1] & 0xfffe0000) {
            ret = QEMU_PSCI_RET_INVALID_PARAMS;
            break;
        }
        /* Powerdown is not supported, we always go into WFI */
        if (is_a64(env)) {
            env->xregs[0] = 0;
        } else {
            env->regs[0] = 0;
        }
        helper_wfi(env, 4);
        break;
    case QEMU_PSCI_1_0_FN_PSCI_FEATURES:
        switch (param[1]) {
        case QEMU_PSCI_0_2_FN_PSCI_VERSION:
        case QEMU_PSCI_0_2_FN_MIGRATE_INFO_TYPE:
        case QEMU_PSCI_0_2_FN_AFFINITY_INFO:
        case QEMU_PSCI_0_2_FN64_AFFINITY_INFO:
        case QEMU_PSCI_0_2_FN_SYSTEM_RESET:
        case QEMU_PSCI_0_2_FN_SYSTEM_OFF:
        case QEMU_PSCI_0_1_FN_CPU_ON:
        case QEMU_PSCI_0_2_FN_CPU_ON:
        case QEMU_PSCI_0_2_FN64_CPU_ON:
        case QEMU_PSCI_0_1_FN_CPU_OFF:
        case QEMU_PSCI_0_2_FN_CPU_OFF:
        case QEMU_PSCI_0_1_FN_CPU_SUSPEND:
        case QEMU_PSCI_0_2_FN_CPU_SUSPEND:
        case QEMU_PSCI_0_2_FN64_CPU_SUSPEND:
        case QEMU_PSCI_1_0_FN_PSCI_FEATURES:
            if (!(param[1] & QEMU_PSCI_0_2_64BIT) || is_a64(env)) {
                ret = 0;
                break;
            }
            /* fallthrough */
        case QEMU_PSCI_0_1_FN_MIGRATE:
        case QEMU_PSCI_0_2_FN_MIGRATE:
        default:
            ret = QEMU_PSCI_RET_NOT_SUPPORTED;
            break;
        }
        break;
    case QEMU_PSCI_0_1_FN_MIGRATE:
    case QEMU_PSCI_0_2_FN_MIGRATE:
    default:
        ret = QEMU_PSCI_RET_NOT_SUPPORTED;
        break;
    }

err:
    if (is_a64(env)) {
        env->xregs[0] = ret;
    } else {
        env->regs[0] = ret;
    }
    return;

cpu_off:
    ret = arm_set_cpu_off(arm_cpu_mp_affinity(cpu));
    /* notreached */
    /* sanity check in case something failed */
    assert(ret == QEMU_ARM_POWERCTL_RET_SUCCESS);
}
