/*
 * QEMU simulated pvpanic device.
 *
 * Copyright Fujitsu, Corp. 2013
 *
 * Authors:
 *     Wen Congyang <wency@cn.fujitsu.com>
 *     Hu Tao <hutao@cn.fujitsu.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "qemu/error-report.h"
#include "system/runstate.h"

#include "hw/nvram/fw_cfg.h"
#include "hw/core/qdev-properties.h"
#include "hw/misc/pvpanic.h"
#include "qom/object.h"
#include "standard-headers/misc/pvpanic.h"

static void handle_event(int event)
{
    static bool logged;

    if (event & ~PVPANIC_EVENTS && !logged) {
        qemu_log_mask(LOG_GUEST_ERROR, "pvpanic: unknown event %#x.\n", event);
        logged = true;
    }

    if (event & PVPANIC_PANICKED) {
        qemu_system_guest_panicked(NULL);
        return;
    }

    if (event & PVPANIC_CRASH_LOADED) {
        qemu_system_guest_crashloaded(NULL);
        return;
    }

    if (event & PVPANIC_SHUTDOWN) {
        qemu_system_guest_pvshutdown();
        return;
    }
}

/* return supported events on read */
static uint64_t pvpanic_read(void *opaque, hwaddr addr, unsigned size)
{
    PVPanicState *pvp = opaque;
    static bool macpad_capability_logged;

    if (!macpad_capability_logged) {
        error_report(
            "MACPAD_PVPANIC_CAP supported=0x%x "
            "panicked=%d crash_loaded=%d shutdown=%d",
            pvp->events,
            !!(pvp->events & PVPANIC_PANICKED),
            !!(pvp->events & PVPANIC_CRASH_LOADED),
            !!(pvp->events & PVPANIC_SHUTDOWN));
        macpad_capability_logged = true;
    }

    return pvp->events;
}

static void pvpanic_write(void *opaque, hwaddr addr, uint64_t val,
                                 unsigned size)
{
    PVPanicState *pvp = opaque;

    error_report(
        "MACPAD_PVPANIC_EVENT value=0x%" PRIx64 " supported=0x%x "
        "panicked=%d crash_loaded=%d shutdown=%d",
        val,
        pvp->events,
        !!(val & PVPANIC_PANICKED),
        !!(val & PVPANIC_CRASH_LOADED),
        !!(val & PVPANIC_SHUTDOWN));

    handle_event(val);
}

static const MemoryRegionOps pvpanic_ops = {
    .endianness = DEVICE_LITTLE_ENDIAN,
    .read = pvpanic_read,
    .write = pvpanic_write,
    .impl = {
        .min_access_size = 1,
        .max_access_size = 1,
    },
};

void pvpanic_setup_io(PVPanicState *s, DeviceState *dev, unsigned size)
{
    memory_region_init_io(&s->mr, OBJECT(dev), &pvpanic_ops, s, "pvpanic", size);
}
