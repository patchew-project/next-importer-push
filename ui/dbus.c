/*
 * QEMU DBus display
 *
 * Copyright (c) 2021 Marc-André Lureau <marcandre.lureau@redhat.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include "qemu/osdep.h"
#include "qemu/dbus.h"
#include "qemu/option.h"
#include "qom/object_interfaces.h"
#include "sysemu/sysemu.h"
#include "ui/egl-helpers.h"
#include "ui/egl-context.h"
#include "qapi/error.h"
#include "trace.h"

#include "dbus.h"

static QEMUGLContext dbus_create_context(DisplayGLCtx *dgc,
                                         QEMUGLParams *params)
{
    eglMakeCurrent(qemu_egl_display, EGL_NO_SURFACE, EGL_NO_SURFACE,
                   qemu_egl_rn_ctx);
    return qemu_egl_create_context(dgc, params);
}

static const DisplayGLCtxOps dbus_gl_ops = {
    .compatible_dcl          = &dbus_gl_dcl_ops,
    .dpy_gl_ctx_create       = dbus_create_context,
    .dpy_gl_ctx_destroy      = qemu_egl_destroy_context,
    .dpy_gl_ctx_make_current = qemu_egl_make_context_current,
};

static void
dbus_display_init(Object *o)
{
    DBusDisplay *self = DBUS_DISPLAY(o);
    g_autoptr(GDBusObjectSkeleton) vm = NULL;

    self->glctx.ops = &dbus_gl_ops;
    self->iface = dbus_display_display1_vm_skeleton_new();
    self->consoles = g_ptr_array_new_with_free_func(g_object_unref);

    self->server = g_dbus_object_manager_server_new(DBUS_DISPLAY1_ROOT);

    vm = g_dbus_object_skeleton_new(DBUS_DISPLAY1_ROOT "/VM");
    g_dbus_object_skeleton_add_interface(vm, G_DBUS_INTERFACE_SKELETON(self->iface));
    g_dbus_object_manager_server_export(self->server, vm);
}

static void
dbus_display_finalize(Object *o)
{
    DBusDisplay *self = DBUS_DISPLAY(o);

    g_clear_object(&self->server);
    g_clear_pointer(&self->consoles, g_ptr_array_unref);
    g_clear_object(&self->bus);
    g_clear_object(&self->iface);
    g_free(self->dbus_addr);
}

static bool
dbus_display_add_console(DBusDisplay *self, int idx, Error **errp)
{
    QemuConsole *con;
    DBusDisplayConsole *dbus_console;

    con = qemu_console_lookup_by_index(idx);
    assert(con);

    if (qemu_console_is_graphic(con) &&
        self->gl_mode != DISPLAYGL_MODE_OFF) {
        qemu_console_set_display_gl_ctx(con, &self->glctx);
    }

    dbus_console = dbus_display_console_new(self, con);
    g_ptr_array_insert(self->consoles, idx, dbus_console);
    g_dbus_object_manager_server_export(self->server,
                                        G_DBUS_OBJECT_SKELETON(dbus_console));
    return true;
}

static void
dbus_display_complete(UserCreatable *uc, Error **errp)
{
    DBusDisplay *self = DBUS_DISPLAY(uc);
    g_autoptr(GError) err = NULL;
    g_autofree char *uuid = qemu_uuid_unparse_strdup(&qemu_uuid);
    g_autoptr(GArray) consoles = NULL;
    GVariant *console_ids;
    int idx;

    if (!object_resolve_path_type("", TYPE_DBUS_DISPLAY, NULL)) {
        error_setg(errp, "There is already an instance of %s",
                   TYPE_DBUS_DISPLAY);
        return;
    }

    if (self->dbus_addr && *self->dbus_addr) {
        self->bus = g_dbus_connection_new_for_address_sync(self->dbus_addr,
                        G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT |
                        G_DBUS_CONNECTION_FLAGS_MESSAGE_BUS_CONNECTION,
                        NULL, NULL, &err);
    } else {
        self->bus = g_bus_get_sync(G_BUS_TYPE_SESSION, NULL, &err);
    }
    if (err) {
        error_setg(errp, "failed to connect to DBus: %s", err->message);
        return;
    }


    consoles = g_array_new(FALSE, FALSE, sizeof(guint32));
    for (idx = 0;; idx++) {
        if (!qemu_console_lookup_by_index(idx)) {
            break;
        }
        if (!dbus_display_add_console(self, idx, errp)) {
            return;
        }
        g_array_append_val(consoles, idx);
    }

    console_ids = g_variant_new_from_data(G_VARIANT_TYPE("au"),
                                          consoles->data, consoles->len * sizeof(guint32), TRUE,
                                          (GDestroyNotify)g_array_unref, consoles);
    g_steal_pointer(&consoles);
    g_object_set(self->iface,
                 "name", qemu_name ?: "QEMU " QEMU_VERSION,
                 "uuid", uuid,
                 "console-ids", console_ids,
                 NULL);

    g_dbus_object_manager_server_set_connection(self->server, self->bus);
    g_bus_own_name_on_connection(self->bus, "org.qemu", G_BUS_NAME_OWNER_FLAGS_NONE,
                                 NULL, NULL, NULL, NULL);
}

static char *
get_dbus_addr(Object *o, Error **errp)
{
    DBusDisplay *self = DBUS_DISPLAY(o);

    return g_strdup(self->dbus_addr);
}

static void
set_dbus_addr(Object *o, const char *str, Error **errp)
{
    DBusDisplay *self = DBUS_DISPLAY(o);

    g_free(self->dbus_addr);
    self->dbus_addr = g_strdup(str);
}

static int
get_gl_mode(Object *o, Error **errp)
{
    DBusDisplay *self = DBUS_DISPLAY(o);

    return self->gl_mode;
}

static void
set_gl_mode(Object *o, int val, Error **errp)
{
    DBusDisplay *self = DBUS_DISPLAY(o);

    self->gl_mode = val;
}

static void
dbus_display_class_init(ObjectClass *oc, void *data)
{
    UserCreatableClass *ucc = USER_CREATABLE_CLASS(oc);

    ucc->complete = dbus_display_complete;
    object_class_property_add_str(oc, "addr", get_dbus_addr, set_dbus_addr);
    object_class_property_add_enum(oc, "gl-mode",
                                   "DisplayGLMode", &DisplayGLMode_lookup,
                                   get_gl_mode, set_gl_mode);
}

static void
early_dbus_init(DisplayOptions *opts)
{
    DisplayGLMode mode = opts->has_gl ? opts->gl : DISPLAYGL_MODE_OFF;

    if (mode != DISPLAYGL_MODE_OFF) {
        if (egl_rendernode_init(opts->u.dbus.rendernode, mode) < 0) {
            error_report("dbus: render node init failed");
            exit(1);
        }

        display_opengl = 1;
    }
}

static void
dbus_init(DisplayState *ds, DisplayOptions *opts)
{
    DisplayGLMode mode = opts->has_gl ? opts->gl : DISPLAYGL_MODE_OFF;

    object_new_with_props(TYPE_DBUS_DISPLAY,
                          object_get_objects_root(),
                          "dbus-display", &error_fatal,
                          "addr", opts->u.dbus.addr ?: "",
                          "gl-mode", DisplayGLMode_str(mode),
                          NULL);
}

static const TypeInfo dbus_display_info = {
    .name = TYPE_DBUS_DISPLAY,
    .parent = TYPE_OBJECT,
    .instance_size = sizeof(DBusDisplay),
    .instance_init = dbus_display_init,
    .instance_finalize = dbus_display_finalize,
    .class_init = dbus_display_class_init,
    .interfaces = (InterfaceInfo[]) {
        { TYPE_USER_CREATABLE },
        { }
    }
};

static QemuDisplay qemu_display_dbus = {
    .type       = DISPLAY_TYPE_DBUS,
    .early_init = early_dbus_init,
    .init       = dbus_init,
};

static void register_dbus(void)
{
    type_register_static(&dbus_display_info);
    qemu_display_register(&qemu_display_dbus);
}

type_init(register_dbus);
