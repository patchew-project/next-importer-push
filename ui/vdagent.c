#include "qemu/osdep.h"
#include "include/qemu-common.h"
#include "chardev/char.h"
#include "trace.h"

#include "qapi/qapi-types-char.h"

#include "spice/vd_agent.h"

#define MSGSIZE_MAX (sizeof(VDIChunkHeader) + \
                     sizeof(VDAgentMessage) + \
                     VD_AGENT_MAX_DATA_SIZE)

struct VDAgentChardev {
    Chardev parent;

    /* guest vdagent */
    uint32_t caps;
    uint8_t msgbuf[MSGSIZE_MAX];
    uint32_t msgsize;
};
typedef struct VDAgentChardev VDAgentChardev;

#define TYPE_CHARDEV_VDAGENT "chardev-vdagent"

DECLARE_INSTANCE_CHECKER(VDAgentChardev, VDAGENT_CHARDEV,
                         TYPE_CHARDEV_VDAGENT);

/* ------------------------------------------------------------------ */
/* names, for debug logging                                           */

static const char *cap_name[] = {
    [VD_AGENT_CAP_MOUSE_STATE]                    = "mouse-state",
    [VD_AGENT_CAP_MONITORS_CONFIG]                = "monitors-config",
    [VD_AGENT_CAP_REPLY]                          = "reply",
    [VD_AGENT_CAP_CLIPBOARD]                      = "clipboard",
    [VD_AGENT_CAP_DISPLAY_CONFIG]                 = "display-config",
    [VD_AGENT_CAP_CLIPBOARD_BY_DEMAND]            = "clipboard-by-demand",
    [VD_AGENT_CAP_CLIPBOARD_SELECTION]            = "clipboard-selection",
    [VD_AGENT_CAP_SPARSE_MONITORS_CONFIG]         = "sparse-monitors-config",
    [VD_AGENT_CAP_GUEST_LINEEND_LF]               = "guest-lineend-lf",
    [VD_AGENT_CAP_GUEST_LINEEND_CRLF]             = "guest-lineend-crlf",
    [VD_AGENT_CAP_MAX_CLIPBOARD]                  = "max-clipboard",
    [VD_AGENT_CAP_AUDIO_VOLUME_SYNC]              = "audio-volume-sync",
    [VD_AGENT_CAP_MONITORS_CONFIG_POSITION]       = "monitors-config-position",
    [VD_AGENT_CAP_FILE_XFER_DISABLED]             = "file-xfer-disabled",
    [VD_AGENT_CAP_FILE_XFER_DETAILED_ERRORS]      = "file-xfer-detailed-errors",
#if 0
    [VD_AGENT_CAP_GRAPHICS_DEVICE_INFO]           = "graphics-device-info",
    [VD_AGENT_CAP_CLIPBOARD_NO_RELEASE_ON_REGRAB] = "clipboard-no-release-on-regrab",
    [VD_AGENT_CAP_CLIPBOARD_GRAB_SERIAL]          = "clipboard-grab-serial",
#endif
};

static const char *msg_name[] = {
    [VD_AGENT_MOUSE_STATE]           = "mouse-state",
    [VD_AGENT_MONITORS_CONFIG]       = "monitors-config",
    [VD_AGENT_REPLY]                 = "reply",
    [VD_AGENT_CLIPBOARD]             = "clipboard",
    [VD_AGENT_DISPLAY_CONFIG]        = "display-config",
    [VD_AGENT_ANNOUNCE_CAPABILITIES] = "announce-capabilities",
    [VD_AGENT_CLIPBOARD_GRAB]        = "clipboard-grab",
    [VD_AGENT_CLIPBOARD_REQUEST]     = "clipboard-request",
    [VD_AGENT_CLIPBOARD_RELEASE]     = "clipboard-release",
    [VD_AGENT_FILE_XFER_START]       = "file-xfer-start",
    [VD_AGENT_FILE_XFER_STATUS]      = "file-xfer-status",
    [VD_AGENT_FILE_XFER_DATA]        = "file-xfer-data",
    [VD_AGENT_CLIENT_DISCONNECTED]   = "client-disconnected",
    [VD_AGENT_MAX_CLIPBOARD]         = "max-clipboard",
    [VD_AGENT_AUDIO_VOLUME_SYNC]     = "audio-volume-sync",
#if 0
    [VD_AGENT_GRAPHICS_DEVICE_INFO]  = "graphics-device-info",
#endif
};

#define GET_NAME(_m, _v) \
    (((_v) < ARRAY_SIZE(_m) && (_m[_v])) ? (_m[_v]) : "???")

/* ------------------------------------------------------------------ */
/* send messages                                                      */

static void vdagent_send_buf(VDAgentChardev *vd, void *ptr, uint32_t msgsize)
{
    uint8_t *msgbuf = ptr;
    uint32_t len, pos = 0;

    while (pos < msgsize) {
        len = qemu_chr_be_can_write(CHARDEV(vd));
        if (len > msgsize - pos) {
            len = msgsize - pos;
        }
        qemu_chr_be_write(CHARDEV(vd), msgbuf + pos, len);
        pos += len;
    }
}

static void vdagent_send_msg(VDAgentChardev *vd, VDAgentMessage *msg)
{
    uint8_t *msgbuf = (void *)msg;
    uint32_t msgsize = sizeof(VDAgentMessage) + msg->size;
    VDIChunkHeader chunk;

    trace_vdagent_send(GET_NAME(msg_name, msg->type));

    chunk.port = VDP_CLIENT_PORT;
    chunk.size = msgsize;
    vdagent_send_buf(vd, &chunk, sizeof(chunk));

    msg->protocol = VD_AGENT_PROTOCOL;
    vdagent_send_buf(vd, msgbuf, msgsize);
    g_free(msg);
}

static void vdagent_send_caps(VDAgentChardev *vd)
{
    VDAgentMessage *msg = g_malloc0(sizeof(VDAgentMessage) +
                                    sizeof(VDAgentAnnounceCapabilities) +
                                    sizeof(uint32_t));

    msg->type = VD_AGENT_ANNOUNCE_CAPABILITIES;
    msg->size = sizeof(VDAgentAnnounceCapabilities) + sizeof(uint32_t);

    vdagent_send_msg(vd, msg);
}

/* ------------------------------------------------------------------ */
/* chardev backend                                                    */

static void vdagent_chr_open(Chardev *chr,
                             ChardevBackend *backend,
                             bool *be_opened,
                             Error **errp)
{
    *be_opened = true;
}

static void vdagent_chr_recv_caps(VDAgentChardev *vd, VDAgentMessage *msg)
{
    VDAgentAnnounceCapabilities *caps = (void *)msg->data;
    int i;

    for (i = 0; i < ARRAY_SIZE(cap_name); i++) {
        if (caps->caps[0] & (1 << i)) {
            trace_vdagent_peer_cap(GET_NAME(cap_name, i));
        }
    }

    vd->caps = caps->caps[0];
    if (caps->request) {
        vdagent_send_caps(vd);
    }
}

static uint32_t vdagent_chr_recv(VDAgentChardev *vd)
{
    VDIChunkHeader *chunk = (void *)vd->msgbuf;
    VDAgentMessage *msg = (void *)vd->msgbuf + sizeof(VDIChunkHeader);

    if (sizeof(VDIChunkHeader) + chunk->size > vd->msgsize) {
        return 0;
    }

    trace_vdagent_recv(GET_NAME(msg_name, msg->type));

    switch (msg->type) {
    case VD_AGENT_ANNOUNCE_CAPABILITIES:
        vdagent_chr_recv_caps(vd, msg);
        break;
    default:
        break;
    }

    return sizeof(VDIChunkHeader) + chunk->size;
}

static int vdagent_chr_write(Chardev *chr, const uint8_t *buf, int len)
{
    VDAgentChardev *vd = VDAGENT_CHARDEV(chr);
    uint32_t copy, move;

    copy = MSGSIZE_MAX - vd->msgsize;
    if (copy > len) {
        copy = len;
    }

    memcpy(vd->msgbuf + vd->msgsize, buf, copy);
    vd->msgsize += copy;

    while (vd->msgsize > sizeof(VDIChunkHeader)) {
        move = vdagent_chr_recv(vd);
        if (move == 0) {
            break;
        }

        memmove(vd->msgbuf, vd->msgbuf + move, vd->msgsize - move);
        vd->msgsize -= move;
    }

    return copy;
}

static void vdagent_chr_set_fe_open(struct Chardev *chr, int fe_open)
{
    VDAgentChardev *vd = VDAGENT_CHARDEV(chr);

    if (!fe_open) {
        trace_vdagent_close();
        /* reset state */
        vd->msgsize = 0;
        vd->caps = 0;
        return;
    }

    trace_vdagent_open();
}

/* ------------------------------------------------------------------ */

static void vdagent_chr_class_init(ObjectClass *oc, void *data)
{
    ChardevClass *cc = CHARDEV_CLASS(oc);

    cc->open             = vdagent_chr_open;
    cc->chr_write        = vdagent_chr_write;
    cc->chr_set_fe_open  = vdagent_chr_set_fe_open;
}

static const TypeInfo vdagent_chr_type_info = {
    .name = TYPE_CHARDEV_VDAGENT,
    .parent = TYPE_CHARDEV,
    .instance_size = sizeof(VDAgentChardev),
    .class_init = vdagent_chr_class_init,
};

static void register_types(void)
{
    type_register_static(&vdagent_chr_type_info);
}

type_init(register_types);
