/*
 * vhost_scsi host device
 *
 * Copyright IBM, Corp. 2011
 *
 * Authors:
 *  Stefan Hajnoczi   <stefanha@linux.vnet.ibm.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2 or later.
 * See the COPYING.LIB file in the top-level directory.
 *
 */

#include <sys/ioctl.h>
#include "config.h"
#include "qemu-queue.h"
#include "vhost-scsi.h"
#include "vhost.h"

struct VHostSCSI {
    const char *id;
    const char *wwpn;
    uint16_t tpgt;
    struct vhost_dev dev;
    struct vhost_virtqueue vqs[3];
    QLIST_ENTRY(VHostSCSI) list;
};

static QLIST_HEAD(, VHostSCSI) vhost_scsi_list =
    QLIST_HEAD_INITIALIZER(vhost_scsi_list);

VHostSCSI *find_vhost_scsi(const char *id)
{
    VHostSCSI *vs;

    QLIST_FOREACH(vs, &vhost_scsi_list, list) {
        if (strcmp(id, vs->id) == 0) {
            return vs;
        }
    }
    return NULL;
}

const char *vhost_scsi_get_id(VHostSCSI *vs)
{
    return vs->id;
}

int vhost_scsi_start(VHostSCSI *vs, VirtIODevice *vdev)
{
    int ret;
    struct vhost_vring_target backend;

    if (!vhost_dev_query(&vs->dev, vdev)) {
        return -ENOTSUP;
    }

    vs->dev.nvqs = 3;
    vs->dev.vqs = vs->vqs;
    ret = vhost_dev_start(&vs->dev, vdev);
    if (ret < 0) {
        return ret;
    }

    pstrcpy((char *)backend.vhost_wwpn, sizeof(backend.vhost_wwpn), vs->wwpn);
    backend.vhost_tpgt = vs->tpgt;
    ret = ioctl(vs->dev.control, VHOST_SCSI_SET_ENDPOINT, &backend);
    if (ret < 0) {
        ret = -errno;
        vhost_dev_stop(&vs->dev, vdev);
        return ret;
    }

    fprintf(stderr, "vhost_scsi_start\n");
    return 0;
}

void vhost_scsi_stop(VHostSCSI *vs, VirtIODevice *vdev)
{
    fprintf(stderr, "vhost_scsi_stop\n");
    /* TODO clear wwpn and tpgt */

    vhost_dev_stop(&vs->dev, vdev);
}

static VHostSCSI *vhost_scsi_add(const char *id, const char *wwpn,
                                 uint16_t tpgt)
{
    VHostSCSI *vs = g_malloc0(sizeof(*vs));
    int ret;

    /* TODO set up vhost-scsi device and bind to tcm_vhost/$wwpm/tpgt_$tpgt */
    fprintf(stderr, "wwpn = \"%s\" tpgt = \"%u\"\n", id, tpgt);

    ret = vhost_dev_init(&vs->dev, -1, "/dev/vhost-scsi", false);
    if (ret < 0) {
        fprintf(stderr, "vhost-scsi: vhost initialization failed: %s\n",
                strerror(-ret));
        return NULL;
    }
    vs->dev.backend_features = 0;
    vs->dev.acked_features = 0;

    vs->id = g_strdup(id);
    vs->wwpn = g_strdup(wwpn);
    vs->tpgt = tpgt;
    QLIST_INSERT_HEAD(&vhost_scsi_list, vs, list);

    return vs;
}

VHostSCSI *vhost_scsi_add_opts(QemuOpts *opts)
{
    const char *id;
    const char *wwpn;
    uint64_t tpgt;

    id = qemu_opts_id(opts);
    if (!id) {
        fprintf(stderr, "vhost-scsi: no id specified\n");
        return NULL;
    }
    if (find_vhost_scsi(id)) {
        fprintf(stderr, "duplicate vhost-scsi: \"%s\"\n", id);
        return NULL;
    }

    wwpn = qemu_opt_get(opts, "wwpn");
    if (!wwpn) {
        fprintf(stderr, "vhost-scsi: \"%s\" missing wwpn\n", id);
        return NULL;
    }

    tpgt = qemu_opt_get_number(opts, "tpgt", UINT64_MAX);
    if (tpgt > UINT16_MAX) {
        fprintf(stderr, "vhost-scsi: \"%s\" needs a 16-bit tpgt\n", id);
        return NULL;
    }

    return vhost_scsi_add(id, wwpn, tpgt);
}
