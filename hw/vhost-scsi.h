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

#ifndef VHOST_SCSI_H
#define VHOST_SCSI_H

#include "qemu-common.h"
#include "qemu-option.h"

/* TODO #include <linux/vhost.h> properly */
/* For VHOST_SCSI_SET_ENDPOINT/VHOST_SCSI_CLEAR_ENDPOINT ioctl */
struct vhost_vring_target {
    unsigned char vhost_wwpn[224];
    unsigned short vhost_tpgt;
};

#define VHOST_VIRTIO 0xAF
#define VHOST_SCSI_SET_ENDPOINT _IOW(VHOST_VIRTIO, 0x40, struct vhost_vring_target)
#define VHOST_SCSI_CLEAR_ENDPOINT _IOW(VHOST_VIRTIO, 0x41, struct vhost_vring_target)

VHostSCSI *find_vhost_scsi(const char *id);
const char *vhost_scsi_get_id(VHostSCSI *vs);

VHostSCSI *vhost_scsi_add_opts(QemuOpts *opts);

int vhost_scsi_start(VHostSCSI *vs, VirtIODevice *vdev);
void vhost_scsi_stop(VHostSCSI *vs, VirtIODevice *vdev);

#endif
