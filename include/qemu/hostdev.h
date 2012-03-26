/*
 * QEMU host device model
 *
 * Copyright IBM, Corp. 2012
 *
 * Authors:
 *  Zhi Yong Wu   <wuzhy@linux.vnet.ibm.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2 or later.
 * See the COPYING.LIB file in the top-level directory.
 *
 */

#ifndef QEMU_HOSTDEV_H
#define QEMU_HOSTDEV_H

#include "qemu-queue.h"
#include "qemu-char.h"
#include "qemu-option.h"
#include "qapi/qapi-visit-core.h"
#include "qemu/object.h"

typedef struct hostdevProperty hostdevProperty;
typedef struct hostdevPropertyInfo hostdevPropertyInfo;

/**
 * SECTION: hostdev
 * @section_id: QEMU-hostdev
 * @title: hostdev Class
 * @short_description: Base class for all host devices
 */

typedef struct HOSTDevice HOSTDevice;

#define TYPE_HOSTDEV "host-dev"
#define HOST_DEVICE(obj) \
     OBJECT_CHECK(HOSTDevice, (obj), TYPE_HOSTDEV)
#define HOSTDEV_CLASS(klass) \
     OBJECT_CLASS_CHECK(HOSTDeviceClass, (klass), TYPE_HOSTDEV)
#define HOSTDEV_GET_CLASS(obj) \
     OBJECT_GET_CLASS(HOSTDeviceClass, (obj), TYPE_HOSTDEV)

/**
 * HOSTDeviceClass:
 *
 * Represents a host device model.
 */
typedef struct HOSTDeviceClass {
    ObjectClass parent_class;
    hostdevProperty *props;

    int (*init)(HOSTDevice *host_dv);
} HOSTDeviceClass;

/**
 * HOSTDevice:
 *
 * State of one host device.
 */
struct HOSTDevice {
    /*< private >*/
    Object parent_obj;

    /*< public >*/
};

struct hostdevProperty {
    const char   *name;
    hostdevPropertyInfo *info;
    int          offset;
    uint8_t      bitnr;
    uint8_t      qtype;
    int64_t      defval;
};

struct hostdevPropertyInfo {
    const char *name;
    const char *legacy_name;
    const char **enum_table;
    int64_t min;
    int64_t max;
    int (*parse)(HOSTDevice *dev,
                 hostdevProperty *prop,
                 const char *str);
    int (*print)(HOSTDevice *dev,
                 hostdevProperty *prop,
                 char *dest,
                 size_t len);
    ObjectPropertyAccessor *get;
    ObjectPropertyAccessor *set;
    ObjectPropertyRelease *release;
};

extern hostdevPropertyInfo hostdev_prop_int32;
extern hostdevPropertyInfo hostdev_prop_string;
extern hostdevPropertyInfo hostdev_prop_netdev;

#define DEFINE_HOSTDEV_PROP(_name, _state, _field, _prop, _type) { \
        .name      = (_name),                                    \
        .info      = &(_prop),                                   \
        .offset    = offsetof(_state, _field)                    \
            + type_check(_type,typeof_field(_state, _field)),    \
        }
#define DEFINE_HOSTDEV_PROP_DEFAULT(_name, _state, _field, _defval, _prop, _type) { \
        .name      = (_name),                                           \
        .info      = &(_prop),                                          \
        .offset    = offsetof(_state, _field)                           \
            + type_check(_type,typeof_field(_state, _field)),           \
        .qtype     = QTYPE_QINT,                                        \
        .defval    = (_type)_defval,                                    \
        }
#define DEFINE_HOSTDEV_PROP_END_OF_LIST()               \
    {}
#define DEFINE_HOSTDEV_PROP_INT32(_n, _s, _f, _d)              \
    DEFINE_HOSTDEV_PROP_DEFAULT(_n, _s, _f, _d, hostdev_prop_int32, int32_t)
#define DEFINE_HOSTDEV_PROP_PEER(_n, _s, _f)             \
    DEFINE_HOSTDEV_PROP(_n, _s, _f, hostdev_prop_netdev, NetClientState*)
#define DEFINE_HOSTDEV_PROP_STRING(_n, _s, _f)             \
    DEFINE_HOSTDEV_PROP(_n, _s, _f, hostdev_prop_string, char*)

HOSTDevice *hostdev_device_create(const char *type);
int hostdev_device_init(HOSTDevice *dev, gchar *id);
void hostdev_prop_set_string(HOSTDevice *dev,
                             const char *name, char *value);
void hostdev_prop_set_peer(HOSTDevice *dev,
                           const char *name, NetClientState *value);

#endif
