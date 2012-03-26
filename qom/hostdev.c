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

#include "qemu/hostdev.h"
#include "qemu-common.h"
#include "net.h"

void hostdev_prop_set_string(HOSTDevice *dev,
                             const char *name, char *value)
{
    Error *errp = NULL;
    object_property_set_str(OBJECT(dev), value, name, &errp);
    assert_no_error(errp);
}

void hostdev_prop_set_peer(HOSTDevice *dev,
                           const char *name, NetClientState *value)
{
    Error *errp = NULL;
    assert(!value || value->name);
    object_property_set_str(OBJECT(dev),
                            value ? value->name : "", name, &errp);
    assert_no_error(errp);
}

static Object *hostdev_get_hostdev(void)
{
    static Object *dev;

    if (dev == NULL) {
        dev = object_new("container");
        object_property_add_child(object_get_root(), "hostdev",
                                  OBJECT(dev), NULL);
    }

    return dev;
}

HOSTDevice *hostdev_device_create(const char *type)
{
    HOSTDevice *hostdev;

    hostdev = HOST_DEVICE(object_new(type));
    if (!hostdev) {
        return NULL;
    }

    return hostdev;
}

int hostdev_device_init(HOSTDevice *dev, gchar *id)
{
    HOSTDeviceClass *dc = HOSTDEV_GET_CLASS(dev);
    int rc;

    rc = dc->init(dev);
    if (rc < 0) {
        object_delete(OBJECT(dev));
        return rc;
    }

    object_property_add_child(hostdev_get_hostdev(), id,
                              OBJECT(dev), NULL);
    g_free(id);

    return 0;
}

static void *hostdev_get_prop_ptr(HOSTDevice *dev, hostdevProperty *prop)
{
    void *ptr = dev;
    ptr += prop->offset;
    return ptr;
}

static void error_set_from_hostdev_prop_error(Error **errp, int ret,
                                              HOSTDevice *dev, hostdevProperty *prop,
                                              const char *value)
{
    switch (ret) {
    case -EEXIST:
        error_set(errp, QERR_PROPERTY_VALUE_IN_USE,
                  object_get_typename(OBJECT(dev)), prop->name, value);
        break;
    default:
    case -EINVAL:
        error_set(errp, QERR_PROPERTY_VALUE_BAD,
                  object_get_typename(OBJECT(dev)), prop->name, value);
        break;
    case -ENOENT:
        error_set(errp, QERR_PROPERTY_VALUE_NOT_FOUND,
                  object_get_typename(OBJECT(dev)), prop->name, value);
        break;
    case 0:
        break;
    }
}

/* --- netdev device --- */
static void get_pointer(Object *obj, Visitor *v, hostdevProperty *prop,
                        const char *(*print)(void *ptr),
                        const char *name, Error **errp)
{
    HOSTDevice *dev = HOST_DEVICE(obj);
    void **ptr = hostdev_get_prop_ptr(dev, prop);
    char *p;

    p = (char *) (*ptr ? print(*ptr) : "");
    visit_type_str(v, &p, name, errp);
}

static void set_pointer(Object *obj, Visitor *v, hostdevProperty *prop,
                        int (*parse)(HOSTDevice *dev, const char *str, void **ptr),
                        const char *name, Error **errp)
{
    HOSTDevice *dev = HOST_DEVICE(obj);
    Error *local_err = NULL;
    void **ptr = hostdev_get_prop_ptr(dev, prop);
    char *str;
    int ret;

    visit_type_str(v, &str, name, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        return;
    }
    if (!*str) {
        g_free(str);
        *ptr = NULL;
        return;
    }
    ret = parse(dev, str, ptr);
    error_set_from_hostdev_prop_error(errp, ret, dev, prop, str);
    g_free(str);
}

/* --- 32bit integer --- */
static void get_int32(Object *obj, Visitor *v, void *opaque,
                      const char *name, Error **errp)
{
    HOSTDevice *dev = HOST_DEVICE(obj);
    hostdevProperty *prop = opaque;
    int32_t *ptr = hostdev_get_prop_ptr(dev, prop);
    int64_t value;

    value = *ptr;
    visit_type_int(v, &value, name, errp);
}

static void set_int32(Object *obj, Visitor *v, void *opaque,
                      const char *name, Error **errp)
{
    HOSTDevice *dev = HOST_DEVICE(obj);
    hostdevProperty *prop = opaque;
    int32_t *ptr = hostdev_get_prop_ptr(dev, prop);
    Error *local_err = NULL;
    int64_t value;

    visit_type_int(v, &value, name, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        return;
    }
    if (value >= prop->info->min && value <= prop->info->max) {
        *ptr = value;
    } else {
        error_set(errp, QERR_PROPERTY_VALUE_OUT_OF_RANGE,
                  "", name, value, prop->info->min,
                  prop->info->max);
    }
}

hostdevPropertyInfo hostdev_prop_int32 = {
    .name  = "int32",
    .get   = get_int32,
    .set   = set_int32,
    .min   = -0x80000000LL,
    .max   = 0x7FFFFFFFLL,
};

/* --- netdev --- */
static int parse_netdev(HOSTDevice *dev, const char *str, void **ptr)
{
    NetClientState *netdev = qemu_find_netdev(str);

    if (netdev == NULL) {
        return -ENOENT;
    }
    if (netdev->peer) {
        return -EEXIST;
    }
    *ptr = netdev;
    return 0;
}

static const char *print_netdev(void *ptr)
{
    NetClientState *netdev = ptr;

    return netdev->name ? netdev->name : "";
}

static void get_netdev(Object *obj, Visitor *v, void *opaque,
                       const char *name, Error **errp)
{
    get_pointer(obj, v, opaque, print_netdev, name, errp);
}

static void set_netdev(Object *obj, Visitor *v, void *opaque,
                       const char *name, Error **errp)
{
    set_pointer(obj, v, opaque, parse_netdev, name, errp);
}

hostdevPropertyInfo hostdev_prop_netdev = {
    .name  = "peer",
    .get   = get_netdev,
    .set   = set_netdev,
};

/* --- string --- */
static void release_string(Object *obj, const char *name, void *opaque)
{
    hostdevProperty *prop = opaque;
    g_free(*(char **)hostdev_get_prop_ptr(HOST_DEVICE(obj), prop));
}

static void get_string(Object *obj, Visitor *v, void *opaque,
                       const char *name, Error **errp)
{
    HOSTDevice *dev = HOST_DEVICE(obj);
    hostdevProperty *prop = opaque;
    char **ptr = hostdev_get_prop_ptr(dev, prop);

    if (!*ptr) {
        char *str = (char *)"";
        visit_type_str(v, &str, name, errp);
    } else {
        visit_type_str(v, ptr, name, errp);
    }
}

static void set_string(Object *obj, Visitor *v, void *opaque,
                       const char *name, Error **errp)
{
    HOSTDevice *dev = HOST_DEVICE(obj);
    hostdevProperty *prop = opaque;
    char **ptr = hostdev_get_prop_ptr(dev, prop);
    Error *local_err = NULL;
    char *str;

    visit_type_str(v, &str, name, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        return;
    }
    if (*ptr) {
        g_free(*ptr);
    }
    *ptr = str;
}

hostdevPropertyInfo hostdev_prop_string = {
    .name  = "string",
    .release = release_string,
    .get   = get_string,
    .set   = set_string,
};

static char *hostdev_get_type(Object *obj, Error **errp)
{
    return g_strdup(object_get_typename(obj));
}

static void hostdev_property_add_static(HOSTDevice *dev, hostdevProperty *prop,
                                        Error **errp)
{
    if (!prop->info->get && !prop->info->set) {
        return;
    }

    object_property_add(OBJECT(dev), prop->name, prop->info->name,
                        prop->info->get, prop->info->set,
                        prop->info->release,
                        prop, errp);
}

static void hostdev_init(Object *obj)
{
    HOSTDevice *s = HOST_DEVICE(obj);
    HOSTDeviceClass *dc = HOSTDEV_GET_CLASS(obj);
    hostdevProperty *prop;

    for (prop = dc->props; prop && prop->name; prop++) {
        hostdev_property_add_static(s, prop, NULL);
    }

    object_property_add_str(OBJECT(s), "type", hostdev_get_type, NULL, NULL);
}

static TypeInfo hostdev_type_info = {
    .name          = TYPE_HOSTDEV,
    .parent        = TYPE_OBJECT,
    .instance_size = sizeof(HOSTDevice),
    .instance_init = hostdev_init,
    .abstract      = true,
    .class_size    = sizeof(HOSTDeviceClass),
};

static void hostdev_register_types(void)
{
    type_register_static(&hostdev_type_info);
}

type_init(hostdev_register_types)
