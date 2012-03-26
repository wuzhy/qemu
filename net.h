#ifndef QEMU_NET_H
#define QEMU_NET_H

#include "qemu-queue.h"
#include "qemu-common.h"
#include "qdict.h"
#include "qemu-option.h"
#include "net/queue.h"
#include "vmstate.h"
#include "qemu/hostdev.h"

typedef struct NETDevice NETDevice;

#define TYPE_NETDEV "net-dev"
#define NET_DEVICE(obj) \
     OBJECT_CHECK(NETDevice, (obj), TYPE_NETDEV)
#define NETDEV_CLASS(klass) \
     OBJECT_CLASS_CHECK(NETDeviceClass, (klass), TYPE_NETDEV)
#define NETDEV_GET_CLASS(obj) \
     OBJECT_GET_CLASS(NETDeviceClass, (obj), TYPE_NETDEV)

typedef struct NETDeviceClass {
    HOSTDeviceClass parent_class;
    int (*init)(NETDevice *net_dev);
} NETDeviceClass;

struct NETDevice {
    /*< private >*/
    HOSTDevice host_dev;

    /*< public >*/
    QemuOpts *opts;
    Monitor *mon;
    const char *name;
    NetClientState *peer;
};

struct MACAddr {
    uint8_t a[6];
};

/* qdev nic properties */

typedef struct NICConf {
    MACAddr macaddr;
    NetClientState *peer;
    int32_t bootindex;
} NICConf;

#define DEFINE_NIC_PROPERTIES(_state, _conf)                            \
    DEFINE_PROP_MACADDR("mac",   _state, _conf.macaddr),                \
    DEFINE_PROP_NETDEV("netdev", _state, _conf.peer),                   \
    DEFINE_PROP_INT32("bootindex", _state, _conf.bootindex, -1)

/* Net clients */

typedef enum {
    NET_CLIENT_TYPE_NONE,
    NET_CLIENT_TYPE_NIC,
    NET_CLIENT_TYPE_USER,
    NET_CLIENT_TYPE_TAP,
    NET_CLIENT_TYPE_SOCKET,
    NET_CLIENT_TYPE_VDE,
    NET_CLIENT_TYPE_DUMP,
    NET_CLIENT_TYPE_BRIDGE,
    NET_CLIENT_TYPE_HUB,

    NET_CLIENT_TYPE_MAX
} net_client_type;

typedef void (NetPoll)(NetClientState *, bool enable);
typedef int (NetCanReceive)(NetClientState *);
typedef ssize_t (NetReceive)(NetClientState *, const uint8_t *, size_t);
typedef ssize_t (NetReceiveIOV)(NetClientState *, const struct iovec *, int);
typedef void (NetCleanup) (NetClientState *);
typedef void (LinkStatusChanged)(NetClientState *);

typedef struct NetClientInfo {
    net_client_type type;
    size_t size;
    NetReceive *receive;
    NetReceive *receive_raw;
    NetReceiveIOV *receive_iov;
    NetCanReceive *can_receive;
    NetCleanup *cleanup;
    LinkStatusChanged *link_status_changed;
    NetPoll *poll;
} NetClientInfo;

struct NetClientState {
    NetClientInfo *info;
    int link_down;
    QTAILQ_ENTRY(NetClientState) next;
    NetClientState *peer;
    NetQueue *send_queue;
    char *model;
    char *name;
    char info_str[256];
    unsigned receive_disabled : 1;
};

typedef struct NICState {
    NetClientState nc;
    NICConf *conf;
    void *opaque;
    bool peer_deleted;
} NICState;

NetClientState *qemu_find_netdev(const char *id);
NetClientState *qemu_new_net_client(NetClientInfo *info,
                                    NetClientState *peer,
                                    const char *model,
                                    const char *name);
NICState *qemu_new_nic(NetClientInfo *info,
                       NICConf *conf,
                       const char *model,
                       const char *name,
                       void *opaque);
void qemu_del_net_client(NetClientState *nc);
NetClientState *qemu_find_vlan_client_by_name(Monitor *mon, int vlan_id,
                                              const char *client_str);
typedef void (*qemu_nic_foreach)(NICState *nic, void *opaque);
void qemu_foreach_nic(qemu_nic_foreach func, void *opaque);
int qemu_can_send_packet(NetClientState *nc);
ssize_t qemu_sendv_packet(NetClientState *nc, const struct iovec *iov,
                          int iovcnt);
ssize_t qemu_sendv_packet_async(NetClientState *nc, const struct iovec *iov,
                                int iovcnt, NetPacketSent *sent_cb);
void qemu_send_packet(NetClientState *nc, const uint8_t *buf, int size);
ssize_t qemu_send_packet_raw(NetClientState *nc, const uint8_t *buf, int size);
ssize_t qemu_send_packet_async(NetClientState *nc, const uint8_t *buf,
                               int size, NetPacketSent *sent_cb);
void qemu_purge_queued_packets(NetClientState *nc);
void qemu_flush_queued_packets(NetClientState *nc);
void qemu_format_nic_info_str(NetClientState *nc, uint8_t macaddr[6]);
void qemu_macaddr_default_if_unset(MACAddr *macaddr);
int qemu_show_nic_models(const char *arg, const char *const *models);
void qemu_check_nic_model(NICInfo *nd, const char *model);
int qemu_find_nic_model(NICInfo *nd, const char * const *models,
                        const char *default_model);

void do_info_network(Monitor *mon);

/* NIC info */

#define MAX_NICS 8

struct NICInfo {
    MACAddr macaddr;
    char *model;
    char *name;
    char *devaddr;
    NetClientState *netdev;
    int used;         /* is this slot in nd_table[] being used? */
    int instantiated; /* does this NICInfo correspond to an instantiated NIC? */
    int nvectors;
};

extern int nb_nics;
extern NICInfo nd_table[MAX_NICS];
extern int default_net;

/* BT HCI info */

struct HCIInfo {
    int (*bdaddr_set)(struct HCIInfo *hci, const uint8_t *bd_addr);
    void (*cmd_send)(struct HCIInfo *hci, const uint8_t *data, int len);
    void (*sco_send)(struct HCIInfo *hci, const uint8_t *data, int len);
    void (*acl_send)(struct HCIInfo *hci, const uint8_t *data, int len);
    void *opaque;
    void (*evt_recv)(void *opaque, const uint8_t *data, int len);
    void (*acl_recv)(void *opaque, const uint8_t *data, int len);
};

struct HCIInfo *qemu_next_hci(void);

/* from net.c */
extern const char *legacy_tftp_prefix;
extern const char *legacy_bootp_filename;

int net_client_init(Monitor *mon, QemuOpts *opts, int is_netdev);
int net_client_parse(QemuOptsList *opts_list, const char *str);
int net_init_clients(void);
void net_check_clients(void);
void net_cleanup(void);
void net_host_device_add(Monitor *mon, const QDict *qdict);
void net_host_device_remove(Monitor *mon, const QDict *qdict);
int do_netdev_add(Monitor *mon, const QDict *qdict, QObject **ret_data);
int do_netdev_del(Monitor *mon, const QDict *qdict, QObject **ret_data);

#define DEFAULT_NETWORK_SCRIPT "/etc/qemu-ifup"
#define DEFAULT_NETWORK_DOWN_SCRIPT "/etc/qemu-ifdown"
#define DEFAULT_BRIDGE_HELPER CONFIG_QEMU_HELPERDIR "/qemu-bridge-helper"
#define DEFAULT_BRIDGE_INTERFACE "br0"

void qdev_set_nic_properties(DeviceState *dev, NICInfo *nd);

int net_handle_fd_param(Monitor *mon, const char *param);

#define vmstate_offset_macaddr(_state, _field)                       \
    vmstate_offset_array(_state, _field.a, uint8_t,                \
                         sizeof(typeof_field(_state, _field)))

#define VMSTATE_MACADDR(_field, _state) {                            \
    .name       = (stringify(_field)),                               \
    .size       = sizeof(MACAddr),                                   \
    .info       = &vmstate_info_buffer,                              \
    .flags      = VMS_BUFFER,                                        \
    .offset     = vmstate_offset_macaddr(_state, _field),            \
}

#endif
