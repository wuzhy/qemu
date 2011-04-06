/*
 * Hub net client
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

#include "monitor.h"
#include "net.h"
#include "hub.h"

/*
 * A hub broadcasts incoming packets to all its ports except the source port.
 * Hubs can be used to provide independent network segments, also confusingly
 * named the QEMU 'vlan' feature.
 */

typedef struct NetHub NetHub;

typedef struct NetHubPort {
    VLANClientState nc;
    QLIST_ENTRY(NetHubPort) next;
    NetHub *hub;
    unsigned int id;
} NetHubPort;

struct NetHub {
    unsigned int id;
    QLIST_ENTRY(NetHub) next;
    unsigned int num_ports;
    QLIST_HEAD(, NetHubPort) ports;
};

static QLIST_HEAD(, NetHub) hubs = QLIST_HEAD_INITIALIZER(&hubs);

static ssize_t net_hub_receive(NetHub *hub, NetHubPort *source_port,
                               const uint8_t *buf, size_t len)
{
    NetHubPort *port;

    QLIST_FOREACH(port, &hub->ports, next) {
        if (port == source_port) {
            continue;
        }

        /* TODO use qemu_send_packet() or need to call *_deliver_* directly? */
        /* TODO ignore return value? */
        qemu_send_packet(&port->nc, buf, len);
    }
    return len;
}

static ssize_t net_hub_receive_iov(NetHub *hub, NetHubPort *source_port,
                                   const struct iovec *iov, int iovcnt)
{
    NetHubPort *port;
    ssize_t ret = 0;

    QLIST_FOREACH(port, &hub->ports, next) {
        if (port == source_port) {
            continue;
        }

        /* TODO use qemu_send_packet() or need to call *_deliver_* directly? */
        /* TODO return value */
        ret = qemu_sendv_packet(&port->nc, iov, iovcnt);
    }
    return ret;
}

static NetHub *net_hub_new(unsigned int id)
{
    NetHub *hub;

    hub = g_malloc(sizeof(*hub));
    hub->id = id;
    hub->num_ports = 0;
    QLIST_INIT(&hub->ports);

    QLIST_INSERT_HEAD(&hubs, hub, next);

    return hub;
}

static ssize_t net_hub_port_receive(VLANClientState *nc,
                                    const uint8_t *buf, size_t len)
{
    NetHubPort *port = DO_UPCAST(NetHubPort, nc, nc);

    return net_hub_receive(port->hub, port, buf, len);
}

static ssize_t net_hub_port_receive_iov(VLANClientState *nc,
                                        const struct iovec *iov, int iovcnt)
{
    NetHubPort *port = DO_UPCAST(NetHubPort, nc, nc);

    return net_hub_receive_iov(port->hub, port, iov, iovcnt);
}

static void net_hub_port_cleanup(VLANClientState *nc)
{
    NetHubPort *port = DO_UPCAST(NetHubPort, nc, nc);

    QLIST_REMOVE(port, next);
}

static NetClientInfo net_hub_port_info = {
    .type = NET_CLIENT_TYPE_HUB,
    .size = sizeof(NetHubPort),
    .receive = net_hub_port_receive,
    .receive_iov = net_hub_port_receive_iov,
    .cleanup = net_hub_port_cleanup,
};

static NetHubPort *net_hub_port_new(NetHub *hub)
{
    VLANClientState *nc;
    NetHubPort *port;
    unsigned int id = hub->num_ports++;
    char name[128];

    snprintf(name, sizeof name, "hub%uport%u", hub->id, id);

    nc = qemu_new_net_client(&net_hub_port_info, NULL, NULL, "hub", name);
    port = DO_UPCAST(NetHubPort, nc, nc);
    port->id = id;
    port->hub = hub;

    QLIST_INSERT_HEAD(&hub->ports, port, next);

    return port;
}

/**
 * Create a port on a given hub
 *
 * If there is no existing hub with the given id then a new hub is created.
 */
VLANClientState *net_hub_add_port(unsigned int hub_id)
{
    NetHub *hub;
    NetHubPort *port;

    QLIST_FOREACH(hub, &hubs, next) {
        if (hub->id == hub_id) {
            break;
        }
    }

    if (!hub) {
        hub = net_hub_new(hub_id);
    }

    port = net_hub_port_new(hub);
    return &port->nc;
}

/**
 * Find a specific client on a hub
 */
VLANClientState *net_hub_find_client_by_name(unsigned int hub_id,
                                             const char *name)
{
    NetHub *hub;
    NetHubPort *port;
    VLANClientState *peer;

    QLIST_FOREACH(hub, &hubs, next) {
        if (hub->id == hub_id) {
            QLIST_FOREACH(port, &hub->ports, next) {
                peer = port->nc.peer;

                if (peer && strcmp(peer->name, name) == 0) {
                    return peer;
                }
            }
        }
    }
    return NULL;
}

/**
 * Print hub configuration
 */
void net_hub_info(Monitor *mon)
{
    NetHub *hub;
    NetHubPort *port;

    QLIST_FOREACH(hub, &hubs, next) {
        monitor_printf(mon, "hub %u\n", hub->id);
        QLIST_FOREACH(port, &hub->ports, next) {
            monitor_printf(mon, "    port %u peer %s\n", port->id,
                           port->nc.peer ? port->nc.peer->name : "<none>");
        }
    }
}

/**
 * Get the hub id that a client is connected to
 *
 * @id              Pointer for hub id output, may be NULL
 */
int net_hub_id_for_client(VLANClientState *nc, unsigned int *id)
{
    NetHub *hub;
    NetHubPort *port;

    QLIST_FOREACH(hub, &hubs, next) {
        QLIST_FOREACH(port, &hub->ports, next) {
            if (&port->nc == nc ||
                (port->nc.peer && port->nc.peer == nc)) {
                if (id) {
                    *id = hub->id;
                }
                return 0;
            }
        }
    }
    return -ENOENT;
}

/**
 * Warn if hub configurations are likely wrong
 */
void net_hub_check_clients(void)
{
    NetHub *hub;
    NetHubPort *port;
    VLANClientState *peer;

    QLIST_FOREACH(hub, &hubs, next) {
        int has_nic = 0, has_host_dev = 0;

        QLIST_FOREACH(port, &hub->ports, next) {
            peer = port->nc.peer;
            if (!peer) {
                fprintf(stderr, "Warning: hub port %s has no peer\n",
                        port->nc.name);
                continue;
            }

            switch (peer->info->type) {
            case NET_CLIENT_TYPE_NIC:
                has_nic = 1;
                break;
            case NET_CLIENT_TYPE_USER:
            case NET_CLIENT_TYPE_TAP:
            case NET_CLIENT_TYPE_SOCKET:
            case NET_CLIENT_TYPE_VDE:
                has_host_dev = 1;
                break;
            default:
                break;
            }
        }
        if (has_host_dev && !has_nic) {
            fprintf(stderr, "Warning: vlan %u with no nics\n", hub->id);
        }
        if (has_nic && !has_host_dev) {
            fprintf(stderr,
                    "Warning: vlan %u is not connected to host network\n",
                    hub->id);
        }
    }
}
