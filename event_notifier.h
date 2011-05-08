/*
 * event notifier support
 *
 * Copyright Red Hat, Inc. 2010
 *
 * Authors:
 *  Michael S. Tsirkin <mst@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef QEMU_EVENT_NOTIFIER_H
#define QEMU_EVENT_NOTIFIER_H

#include "qemu-common.h"

#define EVENT_NOTIFIER_INITIALIZER ((EventNotifier){ .fd = -1 })

struct EventNotifier {
	int fd;
};

int event_notifier_init(EventNotifier *, int active);
void event_notifier_cleanup(EventNotifier *);
bool event_notifier_valid(EventNotifier *e);
int event_notifier_get_fd(EventNotifier *);
int event_notifier_test_and_clear(EventNotifier *);
int event_notifier_test(EventNotifier *);
int event_notifier_notify(EventNotifier *e);

#endif
