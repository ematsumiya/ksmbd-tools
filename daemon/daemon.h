/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *   Copyright (C) 2021 SUSE LLC
 *
 *   linux-cifsd-devel@lists.sourceforge.net
 */

#ifndef __DAEMON_H__
#define __DAEMON_H__

#define KSMBD_SYSFS_KILL_SERVER "/sys/class/ksmbd-control/kill_server"
#define KSMBD_SYSFS_DEBUG	"/sys/class/ksmbd-control/debug"
#define KSMBD_SYSFS_VERSION	"/sys/module/ksmbd/version"

static const char * const debug_type_strings[] = {
	"all", "smb", "auth", "vfs", "oplock", "ipc", "conn", "rdma"
};

static struct option daemon_opts[] = {
	{ "port", required_argument, NULL, 'p' },
	{ "config", required_argument, NULL, 'c' },
	{ "usersdb", required_argument, NULL, 'u' },
	{ "nodetach", no_argument, NULL, 'n' },
	{ "systemd", no_argument, NULL, 's' },
	{ "help", no_argument, NULL, 'h' },
	{ 0, 0, 0, 0 },
};

#endif /* __DAEMON_H__ */
