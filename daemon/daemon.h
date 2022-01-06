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

int daemon_start_cmd(int no_detach, int systemd_service);
int daemon_shutdown_cmd(void);
int daemon_debug_cmd(char *debug_type);
int daemon_version_cmd(void);

typedef enum {
	KSMBD_CMD_DAEMON_NONE = 0,
	KSMBD_CMD_DAEMON_START,
	KSMBD_CMD_DAEMON_SHUTDOWN,
	KSMBD_CMD_DAEMON_DEBUG,
	KSMBD_CMD_DAEMON_VERSION,
	KSMBD_CMD_DAEMON_MAX
} ksmbd_daemon_cmd;

static const char * const debug_type_strings[] = {
	"all", "smb", "auth", "vfs", "oplock", "ipc", "conn", "rdma"
};

/* List of supported subcommands */
static const char *ksmbd_daemon_cmds_str[] ={
	"none",
	"start",
	"shutdown",
	"debug",
	"version",
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

void daemon_usage(ksmbd_daemon_cmd cmd);
int daemon_cmd(int argc, char *argv[]);

#endif /* __DAEMON_H__ */
