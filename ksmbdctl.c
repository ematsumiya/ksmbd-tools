// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2022 SUSE LLC
 * Author: Enzo Matsumiya <ematsumiya@suse.de>
 *
 * linux-cifsd-devel@lists.sourceforge.net
 */
#include <glib.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <signal.h>
#include <errno.h>
#include <ctype.h>

#include "config_parser.h"
#include "ksmbdtools.h"
#include "management/share.h"
#include "linux/ksmbd_server.h"
#include "share/share_admin.h"
#include "user/user_admin.h"
#include "daemon/daemon.h"
#include "version.h"

static inline void version(void)
{
	pr_out("ksmbd-tools version: %s\n", KSMBD_TOOLS_VERSION);
}

static void usage(int cmd)
{
	version();

	switch (cmd) {
	case KSMBD_CMD_SHARE:
		share_usage(-1);
		break;
	case KSMBD_CMD_USER:
		user_usage(-1);
		break;
	case KSMBD_CMD_DAEMON:
		daemon_usage(-1);
		break;
	case KSMBD_CMD_HELP:
	default:
		pr_out("Usage: ksmbdctl [-v] <command> [<option>] <args>\n\n");
		pr_out("%-20s%s", "  -v", "Enable verbose output. "
		       "Use -vv or -vvv for more verbose.\n\n");
		pr_out("List of available commands:\n");
		pr_out("%-20s%s", "  share", "Manage ksmbd shares\n");
		pr_out("%-20s%s", "  user", "Manage ksmbd users\n");
		pr_out("%-20s%s", "  daemon", "Manage ksmbd daemon\n");
		pr_out("%-20s%s", "  version", "Show ksmbd version\n");
		pr_out("%-20s%s", "  help", "Show this help menu\n\n");
		break;
	}

	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
	int ret = EXIT_FAILURE;
	const struct ksmbd_cmd_map *cmd_map;
	int cmd_argc, c, cmd;
	char **cmd_argv;
	int verbosity = 0;

	if (geteuid() != 0) {
		pr_out("You need to be root to run this program.\n");
		return ret;
	}

	if (argc < 2)
		usage(-1);

	while ((c = getopt(argc, argv, "-:v")) != EOF)
		switch (c) {
		case 'v':
			verbosity++;
			break;
		case 1:
			goto out_opt;
			break;
		case '?':
		default:
			usage(-1);
			break;
		}

out_opt:
	log_level = verbosity > PR_DEBUG ? PR_DEBUG : verbosity;

	/* check cmd */
	cmd_map = ksmbdctl_cmd_map(argv[optind-1]);
	if (!cmd_map || cmd_map->cmd == -1)
		usage(-1);

	cmd = cmd_map->cmd;

	/* strip "ksmbdctl" from argv/argc */
	cmd_argc = argc - 1;
	if (verbosity)
		cmd_argc--;

	cmd_argv = &argv[optind-1];

	switch (cmd) {
	case KSMBD_CMD_SHARE:
		ret = share_cmd(cmd_argc, cmd_argv);
		break;
	case KSMBD_CMD_USER:
		ret = user_cmd(cmd_argc, cmd_argv);
		break;
	case KSMBD_CMD_DAEMON:
		ret = daemon_cmd(cmd_argc, cmd_argv);
		break;
	case KSMBD_CMD_VERSION:
		version();
		break;
	case KSMBD_CMD_HELP:
	default:
		usage(-1);
		break;
	}

	return ret;
}
