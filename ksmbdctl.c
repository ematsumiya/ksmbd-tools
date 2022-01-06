// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 SUSE LLC
 *   Author: Enzo Matsumiya <ematsumiya@suse.de>
 *
 *   linux-cifsd-devel@lists.sourceforge.net
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

typedef enum {
       KSMBD_CMD_NONE = 0,
       KSMBD_CMD_SHARE,
       KSMBD_CMD_USER,
       KSMBD_CMD_DAEMON,
       KSMBD_CMD_VERSION,
       KSMBD_CMD_HELP,
       KSMBD_CMD_MAX
} ksmbd_cmd;

/* List of supported commands */
static const char *ksmbd_cmds_str[] = {
       "none",
       "share",
       "user",
       "daemon",
       "version",
       "help"
};

static ksmbd_cmd ksmbd_get_cmd(char *cmd)
{
       int i;

       if (!cmd)
               return KSMBD_CMD_NONE;

       for (i = 1; i < KSMBD_CMD_MAX; i++)
               if (!strcmp(cmd, ksmbd_cmds_str[i]))
                       return (ksmbd_cmd)i;

       return KSMBD_CMD_NONE;
}

static const char *ksmbd_get_cmd_str(ksmbd_cmd cmd)
{
       return ksmbd_cmds_str[(int)cmd];
}

ksmbd_cmd get_cmd_type(char *cmd)
{
       int i;

       if (!cmd)
               return KSMBD_CMD_NONE;

       for (i = 1; i < KSMBD_CMD_MAX; i++)
               if (!strcmp(cmd, ksmbd_cmds_str[i]))
                       return i;

       return KSMBD_CMD_NONE;
}

static void version(void)
{
	pr_out("ksmbd-tools version: %s\n", KSMBD_TOOLS_VERSION);
}

static void usage(ksmbd_cmd cmd)
{
	version();

	switch (cmd) {
	case KSMBD_CMD_SHARE:
		share_usage(0);
		break;
	case KSMBD_CMD_USER:
		user_usage(0);
		break;
	case KSMBD_CMD_DAEMON:
		daemon_usage(0);
		break;
	case KSMBD_CMD_HELP:
	default:
		pr_out("Usage: ksmbdctl [-v] <command> [<option>] <args>\n\n");
		pr_out("%-20s%s", "  -v", "Enable verbose output. Use -vv or -vvv for more verbose.\n\n");
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
	int cmd_argc, c;
	char **cmd_argv;
	int verbosity = 0;

	if (geteuid() != 0) {
		pr_out("You need to be root to run this program.\n");
		return ret;
	}

	if (argc < 2)
		usage(KSMBD_CMD_NONE);

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
			usage(KSMBD_CMD_NONE);
			break;
		}

out_opt:
	log_level = verbosity > PR_DEBUG ? PR_DEBUG : verbosity;

	/* check cmd */
	ksmbd_cmd cmd = get_cmd_type(argv[optind-1]);

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
	case KSMBD_CMD_NONE:
	default:
		usage(KSMBD_CMD_NONE);
		break;
	}

	return ret;
}
