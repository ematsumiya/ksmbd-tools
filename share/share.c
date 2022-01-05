// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2019 Samsung Electronics Co., Ltd.
 *   Copyright (C) 2021 SUSE LLC
 *
 *   linux-cifsd-devel@lists.sourceforge.net
 */

#include <glib.h>
#include <stdlib.h>
#include <stdio.h>
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
#include "share_admin.h"

static ksmbd_share_cmd ksmbd_share_get_cmd(char *cmd)
{
	int i;

	if (!cmd)
		return KSMBD_CMD_SHARE_NONE;

	for (i = 1; i < KSMBD_CMD_SHARE_MAX; i++)
		if (!strcmp(cmd, ksmbd_share_cmds_str[i]))
			return (ksmbd_share_cmd)i;

	return KSMBD_CMD_SHARE_NONE;
}

static const char *ksmbd_share_get_cmd_str(ksmbd_share_cmd cmd)
{
	if (cmd > KSMBD_CMD_SHARE_MAX)
		return ksmbd_share_cmds_str[KSMBD_CMD_SHARE_NONE];

	return ksmbd_share_cmds_str[(int)cmd];
}

static int parse_configs(char *smbconf)
{
	int ret;

	ret = test_file_access(smbconf);
	if (ret)
		return ret;

	ret = cp_smbconfig_hash_create(smbconf);
	if (ret)
		return ret;
	return 0;
}

static int sanity_check_share_name_simple(char *name)
{
	int sz, i;

	if (!name)
		return -EINVAL;

	sz = strlen(name);
	if (sz < 1)
		return -EINVAL;
	if (sz >= KSMBD_REQ_MAX_SHARE_NAME)
		return -EINVAL;

	if (!cp_key_cmp(name, "global"))
		return -EINVAL;

	for (i = 0; i < sz; i++) {
		if (isalnum(name[i]))
			return 0;
	}
	return -EINVAL;
}

void share_usage(ksmbd_share_cmd cmd)
{
	int i;
	const char *cmd_str = ksmbd_share_get_cmd_str(cmd);

	switch (cmd) {
	case KSMBD_CMD_SHARE_ADD:
	case KSMBD_CMD_SHARE_UPDATE:
		pr_out("Usage: ksmbdctl share %s <share_name> [-c <file>] -o "
		       "\"op1 = val1 \\n op2 = val2 \\n ...\" "
		       "(use newlines as options separator)\n", cmd_str);
		pr_out("Adds or updates a share to smb.conf file.\n\n");
		pr_out("%-30s%s", "  -c, --conf=<file>", "Use <file> as smb.conf\n");
		pr_out("%-30s%s", "  -o, --options=<options>", "Specify options for share\n\n");
		pr_out("Supported share options:\n");
		for (i = 0; i < KSMBD_SHARE_CONF_MAX; i++)
			pr_out("%s\n", KSMBD_SHARE_CONF[i]);
		break;
	case KSMBD_CMD_SHARE_DELETE:
		pr_out("Usage: ksmbdctl share delete <share_name>\n");
		pr_out("Deletes a share.\n\n");
		break;
	default:
		pr_out("Usage: ksmbdctl share <subcommand> <args> [options]\n");
		pr_out("Share management.\n\n");
		pr_out("List of available subcommands:\n");
		pr_out("%-20s%s", "  add", "Add a share\n");
		pr_out("%-20s%s", "  delete", "Delete a share\n");
		pr_out("%-20s%s", "  update", "Update a share\n");
		pr_out("%-20s%s", "  list", "List the names of all shares available\n\n");
		break;
	}

	exit(EXIT_FAILURE);
}

int share_cmd(int argc, char *argv[])
{
	int ret = EXIT_FAILURE;
	char *smbconf = PATH_SMBCONF;
	char *share_name = NULL;
	char *options = NULL;
	ksmbd_share_cmd cmd = KSMBD_CMD_SHARE_NONE;
	int c;

	if (argc < 2)
		goto usage;

	set_logger_app_name("ksmbd-share");

	cmd = ksmbd_share_get_cmd(argv[1]);

	if (cmd == KSMBD_CMD_SHARE_NONE)
		goto usage;

	if(argc == 2 && cmd != KSMBD_CMD_SHARE_LIST)
		goto missing_arg;

	if (argv[2] && argv[2][0] != '-')
		share_name = g_ascii_strdown(argv[2], strlen(argv[2]));
	else if (cmd != KSMBD_CMD_SHARE_LIST)
		goto usage;

	optind = 1;
	while ((c = getopt_long(argc, argv, "-:c:o:", share_opts, NULL)) != EOF)
		switch (c) {
		case 1:
			break;
		case 'c':
			if (cmd == KSMBD_CMD_SHARE_DELETE)
				continue;
			smbconf = strdup(optarg);
			break;
		case 'o':
			if (cmd == KSMBD_CMD_SHARE_DELETE || cmd == KSMBD_CMD_SHARE_LIST)
				continue;
			options = strdup(optarg);
			break;
		case ':':
		case '?':
		default:
			goto usage;
		}

	if (cmd == KSMBD_CMD_SHARE_LIST)
		goto share_list;

	if (!share_name)
		goto missing_arg;

	if (cmd != KSMBD_CMD_SHARE_DELETE && !options) {
		pr_out("Subcommand \"%s\" requires '-o' option set.\n\n", ksmbd_share_get_cmd_str(cmd));
		goto usage;
	}

	if (sanity_check_share_name_simple(share_name)) {
		pr_err("Share name (%s) sanity check failure\n", share_name);
		goto out;
	}

share_list:
	if (!smbconf) {
		pr_err("Out of memory\n");
		goto out;
	}

	ret = parse_configs(smbconf);
	if (ret) {
		pr_err("Unable to parse configuration file %s\n", smbconf);
		goto out;
	}

	switch (cmd) {
	case KSMBD_CMD_SHARE_ADD:
		ret = share_add_cmd(smbconf, share_name, options);
		break;
	case KSMBD_CMD_SHARE_DELETE:
		ret = share_delete_cmd(smbconf, share_name);
		break;
	case KSMBD_CMD_SHARE_UPDATE:
		ret = share_update_cmd(smbconf, share_name, options);
		break;
	case KSMBD_CMD_SHARE_LIST:
		ret = share_list_cmd(smbconf);
		break;
	}

	/*
	 * FIXME: We support only ADD_SHARE command for the time being
	 */
	if (ret == 0 && cmd == KSMBD_CMD_SHARE_ADD)
		notify_ksmbd_daemon();

out:
	cp_smbconfig_destroy();
	return ret;
missing_arg:
	if (cmd > KSMBD_CMD_SHARE_NONE && cmd < KSMBD_CMD_SHARE_MAX)
		pr_out("Subcommand \"%s\" requires an argument.\n\n", ksmbd_share_get_cmd_str(cmd));
usage:
	share_usage(cmd);

	return ret;
}
