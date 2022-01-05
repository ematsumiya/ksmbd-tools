// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
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
#include "management/user.h"
#include "management/share.h"
#include "user_admin.h"
#include "linux/ksmbd_server.h"

static ksmbd_user_cmd ksmbd_user_get_cmd(char *cmd)
{
	int i;

	if (!cmd)
		return KSMBD_CMD_USER_NONE;

	for (i = 1; i < KSMBD_CMD_USER_MAX; i++)
		if (!strcmp(cmd, ksmbd_user_cmds_str[i]))
			return (ksmbd_user_cmd)i;

	return KSMBD_CMD_USER_NONE;
}

static const char *ksmbd_user_get_cmd_str(ksmbd_user_cmd cmd)
{
	if (cmd > KSMBD_CMD_USER_MAX)
		return ksmbd_user_cmds_str[KSMBD_CMD_USER_NONE];

	return ksmbd_user_cmds_str[(int)cmd];
}

void user_usage(ksmbd_user_cmd cmd)
{
	const char *cmd_str = ksmbd_user_get_cmd_str(cmd);

	switch (cmd) {
	case KSMBD_CMD_USER_ADD:
	case KSMBD_CMD_USER_UPDATE:
		pr_out("Usage: ksmbdctl user %s <username> [-p <password>] [-d <file>]\n", cmd_str);
		pr_out("Adds or updates a user to the database.\n\n");
		pr_out("%-30s%s", "  -p, --password=<password>", "Use <password> for <username>\n");
		pr_out("%-30s%s", "  -d, --database=<file>", "Use <file> as database\n\n");
		break;
	case KSMBD_CMD_USER_DELETE:
		pr_out("Usage: ksmbdctl user delete <username>\n");
		pr_out("Delete user from database.\n\n");
		break;
	case KSMBD_CMD_USER_LIST:
		pr_out("Usage: ksmbdctl user list\n");
		pr_out("List users in database.\n\n");
		pr_out("%-30s%s", "  -d, --database=<file>", "Use <file> as database\n\n");
		break;
	default:
		pr_out("Usage: ksmbdctl user <subcommand> <args> [options]\n");
		pr_out("User management.\n\n");
		pr_out("List of available subcommands:\n");
		pr_out("%-20s%s", "  add", "Add a user\n");
		pr_out("%-20s%s", "  delete", "Delete a user\n");
		pr_out("%-20s%s", "  update", "Update an existing user\n");
		pr_out("%-20s%s", "  list", "List users in user database\n\n");
		break;
	}

	exit(EXIT_FAILURE);
}

static int parse_configs(char *db)
{
	int ret;

	ret = test_file_access(db);
	if (ret)
		return ret;

	ret = cp_parse_db(db);
	if (ret)
		return ret;
	return 0;
}

static int sanity_check_user_name_simple(char *uname)
{
	int sz, i;

	if (!uname)
		return -EINVAL;

	sz = strlen(uname);
	if (sz < 1)
		return -EINVAL;
	if (sz >= KSMBD_REQ_MAX_ACCOUNT_NAME_SZ)
		return -EINVAL;

	/* 1'; Drop table users -- */
	if (!strcmp(uname, "root"))
		return -EINVAL;

	for (i = 0; i < sz; i++) {
		if (isalnum(uname[i]))
			return 0;
	}
	return -EINVAL;
}

int user_cmd(int argc, char *argv[])
{
	int ret = EXIT_FAILURE;
	char *db = PATH_USERS_DB;
	char *login = NULL;
	char *pw = NULL;
	ksmbd_user_cmd cmd = KSMBD_CMD_USER_NONE;
	const char *cmd_str = NULL;
	int c;

	if (argc < 2)
		goto usage;

	set_logger_app_name("ksmbd-user");

	cmd = ksmbd_user_get_cmd(argv[1]);
	cmd_str = ksmbd_user_get_cmd_str(cmd);

	if (cmd == KSMBD_CMD_USER_NONE)
		goto usage;

	if (cmd != KSMBD_CMD_USER_LIST) {
		if (argc == 2)
			goto missing_arg;

		if (argv[2][0] != '-')
			login = g_strdup(argv[2]);
		else
			goto usage;
	}

	optind = 1;
	while((c = getopt_long(argc, argv, "-:p:d:", user_opts, NULL)) != EOF)
		switch (c) {
		case 1:
			break;
		case 'p':
			pw = g_strdup(optarg);
			break;
		case 'd':
			db = g_strdup(optarg);
			break;
		case ':':
		case '?':
		default:
			goto usage;
		}

	if (cmd == KSMBD_CMD_USER_LIST)
		goto user_list;

	if (!login)
		goto missing_arg;

	if (sanity_check_user_name_simple(login)) {
		pr_err("User name (%s) sanity check failure\n", login);
		goto out;
	}

user_list:
	if (!db) {
		pr_err("Out of memory\n");
		goto out;
	}

	ret = usm_init();
	if (ret) {
		pr_err("Failed to init user management\n");
		goto out;
	}

	ret = shm_init();
	if (ret) {
		pr_err("Failed to init net share management\n");
		goto out;
	}

	ret = parse_configs(db);
	if (ret) {
		pr_err("Unable to parse database file %s\n", db);
		goto out;
	}

	switch (cmd) {
	case KSMBD_CMD_USER_ADD:
		ret = user_add_cmd(db, login, pw);
		break;
	case KSMBD_CMD_USER_DELETE:
		ret = user_delete_cmd(db, login);
		break;
	case KSMBD_CMD_USER_UPDATE:
		ret = user_update_cmd(db, login, pw);
		break;
	case KSMBD_CMD_USER_LIST:
		ret = user_list_cmd(db);
		break;
	}

	/*
	 * FIXME: We support only ADD_USER command at this moment
	 */
	if (ret == 0 && cmd == KSMBD_CMD_USER_ADD)
		notify_ksmbd_daemon();
out:
	shm_destroy();
	usm_destroy();
	return ret;

missing_arg:
	if (cmd > KSMBD_CMD_USER_NONE && cmd < KSMBD_CMD_USER_MAX)
		pr_out("Subcommand \"%s\" requires an argument.\n\n", cmd_str);
usage:
	user_usage(cmd);

	return ret;
}
