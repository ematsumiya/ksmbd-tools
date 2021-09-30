// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
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
#include "version.h"

static struct option opts[] = {
	{ "add-user",		required_argument,	NULL,	'a' },
	{ "del-user",		required_argument,	NULL,	'd' },
	{ "update-user",	required_argument,	NULL,	'u' },
	{ "password",		required_argument,	NULL,	'p' },
	{ "import-users",	required_argument,	NULL,	'i' },
	{ "version",		no_argument,		NULL,	'V' },
	{ "help",		no_argument,		NULL,	'V' },
	{ NULL,			0,			NULL,	0 }
};

enum {
	COMMAND_ADD_USER = 1,
	COMMAND_DEL_USER,
	COMMAND_UPDATE_USER,
};

static void usage(void)
{
	fprintf(stderr, "Usage: ksmbd.user [OPTION] arg\n\n");
	fprintf(stderr, "%-30s%s", "  -a, --add-user=LOGIN", "Add user\n");
	fprintf(stderr, "%-30s%s", "  -d, --del-user=LOGIN", "Delete user\n");
	fprintf(stderr, "%-30s%s", "  -u, --update-user=LOGIN", "Update user information\n");
	fprintf(stderr, "%-30s%s", "  -p, --password=PASSWORD", "Set password for user\n");
	fprintf(stderr, "%-30s%s", "  -i, --import-users=DB_PATH", "Use db file from DB_PATH\n");
	fprintf(stderr, "%-30s%s", "  -V --version", "Show ksmbd version\n");
	fprintf(stderr, "%-30s%s", "  -h --help", "Show this help menu\n");

	exit(EXIT_FAILURE);
}

static void show_version(void)
{
	printf("ksmbd-tools version: %s\n", KSMBD_TOOLS_VERSION);
	exit(EXIT_FAILURE);
}

static int parse_configs(char *pwddb)
{
	int ret;

	ret = test_file_access(pwddb);
	if (ret)
		return ret;

	ret = cp_parse_pwddb(pwddb);
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

int main(int argc, char *argv[])
{
	int ret = EXIT_FAILURE;
	char *pwddb = PATH_PWDDB;
	char *login = NULL;
	char *pw = NULL;
	int c, cmd = 0;

	if (argc < 2)
		usage();

	set_logger_app_name("ksmbd-user");

	opterr = 0;
	while((c = getopt_long(argc, argv, ":a:d:u:p:i:Vh", opts, NULL)) != EOF) {
		switch (c) {
		case 'a':
			login = g_strdup(optarg);
			cmd = COMMAND_ADD_USER;
			break;
		case 'd':
			login = g_strdup(optarg);
			cmd = COMMAND_DEL_USER;
			break;
		case 'u':
			login = g_strdup(optarg);
			cmd = COMMAND_UPDATE_USER;
			break;
		case 'p':
			pw = g_strdup(optarg);
			break;
		case 'i':
			pwddb = g_strdup(optarg);
			break;
		case 'V':
			show_version();
			break;
		case ':':
			fprintf(stderr, "Option '%s' needs an argument.\n", argv[optind-1]);
			exit(EXIT_FAILURE);
		case '?':
			fprintf(stderr, "Invalid option '%s'\n", argv[optind-1]);
			/* Fall through */
		case 'h':
		default:
			usage();
		}
	}

	if (sanity_check_user_name_simple(login)) {
		pr_err("User name sanity check failure\n");
		goto out;
	}

	if (!pwddb) {
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

	ret = parse_configs(pwddb);
	if (ret) {
		pr_err("Unable to parse configuration files\n");
		goto out;
	}

	if (cmd == COMMAND_ADD_USER)
		ret = command_add_user(pwddb, login, pw);
	if (cmd == COMMAND_DEL_USER)
		ret = command_del_user(pwddb, login);
	if (cmd == COMMAND_UPDATE_USER)
		ret = command_update_user(pwddb, login, pw);

	/*
	 * FIXME: We support only ADD_USER command at this moment
	 */
	if (ret == 0 && cmd == COMMAND_ADD_USER)
		notify_ksmbd_daemon();
out:
	shm_destroy();
	usm_destroy();
	return ret;
}
