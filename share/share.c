// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2019 Samsung Electronics Co., Ltd.
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
#include "version.h"

static struct option opts[] = {
	{ "add-share",		required_argument,	NULL,	'a' },
	{ "del-share",		required_argument,	NULL,	'd' },
	{ "update-share",	required_argument,	NULL,	'u' },
	{ "options",		required_argument,	NULL,	'o' },
	{ "conf",		required_argument,	NULL,	'c' },
	{ "version",		no_argument,		NULL,	'V' },
	{ "help",		no_argument,		NULL,	'h' },
	{ NULL,			0,			NULL,	0 }
};

enum {
	COMMAND_ADD_SHARE = 1,
	COMMAND_DEL_SHARE,
	COMMAND_UPDATE_SHARE,
};

static void usage(void)
{
	int i;

	fprintf(stderr, "Usage: ksmbd.share [OPTION] arg\n");
	fprintf(stderr, "%-30s%s", "  -a, --add-share=SHARE", "Add a share\n");
	fprintf(stderr, "%-30s%s", "  -d, --del-share=SHARE", "Delete a share\n");
	fprintf(stderr, "%-30s%s", "  -u, --update-share=SHARE", "Update a share\n");
	fprintf(stderr, "%-30s%s", "  -o, --options=\"[OP1=VAL1 OP2=VAL2 ...]\"", "Share options (see below)\n");
	fprintf(stderr, "%-30s%s", "  -c, --conf FILE", "Use config from FILE\n");
	fprintf(stderr, "%-30s%s", "  -V, --version", "Show ksmbd version\n");
	fprintf(stderr, "%-30s%s", "  -h --help", "Show this help menu\n\n");
	fprintf(stderr, "Supported share options:\n");
	for (i = 0; i < KSMBD_SHARE_CONF_MAX; i++)
		fprintf(stderr, "%s\n", KSMBD_SHARE_CONF[i]);

	exit(EXIT_FAILURE);
}

static void show_version(void)
{
	printf("ksmbd-tools version : %s\n", KSMBD_TOOLS_VERSION);
	exit(EXIT_FAILURE);
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

int main(int argc, char *argv[])
{
	int ret = EXIT_FAILURE;
	char *smbconf = PATH_SMBCONF;
	char *share_name = NULL;
	char *options = NULL;
	int c, cmd = 0;

	if (argc < 2)
		usage();

	set_logger_app_name("ksmbd-share");

	opterr = 0;
	while ((c = getopt_long(argc, argv, ":c:a:d:u:o:Vh", opts, NULL)) != EOF)
		switch (c) {
		case 'a':
			share_name = g_ascii_strdown(optarg, strlen(optarg));
			cmd = COMMAND_ADD_SHARE;
			break;
		case 'd':
			share_name = g_ascii_strdown(optarg, strlen(optarg));
			cmd = COMMAND_DEL_SHARE;
			break;
		case 'u':
			share_name = g_ascii_strdown(optarg, strlen(optarg));
			cmd = COMMAND_UPDATE_SHARE;
			break;
		case 'c':
			smbconf = strdup(optarg);
			break;
		case 'o':
			options = strdup(optarg);
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

	if (cmd != COMMAND_DEL_SHARE && !options)
		usage();

	if (sanity_check_share_name_simple(share_name)) {
		pr_err("Share name sanity check failure\n");
		goto out;
	}

	if (!smbconf) {
		pr_err("Out of memory\n");
		goto out;
	}

	ret = parse_configs(smbconf);
	if (ret) {
		pr_err("Unable to parse configuration files\n");
		goto out;
	}

	if (cmd == COMMAND_ADD_SHARE)
		ret = command_add_share(smbconf, share_name, options);
	if (cmd == COMMAND_DEL_SHARE)
		ret = command_del_share(smbconf, share_name);
	if (cmd == COMMAND_UPDATE_SHARE)
		ret = command_update_share(smbconf, share_name, options);

	/*
	 * FIXME: We support only ADD_SHARE command for the time being
	 */
	if (ret == 0 && cmd == COMMAND_ADD_SHARE)
		notify_ksmbd_daemon();
out:
	cp_smbconfig_destroy();
	return ret;
}
