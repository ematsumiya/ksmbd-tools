/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *   Copyright (C) 2019 Samsung Electronics Co., Ltd.
 *   Copyright (C) 2021 SUSE LLC
 *
 *   linux-cifsd-devel@lists.sourceforge.net
 */

#ifndef __KSMBD_SHARE_ADMIN_H__
#define __KSMBD_SHARE_ADMIN_H__

int share_add_cmd(char *smbconf, char *name, char *opts);
int share_delete_cmd(char *smbconf, char *name);
int share_update_cmd(char *smbconf, char *name, char *opts);
int share_list_cmd(char *smbconf);

typedef enum {
	KSMBD_CMD_SHARE_NONE = 0,
	KSMBD_CMD_SHARE_ADD,
	KSMBD_CMD_SHARE_DELETE,
	KSMBD_CMD_SHARE_UPDATE,
	KSMBD_CMD_SHARE_LIST,
	KSMBD_CMD_SHARE_MAX
} ksmbd_share_cmd;

/* List of supported subcommands */
static const char *ksmbd_share_cmds_str[] = {
	"none",
	"add",
	"delete",
	"update",
	"list"
};

static struct option share_opts[] = {
        { "conf", required_argument, NULL, 'c' },
        { "options", required_argument, NULL, 'o' },
	{ 0, 0, 0, 0 },
};

void share_usage(ksmbd_share_cmd cmd);
int share_cmd(int argc, char *argv[]);

#endif /* __KSMBD_SHARE_ADMIN_H__ */
