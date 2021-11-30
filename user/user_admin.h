/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *   Copyright (C) 2021 SUSE LLC
 *
 *   linux-cifsd-devel@lists.sourceforge.net
 */

#ifndef __KSMBD_USER_ADMIN_H__
#define __KSMBD_USER_ADMIN_H__

int user_add_cmd(char *db, char *account, char *password);
int user_delete_cmd(char *db, char *account);
int user_update_cmd(char *db, char *account, char *password);
int user_list_cmd(char *db);

typedef enum {
	KSMBD_CMD_USER_NONE = 0,
	KSMBD_CMD_USER_ADD,
	KSMBD_CMD_USER_DELETE,
	KSMBD_CMD_USER_UPDATE,
	KSMBD_CMD_USER_LIST,
	KSMBD_CMD_USER_MAX
} ksmbd_user_cmd;

/* List of supported subcommands */
static const char *ksmbd_user_cmds_str[] = {
	"none",
	"add",
	"delete",
	"update",
	"list",
};

static struct option user_opts[] = {
	{ "password", required_argument, NULL, 'p' },
	{ "database", required_argument, NULL, 'd' },
	{ 0, 0, 0, 0 },
};

void user_usage(ksmbd_user_cmd cmd);
int user_cmd(int argc, char *argv[]);

#endif /* __KSMBD_USER_ADMIN_H__ */
