/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2018 Samsung Electronics Co., Ltd.
 * Copyright (C) 2022 SUSE LLC
 *
 * Author: Enzo Matsumiya <ematsumiya@suse.de>
 *
 * linux-cifsd-devel@lists.sourceforge.net
 */
#ifndef __KSMBD_USER_ADMIN_H__
#define __KSMBD_USER_ADMIN_H__

#include "include/ksmbdtools.h"

#define MAX_NT_PWD_LEN 129

int user_add_cmd(char *db, char *account, char *password);
int user_delete_cmd(char *db, char *account);
int user_update_cmd(char *db, char *account, char *password);
int user_list_cmd(char *db);

typedef enum {
	KSMBD_CMD_USER_ADD	= 0,
	KSMBD_CMD_USER_DELETE,
	KSMBD_CMD_USER_UPDATE,
	KSMBD_CMD_USER_LIST,
	KSMBD_CMD_USER_MAX	= 4,
} ksmbd_user_cmd;

/* list of supported user subcommands */
static const struct ksmbd_cmd_map ksmbd_user_cmds[] = {
	{ KSMBD_CMD_USER_ADD,		"add" },
	{ KSMBD_CMD_USER_DELETE,	"delete" },
	{ KSMBD_CMD_USER_UPDATE,	"update" },
	{ KSMBD_CMD_USER_LIST,		"list" },
	{ -1,				NULL },
};

static const struct option user_opts[] = {
	{ "password", required_argument, NULL, 'p' },
	{ "database", required_argument, NULL, 'd' },
	{ 0, 0, 0, 0 },
};

void user_usage(ksmbd_user_cmd cmd);
int user_cmd(int argc, char *argv[]);

#endif /* __KSMBD_USER_ADMIN_H__ */
