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
#include <stdbool.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <termios.h>

#include "config_parser.h"
#include "ksmbdtools.h"
#include "md4_hash.h"
#include "user_admin.h"
#include "management/user.h"
#include "management/share.h"
#include "linux/ksmbd_server.h"

#define MAX_NT_PWD_LEN 129

static int conf_fd = -1;
static char wbuf[2 * MAX_NT_PWD_LEN + 2 * KSMBD_REQ_MAX_ACCOUNT_NAME_SZ];

static int open_db(char *db, bool truncate)
{
	conf_fd = open(db, O_WRONLY);
	if (conf_fd == -1) {
		pr_err("%s: %m\n", db);
		return -EINVAL;
	}

	if (truncate) {
		if (ftruncate(conf_fd, 0)) {
			pr_err("%s: %m\n", db);
			close(conf_fd);
			return -EINVAL;
		}
	}

	return 0;
}

static void term_toggle_echo(int on_off)
{
	struct termios term;

	tcgetattr(STDIN_FILENO, &term);

	if (on_off)
		term.c_lflag |= ECHO;
	else
		term.c_lflag &= ~ECHO;

	tcsetattr(STDIN_FILENO, TCSAFLUSH, &term);
}

static char *prompt_password_stdin(size_t *sz)
{
	char *pw1 = g_try_malloc0(MAX_NT_PWD_LEN + 1);
	char *pw2 = g_try_malloc0(MAX_NT_PWD_LEN + 1);
	size_t len = 0;
	int i;

	if (!pw1 || !pw2)
		goto fail;

again:
	memset(pw1, 0, MAX_NT_PWD_LEN + 1);
	memset(pw2, 0, MAX_NT_PWD_LEN + 1);

	pr_out("New password: ");
	term_toggle_echo(0);
	if (fgets(pw1, MAX_NT_PWD_LEN + 1, stdin) == NULL) {
		if (feof(stdin)) {
			clearerr(stdin);
			goto skip;
		}

		term_toggle_echo(1);
		pr_out("\n");
		pr_err("Fatal error: %m\n");
		free(pw1);
		free(pw2);
		return NULL;
	}
	pr_out("\n");

	if (pw1[MAX_NT_PWD_LEN - 1] != 0x00 &&
		pw1[MAX_NT_PWD_LEN - 1] != '\n') {
		int c;

		while ((c = fgetc(stdin)) != '\n')
			if (c == EOF)
				break;

		term_toggle_echo(1);
		pr_out("\n");
		pr_err("Password exceeds maximum length %d\n", MAX_NT_PWD_LEN - 1);
		goto again;
	}

	pr_out("\nRetype new password: ");
	if (fgets(pw2, MAX_NT_PWD_LEN + 1, stdin) == NULL) {
		if (feof(stdin)) {
			clearerr(stdin);
			goto skip;
		}

		term_toggle_echo(1);
		pr_out("\n");
		pr_err("Fatal error: %m\n");
		free(pw1);
		free(pw2);
		return NULL;
	}

	if (pw2[MAX_NT_PWD_LEN - 1] != 0x00 &&
		pw2[MAX_NT_PWD_LEN - 1] != '\n') {
		int c;

		while ((c = fgetc(stdin)) != '\n')
			if (c == EOF)
				break;

		term_toggle_echo(1);
		pr_out("\n");
		pr_err("Password exceeds maximum length %d\n", MAX_NT_PWD_LEN - 1);
		goto again;
	}

skip:
	term_toggle_echo(1);
	pr_out("\n");

	len = strlen(pw1);
	for (i = 0; i < len; i++)
		if (pw1[i] == '\n')
			pw1[i] = 0x00;

	len = strlen(pw2);
	for (i = 0; i < len; i++)
		if (pw2[i] == '\n')
			pw2[i] = 0x00;

	if (memcmp(pw1, pw2, MAX_NT_PWD_LEN + 1)) {
		pr_err("Passwords don't match\n");
		goto again;
	}

	len = strlen(pw1);
	if (!len)
		pr_info("Empty password was provided\n");

	*sz = len;
	free(pw2);
	return pw1;
fail:
	pr_err("Fatal error: %m\n");
	free(pw1);
	free(pw2);
	return NULL;
}

static char *prompt_password(char *pw, size_t *sz)
{
	if (!pw)
		return prompt_password_stdin(sz);

	*sz = strlen(pw);
	if (!*sz)
		pr_info("Empty password was provided\n");
	else if (*sz >= MAX_NT_PWD_LEN) {
		pr_err("Password exceeds maximum length %d\n", MAX_NT_PWD_LEN - 1);
		exit(EXIT_FAILURE);
	}
	return pw;
}

static char *get_utf8_password(char *pw, long *len)
{
	size_t raw_sz;
	char *pw_raw, *pw_converted;
	gsize bytes_read = 0;
	gsize bytes_written = 0;

	pw_raw = prompt_password(pw, &raw_sz);
	if (!pw_raw)
		return NULL;

	pw_converted = ksmbd_gconvert(pw_raw, raw_sz, KSMBD_CHARSET_UTF16LE,
				      KSMBD_CHARSET_DEFAULT, &bytes_read,
				      &bytes_written);
	if (!pw_converted) {
		free(pw_raw);
		return NULL;
	}

	*len = bytes_written;
	free(pw_raw);
	return pw_converted;
}

static void sanity_check_pw(char *pw_hash, char *pw_b64)
{
	size_t len;
	char *pass = base64_decode(pw_b64, &len);

	if (!pass) {
		pr_err("Unable to decode NT hash\n");
		exit(EXIT_FAILURE);
	}

	if (memcmp(pass, pw_hash, len)) {
		pr_err("NT hash encoding error\n");
		exit(EXIT_FAILURE);
	}
	free(pass);
}

static char *get_hashed_b64_password(char *pw)
{
	struct md4_ctx mctx;
	long len;
	char *pw_plain, *pw_hash, *pw_b64;

	pw_plain = get_utf8_password(pw, &len);
	if (!pw_plain)
		return NULL;

	pw_hash = g_try_malloc0(sizeof(mctx.hash) + 1);
	if (!pw_hash) {
		free(pw_plain);
		pr_err("Out of memory\n");
		return NULL;
	}

	md4_init(&mctx);
	md4_update(&mctx, pw_plain, len);
	md4_final(&mctx, pw_hash);

	pw_b64 = base64_encode(pw_hash, MD4_HASH_WORDS * sizeof(unsigned int));

	sanity_check_pw(pw_hash, pw_b64);
	free(pw_plain);
	free(pw_hash);
	return pw_b64;
}

static void write_user(struct ksmbd_user *user)
{
	int ret, nr = 0;
	size_t wsz;

	if (test_user_flag(user, KSMBD_USER_FLAG_GUEST_ACCOUNT))
		return;

	wsz = snprintf(wbuf, sizeof(wbuf), "%s:%s\n", user->name, user->pass_b64);
	if (wsz > sizeof(wbuf)) {
		pr_err("Entry size is above the limit: %zu > %zu\n",
			wsz,
			sizeof(wbuf));
		exit(EXIT_FAILURE);
	}

	while (wsz && (ret = write(conf_fd, wbuf + nr, wsz)) != 0) {
		if (ret == -1) {
			if (errno == EINTR)
				continue;
			pr_err("%m\n");
			exit(EXIT_FAILURE);
		}

		nr += ret;
		wsz -= ret;
	}
}

static void write_user_cb(gpointer key, gpointer value, gpointer user_data)
{
	struct ksmbd_user *user = (struct ksmbd_user *)value;

	write_user(user);
}

static void write_remove_user_cb(gpointer key,
				 gpointer value,
				 gpointer user_data)
{
	struct ksmbd_user *user = (struct ksmbd_user *)value;

	if (!g_ascii_strcasecmp(user->name, (char *)user_data)) {
		pr_info("User '%s' removed\n", user->name);
		return;
	}

	write_user_cb(key, value, user_data);
}

static void lookup_can_del_user(gpointer key,
				gpointer value,
				gpointer user_data)
{
	struct ksmbd_share *share = (struct ksmbd_share *)value;
	int ret = 0;
	char *account = (char *)user_data;

	if (!account)
		return;

	ret = shm_lookup_users_map(share,
				   KSMBD_SHARE_ADMIN_USERS_MAP,
				   account);
	if (ret == 0)
		goto conflict;

	ret = shm_lookup_users_map(share,
				   KSMBD_SHARE_WRITE_LIST_MAP,
				   account);
	if (ret == 0)
		goto conflict;

	ret = shm_lookup_users_map(share,
				   KSMBD_SHARE_VALID_USERS_MAP,
				   account);
	if (ret == 0)
		goto conflict;

	return;

conflict:
	pr_err("Share %s requires user %s to exist\n",
		share->name, account);
	account = NULL;
}

int user_add_cmd(char *db, char *account, char *pw)
{
	struct ksmbd_user *user;
	char *pw_hash;

	user = usm_lookup_user(account);
	if (user) {
		put_ksmbd_user(user);
		pr_err("Account `%s' already exists\n", account);
		return -EEXIST;
	}

	pw_hash = get_hashed_b64_password(pw);
	if (!pw) {
		pr_err("Out of memory\n");
		return -ENOMEM;
	}

	/* pw is already g_strdup-ed */
	if (usm_add_new_user(account, pw_hash)) {
		pr_err("Could not add new account\n");
		return -EINVAL;
	}

	if (open_db(db, true))
		return -EINVAL;

	for_each_ksmbd_user(write_user_cb, NULL);

	pr_info("User '%s' added\n", account);

	close(conf_fd);
	return 0;
}

int user_update_cmd(char *db, char *account, char *pw)
{
	struct ksmbd_user *user;
	char *pw_hash;

	user = usm_lookup_user(account);
	if (!user) {
		pr_err("Unknown account \"%s\"\n", account);
		return -EINVAL;
	}

	pw_hash = get_hashed_b64_password(pw);
	if (!pw) {
		pr_err("Out of memory\n");
		put_ksmbd_user(user);
		return -ENOMEM;
	}

	if (usm_update_user_password(user, pw_hash)) {
		pr_err("Out of memory\n");
		put_ksmbd_user(user);
		return -ENOMEM;
	}

	pr_info("User '%s' updated\n", account);
	put_ksmbd_user(user);
	free(pw);

	if (open_db(db, true))
		return -EINVAL;

	for_each_ksmbd_user(write_user_cb, NULL);
	close(conf_fd);
	return 0;
}

int user_delete_cmd(char *db, char *account)
{
	char *abort_del_user = strdup(account);

	if (global_conf.guest_account &&
	    !cp_key_cmp(global_conf.guest_account, account)) {
		pr_err("User %s is a global guest account. Abort deletion.\n",
		       account);
		return -EINVAL;
	}

	for_each_ksmbd_share(lookup_can_del_user, abort_del_user);

	if (!abort_del_user) {
		pr_err("Aborting user deletion\n");
		return -EINVAL;
	}

	if (open_db(db, true))
		return -EINVAL;

	for_each_ksmbd_user(write_remove_user_cb, account);
	close(conf_fd);
	return 0;
}

static void list_users_cb(gpointer key, gpointer value, gpointer data)
{
	struct ksmbd_user *user = (struct ksmbd_user *)value;

	pr_out("%s\n", user->name);
}

int user_list_cmd(char *db)
{
	if (open_db(db, false))
		return -EINVAL;

	pr_out("Users in %s:\n", db);
	for_each_ksmbd_user(list_users_cb, NULL);
	pr_out("\n");
	close(conf_fd);

	return 0;
}
