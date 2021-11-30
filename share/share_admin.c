// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2019 Samsung Electronics Co., Ltd.
 *   Copyright (C) 2021 SUSE LLC
 *
 *   linux-cifsd-devel@lists.sourceforge.net
 */

#include <glib.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "config_parser.h"
#include "ksmbdtools.h"
#include "management/share.h"
#include "linux/ksmbd_server.h"
#include "share_admin.h"

static int conf_fd = -1;
static char wbuf[16384];
static size_t wsz;

#define AUX_GROUP_PREFIX	"_a_u_x_grp_"

static char *new_group_name(char *name)
{
	char *gn;

	if (strchr(name, '['))
		return name;

	gn = g_malloc(strlen(name) + 3);
	if (gn)
		sprintf(gn, "[%s]", name);
	return gn;
}

static char *aux_group_name(char *name)
{
	char *gn;

	gn = g_malloc(strlen(name) + 3 + strlen(AUX_GROUP_PREFIX));
	if (gn)
		sprintf(gn, "[%s%s]", AUX_GROUP_PREFIX, name);
	return gn;
}

static int open_smbconf(char *smbconf, bool truncate)
{
	conf_fd = open(smbconf, O_RDWR);
	if (conf_fd == -1) {
		pr_err("%s %s\n", strerr(errno), smbconf);
		return -EINVAL;
	}

	if (truncate) {
		if (ftruncate(conf_fd, 0)) {
			pr_err("%s %s\n", strerr(errno), smbconf);
			close(conf_fd);
			return -EINVAL;
		}
	}

	return 0;
}

static void do_write(void)
{
	int nr = 0;
	int ret;

	while (wsz && (ret = write(conf_fd, wbuf + nr, wsz)) != 0) {
		if (ret == -1) {
			if (errno == EINTR)
				continue;
			pr_err("%s\n", strerr(errno));
			exit(EXIT_FAILURE);
		}

		nr += ret;
		wsz -= ret;
	}
}

static void write_share(gpointer key, gpointer value, gpointer buf)
{
	char *k = (char *)key;
	char *v = (char *)value;

	wsz = snprintf(wbuf, sizeof(wbuf), "\t%s = %s\n", k, v);
	if (wsz > sizeof(wbuf)) {
		pr_err("smb.conf entry size is above the limit: %zu > %zu\n",
			wsz,
			sizeof(wbuf));
		exit(EXIT_FAILURE);
	}
	do_write();
}

static void write_share_all(struct smbconf_group *g)
{
	wsz = snprintf(wbuf, sizeof(wbuf), "[%s]\n", g->name);
	do_write();
	g_hash_table_foreach(g->kv, write_share, NULL);
}

static void write_share_cb(gpointer key, gpointer value, gpointer share_data)
{
	struct smbconf_group *g = (struct smbconf_group *)value;

	/*
	 * Do not write AUX group
	 */
	if (!strstr(g->name, AUX_GROUP_PREFIX))
		write_share_all(g);
}

static void write_remove_share_cb(gpointer key,
				  gpointer value,
				  gpointer name)
{
	struct smbconf_group *g = (struct smbconf_group *)value;

	if (!g_ascii_strcasecmp(g->name, name)) {
		pr_info("share '%s' removed\n", g->name);
		return;
	}

	write_share_all(g);
}

static void update_share_cb(gpointer key,
			    gpointer value,
			    gpointer g)
{
	char *nk, *nv;

	nk = g_strdup(key);
	nv = g_strdup(value);
	if (!nk || !nv)
		exit(EXIT_FAILURE);

	/* This will call .dtor for already existing key/value pairs */
	g_hash_table_insert(g, nk, nv);
}

static void list_shares_cb(gpointer key, gpointer value, gpointer data)
{
	char *nk, *nv;

	nk = g_strdup(key);
	nv = g_strdup(value);

	if (!nk || !nv)
		exit(EXIT_FAILURE);

	if (!strcmp(nk, "global"))
		goto out;

	pr_out("%s\n", nk);

out:
	g_free(nk);
	g_free(nv);
}

int share_add_cmd(char *smbconf, char *name, char *opts)
{
	char *new_name = NULL;

	if (g_hash_table_lookup(parser.groups, name)) {
		pr_warn("Share already exists: %s\n", name);
		return -EEXIST;
	}

	new_name = new_group_name(name);
	if (cp_parse_external_smbconf_group(new_name, opts))
		goto error;

	if (open_smbconf(smbconf, true))
		goto error;
	g_hash_table_foreach(parser.groups, write_share_cb, NULL);
	close(conf_fd);
	g_free(new_name);
	return 0;

error:
	g_free(new_name);
	return -EINVAL;
}

int share_update_cmd(char *smbconf, char *name, char *opts)
{
	struct smbconf_group *existing_group;
	struct smbconf_group *update_group;
	char *aux_name = NULL;

	existing_group = g_hash_table_lookup(parser.groups, name);
	if (!existing_group) {
		pr_err("Unknown share: %s\n", name);
		goto error;
	}

	aux_name = aux_group_name(name);
	if (cp_parse_external_smbconf_group(aux_name, opts))
		goto error;

	/* get rid of [] */
	sprintf(aux_name, "%s%s", AUX_GROUP_PREFIX, name);
	update_group = g_hash_table_lookup(parser.groups, aux_name);
	if (!update_group) {
		pr_err("Cannot find the external group\n");
		goto error;
	}

	g_hash_table_foreach(update_group->kv,
			     update_share_cb,
			     existing_group->kv);

	if (open_smbconf(smbconf, true))
		goto error;

	g_hash_table_foreach(parser.groups, write_share_cb, NULL);
	close(conf_fd);
	g_free(aux_name);
	return 0;

error:
	g_free(aux_name);
	return -EINVAL;
}

int share_delete_cmd(char *smbconf, char *name)
{
	if (open_smbconf(smbconf, true))
		return -EINVAL;

	g_hash_table_foreach(parser.groups,
			     write_remove_share_cb,
			     name);
	close(conf_fd);
	return 0;
}

int share_list_cmd(char *smbconf)
{
	if (open_smbconf(smbconf, false))
		return -EINVAL;

	if (g_hash_table_size(parser.groups) <= 1) {
		pr_out("No shares available in %s.\n", smbconf);
		goto out;
	}

	pr_out("Shares available in %s:\n", smbconf);
	g_hash_table_foreach(parser.groups,
			     list_shares_cb,
			     NULL);
out:
	close(conf_fd);
	return 0;
}
