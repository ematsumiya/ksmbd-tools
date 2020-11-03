// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2020 Samsung Electronics Co., Ltd.
 *
 *   linux-cifsd-devel@lists.sourceforge.net
 */

#include <memory.h>
#include <endian.h>
#include <glib.h>
#include <pwd.h>
#include <errno.h>
#include <linux/ksmbd_server.h>

#include <management/user.h>
#include <rpc.h>
#include <rpc_lsarpc.h>
#include <smbacl.h>
#include <ksmbdtools.h>

#define LSARPC_OPNUM_DS_ROLE_GET_PRIMARY_DOMAIN_INFO	0
#define LSARPC_OPNUM_OPEN_POLICY2			44
#define LSARPC_OPNUM_QUERY_INFO_POLICY			7
#define LSARPC_OPNUM_LOOKUP_SID2			57
#define LSARPC_OPNUM_LOOKUP_NAMES3			68
#define LSARPC_OPNUM_CLOSE				0

#define DS_ROLE_STANDALONE_SERVER	2
#define DS_ROLE_BASIC_INFORMATION	1

#define LSA_POLICY_INFO_ACCOUNT_DOMAIN	5

static GHashTable	*ph_table;
static GRWLock		ph_table_lock;

static void lsarpc_ph_free(struct policy_handle *ph)
{
	g_rw_lock_writer_lock(&ph_table_lock);
	g_hash_table_remove(ph_table, &(ph->handle));
	g_rw_lock_writer_unlock(&ph_table_lock);

	free(ph);
}

static struct policy_handle *lsarpc_ph_lookup(unsigned char *handle)
{
	struct policy_handle *ph;

	g_rw_lock_reader_lock(&ph_table_lock);
	ph = g_hash_table_lookup(ph_table, handle);
	g_rw_lock_reader_unlock(&ph_table_lock);

	return ph;
}

static struct policy_handle *lsarpc_ph_alloc(unsigned int id)
{
	struct policy_handle *ph;
	int ret;

	ph = calloc(1, sizeof(struct policy_handle));
	if (!ph)
		return NULL;

	id++;
	memcpy(ph->handle, &id, sizeof(unsigned int));
	g_rw_lock_writer_lock(&ph_table_lock);
	ret = g_hash_table_insert(ph_table, &(ph->handle), ph);
	g_rw_lock_writer_unlock(&ph_table_lock);

	if (!ret) {
		lsarpc_ph_free(ph);
		ph = NULL;
	}

	return ph;
}


static int lsarpc_get_primary_domain_info_invoke(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;

	dce->lr_req.level = ndr_read_int16(dce);

	return KSMBD_RPC_OK;
}

static int lsarpc_get_primary_domain_info_return(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	int i;
	char domain_string[NAME_MAX];

	if (dce->lr_req.level != DS_ROLE_BASIC_INFORMATION)
		return KSMBD_RPC_EBAD_FUNC;

	dce->num_pointers++;
	ndr_write_int32(dce, dce->num_pointers); // ref pointer
	ndr_write_int16(dce, 1); // count
	ndr_write_int16(dce, 0);
	ndr_write_int16(dce, DS_ROLE_STANDALONE_SERVER); // role
	ndr_write_int16(dce, 0);
	ndr_write_int32(dce, 0); // flags
	dce->num_pointers++;
	ndr_write_int32(dce, dce->num_pointers); // ref pointer
	ndr_write_int32(dce, 0); // NULL pointer : Pointer to Dns Domain
	ndr_write_int32(dce, 0); // NULL pointer : Pointer to Forest

	/* NULL Domain guid */
	for (i = 0; i < 16; i++)
		ndr_write_int8(dce, 0);

	gethostname(domain_string, NAME_MAX);
	ndr_write_vstring(dce, domain_string); // domain string

	return KSMBD_RPC_OK;
}

static int lsarpc_open_policy2_return(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	struct policy_handle *ph;

	ph = lsarpc_ph_alloc(pipe->id);
	if (!ph)
		return KSMBD_RPC_ENOMEM;

	/* write connect handle */
	ndr_write_bytes(dce, ph->handle, HANDLE_SIZE);

	return KSMBD_RPC_OK;
}

static int lsarpc_query_info_policy_invoke(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	unsigned long long id;

	ndr_read_bytes(dce, dce->lr_req.handle, HANDLE_SIZE);
	dce->lr_req.level = ndr_read_int16(dce); // level

	return KSMBD_RPC_OK;
}

int lsarpc_ndr_write_vstring(struct ksmbd_dcerpc *dce, char *value)
{
	gchar *out;
	gsize bytes_read = 0;
	gsize bytes_written = 0;

	size_t raw_len;
	char *raw_value = value;
	int charset = KSMBD_CHARSET_UTF16LE;
	int ret;

	if (!value)
		raw_value = "";
	raw_len = strlen(raw_value);

	if (!(dce->flags & KSMBD_DCERPC_LITTLE_ENDIAN))
		charset = KSMBD_CHARSET_UTF16BE;

	if (dce->flags & KSMBD_DCERPC_ASCII_STRING)
		charset = KSMBD_CHARSET_UTF8;

	out = ksmbd_gconvert(raw_value,
			     raw_len,
			     charset,
			     KSMBD_CHARSET_DEFAULT,
			     &bytes_read,
			     &bytes_written);
	if (!out)
		return -EINVAL;

	ret = ndr_write_int32(dce, raw_len + 1);
	ret |= ndr_write_int32(dce, 0);
	ret |= ndr_write_int32(dce, raw_len);
	ret |= ndr_write_bytes(dce, out, bytes_written);
	auto_align_offset(dce);

	g_free(out);
	return ret;
}

static int lsarpc_query_info_policy_return(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	char domain_string[NAME_MAX];
	struct smb_sid sid;
	struct policy_handle *ph;
	int len;

	ph = lsarpc_ph_lookup(dce->lr_req.handle);
	if (!ph)
		return KSMBD_RPC_EBAD_FID;

	if (dce->lr_req.level != LSA_POLICY_INFO_ACCOUNT_DOMAIN)
		return KSMBD_RPC_EBAD_FUNC;

	dce->num_pointers++;
	ndr_write_int32(dce, dce->num_pointers); // ref pointer
	ndr_write_int16(dce, LSA_POLICY_INFO_ACCOUNT_DOMAIN); // level
	ndr_write_int16(dce, 0);

	/* Account Domain */
	gethostname(domain_string, NAME_MAX); // domain string
	len = strlen(domain_string);
	ndr_write_int16(dce, (len+1)*2); // length
	ndr_write_int16(dce, len*2); // size
	dce->num_pointers++;
	ndr_write_int32(dce, dce->num_pointers); // ref pointer

	/* Pointer to Sid */
	dce->num_pointers++;
	ndr_write_int32(dce, dce->num_pointers);
	lsarpc_ndr_write_vstring(dce, domain_string); // domain string
	smb_init_domain_sid(&sid);
	ndr_write_int32(dce, sid.num_subauth); // count
	smb_write_sid(dce, &sid); // sid

	return KSMBD_RPC_OK;
}

static int __lsarpc_entry_processed(struct ksmbd_rpc_pipe *pipe, int i)
{
	gpointer entry;

	entry = g_array_index(pipe->entries, gpointer, i);
	pipe->entries = g_array_remove_index(pipe->entries, i);
	free(entry);
	return 0;
}

static int lsarpc_lookup_sid2_invoke(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	unsigned long long id;
	unsigned int num_sid, i;

	ndr_read_bytes(dce, dce->lr_req.handle, HANDLE_SIZE);

	num_sid = ndr_read_int32(dce);
	ndr_read_int32(dce); // ref pointer
	ndr_read_int32(dce); // max count

	for (i = 0; i < num_sid; i++)
		ndr_read_int32(dce); // ref pointer

	for (i = 0; i < num_sid; i++) {
		struct lsarpc_names_info *ni;
		struct passwd *passwd;
		int rid;

		ni = malloc(sizeof(struct lsarpc_names_info));
		if (!ni)
			break;

		ndr_read_int32(dce); // max count
		smb_read_sid(dce, &ni->sid); // sid
		ni->sid.num_subauth--;
		rid = ni->sid.sub_auth[ni->sid.num_subauth];
		passwd = getpwuid(rid);
		if (!passwd) {
			free(ni);
			continue;
		}

		ni->user = usm_lookup_user(passwd->pw_name);
		if (!ni->user) {
			free(ni);
			continue;
		}

		if (get_sid_info(&ni->sid, &ni->type, ni->domain_str) < 0) {
			free(ni);
			continue;
		}

		pipe->entries = g_array_append_val(pipe->entries, ni);
		pipe->num_entries++;
	}

	pipe->entry_processed = __lsarpc_entry_processed;
	return KSMBD_RPC_OK;
}

static int lsarpc_lookup_sid2_return(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	struct policy_handle *ph;
	int i;

	ph = lsarpc_ph_lookup(dce->lr_req.handle);
	if (!ph)
		return KSMBD_RPC_EBAD_FID;

	dce->num_pointers++;
	ndr_write_int32(dce, dce->num_pointers); // ref pointer
	ndr_write_int32(dce, pipe->num_entries); // count

	dce->num_pointers++;
	ndr_write_int32(dce, dce->num_pointers); // ref pointer
	ndr_write_int32(dce, 32); // max size
	ndr_write_int32(dce, pipe->num_entries); // max count

	for (i = 0; i < pipe->num_entries; i++) {
		struct lsarpc_names_info *ni;
		int max_cnt, actual_cnt;

		ni = (struct lsarpc_names_info *)g_array_index(pipe->entries,
				gpointer, i);
		actual_cnt = strlen(ni->domain_str);
		max_cnt = actual_cnt + 1;
		ndr_write_int16(dce, actual_cnt * 2); // length
		ndr_write_int16(dce, max_cnt * 2); // size
		dce->num_pointers++;
		ndr_write_int32(dce, dce->num_pointers); /* ref pointer for domain name*/
		dce->num_pointers++;
		ndr_write_int32(dce, dce->num_pointers); /* ref pointer for sid*/
	}

	for (i = 0; i < pipe->num_entries; i++) {
		struct lsarpc_names_info *ni;

		ni = (struct lsarpc_names_info *)g_array_index(pipe->entries,
				gpointer, i);
		ndr_write_vstring(dce, ni->domain_str); // domain string
		ndr_write_int32(dce, ni->sid.num_subauth); // count
		smb_write_sid(dce, &ni->sid); // sid
	}

	/* Pointer to Names */
	ndr_write_int32(dce, pipe->num_entries); // count
	dce->num_pointers++; // ref pointer
	ndr_write_int32(dce, dce->num_pointers);
	ndr_write_int32(dce, pipe->num_entries); // max count

	for (i = 0; i < pipe->num_entries; i++) {
		struct lsarpc_names_info *ni;
		int len;

		ni = (struct lsarpc_names_info *)g_array_index(pipe->entries,
				gpointer, i);
		ndr_write_int16(dce, ni->type); // sid type
		ndr_write_int16(dce, 0);
		len = strlen(ni->user->name);
		ndr_write_int16(dce, len); // length
		ndr_write_int16(dce, len); // size
		dce->num_pointers++; // ref pointer
		ndr_write_int32(dce, dce->num_pointers);
		ndr_write_int32(dce, i); // sid index
		ndr_write_int32(dce, 0); // unknown
	}

	for (i = 0; i < pipe->num_entries; i++) {
		struct lsarpc_names_info *ni;

		ni = (struct lsarpc_names_info *)g_array_index(pipe->entries,
				gpointer, i);
		ndr_write_vstring(dce, ni->user->name); // username
	}

	ndr_write_int32(dce, pipe->num_entries); // count
	if (pipe->entry_processed) {
		for (i = 0; i < pipe->num_entries; i++)
			pipe->entry_processed(pipe, 0);
		pipe->num_entries = 0;
	}

	return KSMBD_RPC_OK;
}

static int lsarpc_lookup_names3_invoke(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	struct ndr_uniq_char_ptr username;
	int num_names, i;

	ndr_read_bytes(dce, dce->lr_req.handle, HANDLE_SIZE);

	num_names = ndr_read_int32(dce); // num names
	ndr_read_int32(dce); // max count

	for (i = 0; i < num_names; i++) {
		struct lsarpc_names_info *ni;
		char *name;

		ni = malloc(sizeof(struct lsarpc_names_info));
		if (!ni)
			break;
		ndr_read_int16(dce); // length
		ndr_read_int16(dce); // size
		ndr_read_uniq_vsting_ptr(dce, &username);
		if (strstr(STR_VAL(username), "\\")) {
			strtok(STR_VAL(username), "\\");
			name = strtok(NULL, "\\");
		}

		ni->user = usm_lookup_user(name);
		if (!ni->user)
			break;
		pipe->entries = g_array_append_val(pipe->entries, ni);
		pipe->num_entries++;
		smb_init_domain_sid(&ni->sid);
	}
	pipe->entry_processed = __lsarpc_entry_processed;

	return KSMBD_RPC_OK;
}

static int lsarpc_lookup_names3_return(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	struct policy_handle *ph;
	struct smb_sid sid;
	int len, i;
	char domain_string[NAME_MAX];

	ph = lsarpc_ph_lookup(dce->lr_req.handle);
	if (!ph)
		return KSMBD_RPC_EBAD_FID;

	/* Domain list */
	dce->num_pointers++;
	ndr_write_int32(dce, dce->num_pointers); // ref pointer

	ndr_write_int32(dce, 1); // domain count
	dce->num_pointers++;
	ndr_write_int32(dce, dce->num_pointers); // ref pointer
	ndr_write_int32(dce, 32); // max size
	ndr_write_int32(dce, 1); // max count

	gethostname(domain_string, NAME_MAX);
	len = strlen(domain_string);
	ndr_write_int16(dce, len*2); // domain string length
	ndr_write_int16(dce, (len+1)*2); // domain string size

	dce->num_pointers++;
	ndr_write_int32(dce, dce->num_pointers); // domain string ref pointer
	dce->num_pointers++;
	ndr_write_int32(dce, dce->num_pointers); // sid ref pointer
	lsarpc_ndr_write_vstring(dce, domain_string); // domain string
	smb_init_domain_sid(&sid);
	ndr_write_int32(dce, sid.num_subauth); // sid auth count
	smb_write_sid(dce, &sid); // sid

	ndr_write_int32(dce, pipe->num_entries); // count
	dce->num_pointers++;
	ndr_write_int32(dce, dce->num_pointers); // sid ref id
	ndr_write_int32(dce, pipe->num_entries); // count

	for (i = 0; i < pipe->num_entries; i++) {
		ndr_write_int16(dce, SID_TYPE_USER); // sid type
		ndr_write_int16(dce, 0);
		dce->num_pointers++;
		ndr_write_int32(dce, dce->num_pointers); // ref pointer
		ndr_write_int32(dce, i); // sid index
		ndr_write_int32(dce, 0);
	}

	for (i = 0; i < pipe->num_entries; i++) {
		struct lsarpc_names_info *ni;

		ni = (struct lsarpc_names_info *)g_array_index(pipe->entries,
				gpointer, i);
		ni->sid.sub_auth[ni->sid.num_subauth++] = ni->user->uid;
		ndr_write_int32(dce, ni->sid.num_subauth); // sid auth count
		smb_write_sid(dce, &ni->sid); // sid
	}

	ndr_write_int32(dce, pipe->num_entries);
	if (pipe->entry_processed) {
		for (i = 0; i < pipe->num_entries; i++)
			pipe->entry_processed(pipe, 0);
		pipe->num_entries = 0;
	}

	return KSMBD_RPC_OK;
}

static int lsarpc_close_invoke(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;

	ndr_read_bytes(dce, dce->lr_req.handle, HANDLE_SIZE);

	return KSMBD_RPC_OK;
}

static int lsarpc_close_return(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	struct policy_handle *ph;

	ph = lsarpc_ph_lookup(dce->lr_req.handle);
	if (!ph)
		return KSMBD_RPC_EBAD_FID;
	lsarpc_ph_free(ph);

	ndr_write_int64(dce, 0);
	ndr_write_int64(dce, 0);
	ndr_write_int32(dce, 0);
	return KSMBD_RPC_OK;
}

static int lsarpc_invoke(struct ksmbd_rpc_pipe *pipe)
{
	int ret = KSMBD_RPC_ENOTIMPLEMENTED;

	switch (pipe->dce->req_hdr.opnum) {
	case LSARPC_OPNUM_DS_ROLE_GET_PRIMARY_DOMAIN_INFO || LSARPC_OPNUM_CLOSE:
		if (pipe->dce->hdr.frag_length == 26)
			ret = lsarpc_get_primary_domain_info_invoke(pipe);
		else
			ret = lsarpc_close_invoke(pipe);
		break;
	case LSARPC_OPNUM_OPEN_POLICY2:
		ret = KSMBD_RPC_OK;
		break;
	case LSARPC_OPNUM_QUERY_INFO_POLICY:
		ret = lsarpc_query_info_policy_invoke(pipe);
		break;
	case LSARPC_OPNUM_LOOKUP_SID2:
		ret = lsarpc_lookup_sid2_invoke(pipe);
		break;
	case LSARPC_OPNUM_LOOKUP_NAMES3:
		ret = lsarpc_lookup_names3_invoke(pipe);
		break;
	default:
		pr_err("LSARPC: unsupported INVOKE method %d, alloc_hint : %d\n",
		       pipe->dce->req_hdr.opnum, pipe->dce->req_hdr.alloc_hint);
		break;
	}

	return ret;
}

static int lsarpc_return(struct ksmbd_rpc_pipe *pipe,
			 struct ksmbd_rpc_command *resp,
			 int max_resp_sz)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	int status = KSMBD_RPC_ENOTIMPLEMENTED;

	dce->offset = sizeof(struct dcerpc_header);
	dce->offset += sizeof(struct dcerpc_response_header);

	switch (dce->req_hdr.opnum) {
	case LSARPC_OPNUM_DS_ROLE_GET_PRIMARY_DOMAIN_INFO || LSARPC_OPNUM_CLOSE:
		if (dce->hdr.frag_length == 26)
			status = lsarpc_get_primary_domain_info_return(pipe);
		else
			status = lsarpc_close_return(pipe);
		break;
	case LSARPC_OPNUM_OPEN_POLICY2:
		status = lsarpc_open_policy2_return(pipe);
		break;
	case LSARPC_OPNUM_QUERY_INFO_POLICY:
		status = lsarpc_query_info_policy_return(pipe);
		break;
	case LSARPC_OPNUM_LOOKUP_SID2:
		status = lsarpc_lookup_sid2_return(pipe);
		break;
	case LSARPC_OPNUM_LOOKUP_NAMES3:
		status = lsarpc_lookup_names3_return(pipe);
		break;
	default:
		pr_err("LSARPC: unsupported RETURN method %d\n",
			dce->req_hdr.opnum);
		status = KSMBD_RPC_EBAD_FUNC;
		break;
	}

	/*
	 * [out] DWORD Return value/code
	 */
	ndr_write_int32(dce, status);
	dcerpc_write_headers(dce, status);

	dce->rpc_resp->payload_sz = dce->offset;
	return status;
}

int rpc_lsarpc_read_request(struct ksmbd_rpc_pipe *pipe,
			    struct ksmbd_rpc_command *resp,
			    int max_resp_sz)
{
	return lsarpc_return(pipe, resp, max_resp_sz);
}

int rpc_lsarpc_write_request(struct ksmbd_rpc_pipe *pipe)
{
	return lsarpc_invoke(pipe);
}

int rpc_lsarpc_init(void)
{
	ph_table = g_hash_table_new(g_str_hash, g_str_equal);
	if (!ph_table)
		return -ENOMEM;
	return 0;
}

void rpc_lsarpc_destroy(void)
{
	if (ph_table)
		g_hash_table_destroy(ph_table);
	g_rw_lock_clear(&ph_table_lock);
}
