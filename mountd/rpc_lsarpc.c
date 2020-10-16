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
#define LSARPC_OPNUM_CLOSE				0

#define DS_ROLE_STANDALONE_SERVER	2
#define DS_ROLE_BASIC_INFORMATION	1

#define LSA_POLICY_INFO_ACCOUNT_DOMAIN	5

static GHashTable	*ph_table;
static GRWLock		ph_table_lock;

static void lsarpc_ph_free(struct policy_handle *ph)
{
	if (ph->handle != (unsigned int)-1) {
		g_rw_lock_writer_lock(&ph_table_lock);
		g_hash_table_remove(ph_table, &(ph->handle));
		g_rw_lock_writer_unlock(&ph_table_lock);
	}

	free(ph);
}

static struct policy_handle *lsarpc_ph_alloc(void)
{
	struct policy_handle *ph;
	int ret;

	ph = calloc(1, sizeof(struct policy_handle));
	if (!ph) {
		pr_err("trace 1\n");
		return NULL;
	}

	ph->handle = 1;
	g_rw_lock_writer_lock(&ph_table_lock);
	ret = g_hash_table_insert(ph_table, &(ph->handle), ph);
	g_rw_lock_writer_unlock(&ph_table_lock);

	if (!ret) {
		pr_err("trace 2 ret : %d\n", ret);
		ph->handle = (unsigned int)-1;
		lsarpc_ph_free(ph);
		ph = NULL;
	}

	return ph;
}

static struct policy_handle *lsarpc_ph_lookup(unsigned int handle)
{
	struct policy_handle *ph;

	g_rw_lock_reader_lock(&ph_table_lock);
	ph = g_hash_table_lookup(ph_table, &handle);
	g_rw_lock_reader_unlock(&ph_table_lock);

	return ph;
}

static int lsarpc_get_primary_domain_info_invoke(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	int level;

	level = ndr_read_int16(dce);
	if (level != DS_ROLE_BASIC_INFORMATION)
		return KSMBD_RPC_EBAD_FUNC; 

	return KSMBD_RPC_OK;
}

static int lsarpc_get_primary_domain_info_return(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	int i;
	char domain[256];

	pr_err("%s : %d\n", __func__, __LINE__);
	
	dce->num_pointers++;
	ndr_write_int32(dce, dce->num_pointers);
	ndr_write_int16(dce, 1);
	ndr_write_int16(dce, 0);

	/* Role */
	ndr_write_int16(dce, DS_ROLE_STANDALONE_SERVER);
	ndr_write_int16(dce, 0);

	/* Flags */
	ndr_write_int32(dce, 0);

	dce->num_pointers++;
	ndr_write_int32(dce, dce->num_pointers);

	/* NULL pointer : Pointer to Dns Domain */
	ndr_write_int32(dce, 0);
	/* NULL pointer : Pointer to Forest */
	ndr_write_int32(dce, 0);

	/* NULL Domain guid */
	for (i = 0; i < 16; i++)
		ndr_write_int8(dce, 0);
	
	gethostname(domain, 256);
	ndr_write_vstring(dce, domain);

	return KSMBD_RPC_OK;
}

static int lsarpc_open_policy2_invoke(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	pr_err("%s : %d\n", __func__, __LINE__);

	return KSMBD_RPC_OK;
}

static int lsarpc_open_policy2_return(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
//	struct policy_handle *ph;
	pr_err("%s : %d\n", __func__, __LINE__);

//	ph = lsarpc_ph_alloc();
//	if (!ph)
//		return KSMBD_RPC_ENOMEM;
	/* write connect handle */
	ndr_write_int64(dce, (__u64)pipe->id + 1);
	ndr_write_int64(dce, (__u64)pipe->id + 1);
	ndr_write_int32(dce, 0);
	return KSMBD_RPC_OK;
}

static int __lsarpc_entry_processed(struct ksmbd_rpc_pipe *pipe, int i)
{
	char *name;

//	name = g_array_index(pipe->entries, gpointer, i);
//	pipe->entries = g_array_remove_index(pipe->entries, i);
//	pipe->num_entries--;
	pipe->num_processed++;
//	kfree(name);

	return 0;
}

static int lsarpc_query_info_policy_invoke(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	unsigned long long id;
	int level;

	pr_err("%s : %d\n", __func__, __LINE__);
	id = ndr_read_int64(dce);
	ndr_read_int64(dce);
	ndr_read_int32(dce);

	level = ndr_read_int16(dce);
	if (level != LSA_POLICY_INFO_ACCOUNT_DOMAIN)
		return KSMBD_RPC_EBAD_FUNC; 
	pr_err("%s : %d\n", __func__, __LINE__);

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

	/*
	 * NDR represents a conformant and varying string as an ordered
	 * sequence of representations of the string elements, preceded
	 * by three unsigned long integers. The first integer gives the
	 * maximum number of elements in the string, including the terminator.
	 * The second integer gives the offset from the first index of the
	 * string to the first index of the actual subset being passed.
	 * The third integer gives the actual number of elements being
	 * passed, including the terminator.
	 */
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
	char domain_name[256];
	struct smb_sid sid;
	int len;

	pr_err("%s : %d\n", __func__, __LINE__);
	
	/* Ref ID */
	dce->num_pointers++;
	ndr_write_int32(dce, dce->num_pointers);

	/* Level */
	ndr_write_int16(dce, LSA_POLICY_INFO_ACCOUNT_DOMAIN);
	ndr_write_int16(dce, 0);

	/* Account Domain */
	gethostname(domain_name, 256);
	len = strlen(domain_name);
	ndr_write_int16(dce, (len + 1)*2);
	ndr_write_int16(dce, len*2);
	dce->num_pointers++;
	ndr_write_int32(dce, dce->num_pointers);

	/* Pointer to Sid */
	dce->num_pointers++;
	ndr_write_int32(dce, dce->num_pointers);

	lsarpc_ndr_write_vstring(dce, domain_name);

	smb_init_sid(dce, &sid);
	ndr_write_int32(dce, sid.num_subauth);
	smb_write_sid(dce, &sid);
	pr_err("%s : %d\n", __func__, __LINE__);

	return KSMBD_RPC_OK;
}

static int lsarpc_lookup_sid2_invoke(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
//	struct policy_handle *ph;
	unsigned long long id;
	unsigned int num_sid, i;

	pr_err("%s : %d\n", __func__, __LINE__);
	id = ndr_read_int64(dce);
	ndr_read_int64(dce);
	ndr_read_int32(dce);
//	ph = lsarpc_ph_lookup(id);
//	if (!ph)
//		return KSMBD_RPC_EBAD_FID;

	pr_err("%s : %d\n", __func__, __LINE__);
	num_sid = ndr_read_int32(dce);
	ndr_read_int32(dce); // read Ref ID
	ndr_read_int32(dce); // read Max Count

	pr_err("%s : %d\n", __func__, __LINE__);
	for (i = 0; i < num_sid; i++)
		ndr_read_int32(dce); // read Ref ID

	pr_err("%s : %d\n", __func__, __LINE__);
	for (i = 0; i < num_sid; i++) {
		struct user_info *ui;
		struct passwd *passwd;
		struct ksmbd_user *user;
		int rid;

		ui = malloc(sizeof(struct user_info));
		if (!ui)
			break;

	pr_err("%s : %d\n", __func__, __LINE__);
		ndr_read_int32(dce); // read Max Count
		smb_read_sid(dce, &ui->sid);
		ui->sid.num_subauth--;
	pr_err("%s : %d\n", __func__, __LINE__);
		rid = ui->sid.sub_auth[ui->sid.num_subauth];
		passwd = getpwuid(rid);
	pr_err("%s : %d, rid : %d, passwd : %p\n", __func__, __LINE__, rid, passwd);
		if (!passwd) {
			free(ui);
			continue;
		}

		user = usm_lookup_user(passwd->pw_name);
		if (!user)
			break;
	pr_err("%s : %d\n", __func__, __LINE__);

		ui->user = user;

	pr_err("%s : %d\n", __func__, __LINE__);
		if (get_sid_info(&ui->sid, &ui->type, ui->domain_name) < 0);
			break;
	pr_err("%s : %d\n", __func__, __LINE__);

		pipe->entries = g_array_append_val(pipe->entries, ui);
		pipe->num_entries++;
	pr_err("%s : %d\n", __func__, __LINE__);
	}

	pipe->entry_processed = __lsarpc_entry_processed;

	return KSMBD_RPC_OK;
}

static int lsarpc_lookup_sid2_return(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	int i;

	pr_err("%s : %d\n", __func__, __LINE__);

	dce->num_pointers++;
	ndr_write_int32(dce, dce->num_pointers);
	ndr_write_int32(dce, pipe->num_entries);

	dce->num_pointers++;
	ndr_write_int32(dce, dce->num_pointers);
	ndr_write_int32(dce, pipe->num_entries);

	for (i = 0; i < pipe->num_entries; i++) {
		struct user_info *ui;
		int max_cnt, actual_cnt;

		ui = (struct user_info *)g_array_index(pipe->entries, gpointer, i);
		actual_cnt = strlen(ui->domain_name);
		max_cnt = actual_cnt + 1;

		/* Length */
		ndr_write_int32(dce, actual_cnt * 2);
		/* Size */
		ndr_write_int32(dce, max_cnt * 2);

		dce->num_pointers++;
		ndr_write_int32(dce, dce->num_pointers); /* ref pointer for domain name*/
		dce->num_pointers++;
		ndr_write_int32(dce, dce->num_pointers); /* ref pointer for sid*/
	}

	for (i = 0; i < pipe->num_entries; i++) {
		struct user_info *ui;

		ui = (struct user_info *)g_array_index(pipe->entries, gpointer, i);
		ndr_write_vstring(dce, ui->domain_name);

		/* Count */
		ndr_write_int32(dce, ui->sid.num_subauth);
		smb_write_sid(dce, &ui->sid);
	}

	/* Pointer to Names */	
	ndr_write_int32(dce, pipe->num_entries);
	/* Ref ID */
	dce->num_pointers++;
	ndr_write_int32(dce, dce->num_pointers);
	/* Max Count */
	ndr_write_int32(dce, pipe->num_entries);

	for (i = 0; i < pipe->num_entries; i++) {
		struct user_info *ui;
		int len;

		ui = (struct user_info *)g_array_index(pipe->entries, gpointer, i);

		/* Sid Type */
		ndr_write_int16(dce, ui->type);
		ndr_write_int16(dce, 0);

		len = strlen(ui->user->name);
		/* Length and Size */
		ndr_write_int16(dce, len);
		ndr_write_int16(dce, len);
		
		/* Ref ID */
		dce->num_pointers++;
		ndr_write_int32(dce, dce->num_pointers);

		/* Sid Index */
		ndr_write_int32(dce, i);
		ndr_write_int32(dce, 0);
	}

	for (i = 0; i < pipe->num_entries; i++) {
		struct user_info *ui;

		ui = (struct user_info *)g_array_index(pipe->entries, gpointer, i);
		ndr_write_vstring(dce, ui->user->name);

		/* Count */
		ndr_write_int32(dce, ui->sid.num_subauth);
		smb_write_sid(dce, &ui->sid);
	}
	
	/* Count */
	ndr_write_int32(dce, pipe->num_entries);

	if (pipe->entry_processed) {
		for (i = 0; i < pipe->num_entries; i++)
			pipe->entry_processed(pipe, 0);
	}
	return KSMBD_RPC_OK;
}

static int lsarpc_close_return(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
//	struct policy_handle *ph;
//	unsigned long long id;
	int i;

	pr_err("%s : %d\n", __func__, __LINE__);
//	id = ndr_read_int64(dce);
//	ph = lsarpc_ph_lookup(id);
//	if (!ph)
//		return KSMBD_RPC_EBAD_FID;

//	lsarpc_ph_free(ph);

	for (i = 0; i < pipe->num_entries; i++) {
		gpointer entry;

		entry = g_array_index(pipe->entries, gpointer, i);
		pipe->entries = g_array_remove_index(pipe->entries, i);
		free(entry);
	}

	ndr_write_int64(dce, 0);
	ndr_write_int64(dce, 0);
	ndr_write_int32(dce, 0);
}

static int lsarpc_invoke(struct ksmbd_rpc_pipe *pipe)
{
	int ret = KSMBD_RPC_ENOTIMPLEMENTED;

	pr_err("%s : %d\n", __func__, __LINE__);
	switch (pipe->dce->req_hdr.opnum) {
	case LSARPC_OPNUM_DS_ROLE_GET_PRIMARY_DOMAIN_INFO || LSARPC_OPNUM_CLOSE:
		if (pipe->dce->hdr.frag_length == 26)
			ret = lsarpc_get_primary_domain_info_invoke(pipe);
		else
			ret = KSMBD_RPC_OK;
		break;
	case LSARPC_OPNUM_OPEN_POLICY2:
		ret = lsarpc_open_policy2_invoke(pipe);
		break;
	case LSARPC_OPNUM_QUERY_INFO_POLICY:
		ret = lsarpc_query_info_policy_invoke(pipe);
		break;
	case LSARPC_OPNUM_LOOKUP_SID2:
		ret = lsarpc_lookup_sid2_invoke(pipe);
		break;
	default:
		pr_err("LSARPC: unsupported INVOKE method %d, alloc_hint : %d\n",
		       pipe->dce->req_hdr.opnum, pipe->dce->req_hdr.alloc_hint);
		break;
	}
	pr_err("%s : %d\n", __func__, __LINE__);

	return ret;
}

static int lsarpc_return(struct ksmbd_rpc_pipe *pipe,
			 struct ksmbd_rpc_command *resp,
			 int max_resp_sz)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	int status = KSMBD_RPC_ENOTIMPLEMENTED;

	pr_err("%s : %d\n", __func__, __LINE__);
	/*
	 * Reserve space for response NDR header. We don't know yet if
	 * the payload buffer is big enough. This will determine if we
	 * can set DCERPC_PFC_FIRST_FRAG|DCERPC_PFC_LAST_FRAG or if we
	 * will have a multi-part response.
	 */
	dce->offset = sizeof(struct dcerpc_header);
	dce->offset += sizeof(struct dcerpc_response_header);
	pipe->num_processed = 0;

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
	default:
		pr_err("LSARPC: unsupported RETURN method %d\n",
			dce->req_hdr.opnum);
		status = KSMBD_RPC_EBAD_FUNC;
		break;
	}

	/*
	 * [out] DWORD Return value/code
	 */
	printf("status : %d\n", status);
	ndr_write_int32(dce, status);
	dcerpc_write_headers(dce, status);

	dce->rpc_resp->payload_sz = dce->offset;
	pr_err("%s : %d, payload_sz : %d\n", __func__, __LINE__, dce->rpc_resp->payload_sz);
	return status;
}

int rpc_lsarpc_read_request(struct ksmbd_rpc_pipe *pipe,
			    struct ksmbd_rpc_command *resp,
			    int max_resp_sz)
{
	pr_err("%s : %d\n", __func__, __LINE__);
	return lsarpc_return(pipe, resp, max_resp_sz);
}

int rpc_lsarpc_write_request(struct ksmbd_rpc_pipe *pipe)
{
	pr_err("%s : %d\n", __func__, __LINE__);
	return lsarpc_invoke(pipe);
}
