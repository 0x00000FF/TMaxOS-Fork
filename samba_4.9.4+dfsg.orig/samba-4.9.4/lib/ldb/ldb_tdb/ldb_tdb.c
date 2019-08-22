/*
   ldb database library

   Copyright (C) Andrew Tridgell 2004
   Copyright (C) Stefan Metzmacher 2004
   Copyright (C) Simo Sorce 2006-2008
   Copyright (C) Matthias Dieter Wallnöfer 2009-2010

     ** NOTE! The following LGPL license applies to the ldb
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

/*
 *  Name: ldb_tdb
 *
 *  Component: ldb tdb backend
 *
 *  Description: core functions for tdb backend
 *
 *  Author: Andrew Tridgell
 *  Author: Stefan Metzmacher
 *
 *  Modifications:
 *
 *  - description: make the module use asynchronous calls
 *    date: Feb 2006
 *    Author: Simo Sorce
 *
 *  - description: make it possible to use event contexts
 *    date: Jan 2008
 *    Author: Simo Sorce
 *
 *  - description: fix up memory leaks and small bugs
 *    date: Oct 2009
 *    Author: Matthias Dieter Wallnöfer
 */

#include "ldb_tdb.h"
#include "ldb_private.h"
#include <tdb.h>

/*
  prevent memory errors on callbacks
*/
struct ltdb_req_spy {
	struct ltdb_context *ctx;
};

/*
  map a tdb error code to a ldb error code
*/
int ltdb_err_map(enum TDB_ERROR tdb_code)
{
	switch (tdb_code) {
	case TDB_SUCCESS:
		return LDB_SUCCESS;
	case TDB_ERR_CORRUPT:
	case TDB_ERR_OOM:
	case TDB_ERR_EINVAL:
		return LDB_ERR_OPERATIONS_ERROR;
	case TDB_ERR_IO:
		return LDB_ERR_PROTOCOL_ERROR;
	case TDB_ERR_LOCK:
	case TDB_ERR_NOLOCK:
		return LDB_ERR_BUSY;
	case TDB_ERR_LOCK_TIMEOUT:
		return LDB_ERR_TIME_LIMIT_EXCEEDED;
	case TDB_ERR_EXISTS:
		return LDB_ERR_ENTRY_ALREADY_EXISTS;
	case TDB_ERR_NOEXIST:
		return LDB_ERR_NO_SUCH_OBJECT;
	case TDB_ERR_RDONLY:
		return LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS;
	default:
		break;
	}
	return LDB_ERR_OTHER;
}

/*
  lock the database for read - use by ltdb_search and ltdb_sequence_number
*/
static int ltdb_lock_read(struct ldb_module *module)
{
	void *data = ldb_module_get_private(module);
	struct ltdb_private *ltdb = talloc_get_type(data, struct ltdb_private);
	int tdb_ret = 0;
	int ret;
	pid_t pid = getpid();

	if (ltdb->pid != pid) {
		ldb_asprintf_errstring(
			ldb_module_get_ctx(module),
			__location__": Reusing ldb opend by pid %d in "
			"process %d\n",
			ltdb->pid,
			pid);
		return LDB_ERR_PROTOCOL_ERROR;
	}

	if (tdb_transaction_active(ltdb->tdb) == false &&
	    ltdb->read_lock_count == 0) {
		tdb_ret = tdb_lockall_read(ltdb->tdb);
	}
	if (tdb_ret == 0) {
		ltdb->read_lock_count++;
		return LDB_SUCCESS;
	}
	ret = ltdb_err_map(tdb_error(ltdb->tdb));
	if (ret == LDB_SUCCESS) {
		ret = LDB_ERR_OPERATIONS_ERROR;
	}
	ldb_debug_set(ldb_module_get_ctx(module),
		      LDB_DEBUG_FATAL,
		      "Failure during ltdb_lock_read(): %s -> %s",
		      tdb_errorstr(ltdb->tdb),
		      ldb_strerror(ret));
	return ret;
}

/*
  unlock the database after a ltdb_lock_read()
*/
static int ltdb_unlock_read(struct ldb_module *module)
{
	void *data = ldb_module_get_private(module);
	struct ltdb_private *ltdb = talloc_get_type(data, struct ltdb_private);
	pid_t pid = getpid();

	if (ltdb->pid != pid) {
		ldb_asprintf_errstring(
			ldb_module_get_ctx(module),
			__location__": Reusing ldb opend by pid %d in "
			"process %d\n",
			ltdb->pid,
			pid);
		return LDB_ERR_PROTOCOL_ERROR;
	}
	if (!tdb_transaction_active(ltdb->tdb) && ltdb->read_lock_count == 1) {
		tdb_unlockall_read(ltdb->tdb);
		ltdb->read_lock_count--;
		return 0;
	}
	ltdb->read_lock_count--;
	return 0;
}


/* 
 * Determine if this key could hold a record.  We allow the new GUID
 * index, the old DN index and a possible future ID=
 */
bool ltdb_key_is_record(TDB_DATA key)
{
	if (key.dsize < 4) {
		return false;
	}

	if (memcmp(key.dptr, "DN=", 3) == 0) {
		return true;
	}
	
	if (memcmp(key.dptr, "ID=", 3) == 0) {
		return true;
	}

	if (key.dsize < sizeof(LTDB_GUID_KEY_PREFIX)) {
		return false;
	}

	if (memcmp(key.dptr, LTDB_GUID_KEY_PREFIX,
		   sizeof(LTDB_GUID_KEY_PREFIX) - 1) == 0) {
		return true;
	}
	
	return false;
}

/*
  form a TDB_DATA for a record key
  caller frees

  note that the key for a record can depend on whether the
  dn refers to a case sensitive index record or not
*/
TDB_DATA ltdb_key_dn(struct ldb_module *module, TALLOC_CTX *mem_ctx,
		     struct ldb_dn *dn)
{
	TDB_DATA key;
	char *key_str = NULL;
	const char *dn_folded = NULL;

	/*
	  most DNs are case insensitive. The exception is index DNs for
	  case sensitive attributes

	  there are 3 cases dealt with in this code:

	  1) if the dn doesn't start with @ then uppercase the attribute
             names and the attributes values of case insensitive attributes
	  2) if the dn starts with @ then leave it alone -
	     the indexing code handles the rest
	*/

	dn_folded = ldb_dn_get_casefold(dn);
	if (!dn_folded) {
		goto failed;
	}

	key_str = talloc_strdup(mem_ctx, "DN=");
	if (!key_str) {
		goto failed;
	}

	key_str = talloc_strdup_append_buffer(key_str, dn_folded);
	if (!key_str) {
		goto failed;
	}

	key.dptr = (uint8_t *)key_str;
	key.dsize = strlen(key_str) + 1;

	return key;

failed:
	errno = ENOMEM;
	key.dptr = NULL;
	key.dsize = 0;
	return key;
}

/* The caller is to provide a correctly sized key */
int ltdb_guid_to_key(struct ldb_module *module,
		     struct ltdb_private *ltdb,
		     const struct ldb_val *GUID_val,
		     TDB_DATA *key)
{
	const char *GUID_prefix = LTDB_GUID_KEY_PREFIX;
	const int GUID_prefix_len = sizeof(LTDB_GUID_KEY_PREFIX) - 1;

	if (key->dsize != (GUID_val->length+GUID_prefix_len)) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	memcpy(key->dptr, GUID_prefix, GUID_prefix_len);
	memcpy(&key->dptr[GUID_prefix_len],
	       GUID_val->data, GUID_val->length);
	return LDB_SUCCESS;
}

/*
 * The caller is to provide a correctly sized key, used only in
 * the GUID index mode
 */
int ltdb_idx_to_key(struct ldb_module *module,
		    struct ltdb_private *ltdb,
		    TALLOC_CTX *mem_ctx,
		    const struct ldb_val *idx_val,
		    TDB_DATA *key)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct ldb_dn *dn;

	if (ltdb->cache->GUID_index_attribute != NULL) {
		return ltdb_guid_to_key(module, ltdb,
					idx_val, key);
	}

	dn = ldb_dn_from_ldb_val(mem_ctx, ldb, idx_val);
	if (dn == NULL) {
		/*
		 * LDB_ERR_INVALID_DN_SYNTAX would just be confusing
		 * to the caller, as this in an invalid index value
		 */
		return LDB_ERR_OPERATIONS_ERROR;
	}
	/* form the key */
	*key = ltdb_key_dn(module, mem_ctx, dn);
	TALLOC_FREE(dn);
	if (!key->dptr) {
		return ldb_module_oom(module);
	}
	return LDB_SUCCESS;
}

/*
  form a TDB_DATA for a record key
  caller frees mem_ctx, which may or may not have the key
  as a child.

  note that the key for a record can depend on whether a
  GUID index is in use, or the DN is used as the key
*/
TDB_DATA ltdb_key_msg(struct ldb_module *module, TALLOC_CTX *mem_ctx,
		      const struct ldb_message *msg)
{
	void *data = ldb_module_get_private(module);
	struct ltdb_private *ltdb = talloc_get_type(data, struct ltdb_private);
	TDB_DATA key;
	const struct ldb_val *guid_val;
	int ret;

	if (ltdb->cache->GUID_index_attribute == NULL) {
		return ltdb_key_dn(module, mem_ctx, msg->dn);
	}

	if (ldb_dn_is_special(msg->dn)) {
		return ltdb_key_dn(module, mem_ctx, msg->dn);
	}

	guid_val = ldb_msg_find_ldb_val(msg,
				       ltdb->cache->GUID_index_attribute);
	if (guid_val == NULL) {
		ldb_asprintf_errstring(ldb_module_get_ctx(module),
				       "Did not find GUID attribute %s "
				       "in %s, required for TDB record "
				       "key in " LTDB_IDXGUID " mode.",
				       ltdb->cache->GUID_index_attribute,
				       ldb_dn_get_linearized(msg->dn));
		errno = EINVAL;
		key.dptr = NULL;
		key.dsize = 0;
		return key;
	}

	/* In this case, allocate with talloc */
	key.dptr = talloc_size(mem_ctx, LTDB_GUID_KEY_SIZE);
	if (key.dptr == NULL) {
		errno = ENOMEM;
		key.dptr = NULL;
		key.dsize = 0;
		return key;
	}
	key.dsize = talloc_get_size(key.dptr);

	ret = ltdb_guid_to_key(module, ltdb, guid_val, &key);

	if (ret != LDB_SUCCESS) {
		errno = EINVAL;
		key.dptr = NULL;
		key.dsize = 0;
		return key;
	}
	return key;
}

/*
  check special dn's have valid attributes
  currently only @ATTRIBUTES is checked
*/
static int ltdb_check_special_dn(struct ldb_module *module,
				 const struct ldb_message *msg)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	unsigned int i, j;

	if (! ldb_dn_is_special(msg->dn) ||
	    ! ldb_dn_check_special(msg->dn, LTDB_ATTRIBUTES)) {
		return LDB_SUCCESS;
	}

	/* we have @ATTRIBUTES, let's check attributes are fine */
	/* should we check that we deny multivalued attributes ? */
	for (i = 0; i < msg->num_elements; i++) {
		if (ldb_attr_cmp(msg->elements[i].name, "distinguishedName") == 0) continue;

		for (j = 0; j < msg->elements[i].num_values; j++) {
			if (ltdb_check_at_attributes_values(&msg->elements[i].values[j]) != 0) {
				ldb_set_errstring(ldb, "Invalid attribute value in an @ATTRIBUTES entry");
				return LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;
			}
		}
	}

	return LDB_SUCCESS;
}


/*
  we've made a modification to a dn - possibly reindex and
  update sequence number
*/
static int ltdb_modified(struct ldb_module *module, struct ldb_dn *dn)
{
	int ret = LDB_SUCCESS;
	struct ltdb_private *ltdb = talloc_get_type(ldb_module_get_private(module), struct ltdb_private);

	/* only allow modifies inside a transaction, otherwise the
	 * ldb is unsafe */
	if (ltdb->kv_ops->transaction_active(ltdb) == false) {
		ldb_set_errstring(ldb_module_get_ctx(module), "ltdb modify without transaction");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (ldb_dn_is_special(dn) &&
	    (ldb_dn_check_special(dn, LTDB_INDEXLIST) ||
	     ldb_dn_check_special(dn, LTDB_ATTRIBUTES)) )
	{
		if (ltdb->warn_reindex) {
			ldb_debug(ldb_module_get_ctx(module),
				LDB_DEBUG_ERROR, "Reindexing %s due to modification on %s",
				ltdb->kv_ops->name(ltdb), ldb_dn_get_linearized(dn));
		}
		ret = ltdb_reindex(module);
	}

	/* If the modify was to a normal record, or any special except @BASEINFO, update the seq number */
	if (ret == LDB_SUCCESS &&
	    !(ldb_dn_is_special(dn) &&
	      ldb_dn_check_special(dn, LTDB_BASEINFO)) ) {
		ret = ltdb_increase_sequence_number(module);
	}

	/* If the modify was to @OPTIONS, reload the cache */
	if (ret == LDB_SUCCESS &&
	    ldb_dn_is_special(dn) &&
	    (ldb_dn_check_special(dn, LTDB_OPTIONS)) ) {
		ret = ltdb_cache_reload(module);
	}

	if (ret != LDB_SUCCESS) {
		ltdb->reindex_failed = true;
	}

	return ret;
}

static int ltdb_tdb_store(struct ltdb_private *ltdb, struct ldb_val ldb_key,
			  struct ldb_val ldb_data, int flags)
{
	TDB_DATA key = {
		.dptr = ldb_key.data,
		.dsize = ldb_key.length
	};
	TDB_DATA data = {
		.dptr = ldb_data.data,
		.dsize = ldb_data.length
	};
	bool transaction_active = tdb_transaction_active(ltdb->tdb);
	if (transaction_active == false){
		return LDB_ERR_PROTOCOL_ERROR;
	}
	return tdb_store(ltdb->tdb, key, data, flags);
}

static int ltdb_error(struct ltdb_private *ltdb)
{
	return ltdb_err_map(tdb_error(ltdb->tdb));
}

static const char *ltdb_errorstr(struct ltdb_private *ltdb)
{
	return tdb_errorstr(ltdb->tdb);
}

/*
  store a record into the db
*/
int ltdb_store(struct ldb_module *module, const struct ldb_message *msg, int flgs)
{
	void *data = ldb_module_get_private(module);
	struct ltdb_private *ltdb = talloc_get_type(data, struct ltdb_private);
	TDB_DATA tdb_key;
	struct ldb_val ldb_key;
	struct ldb_val ldb_data;
	int ret = LDB_SUCCESS;
	TALLOC_CTX *tdb_key_ctx = talloc_new(module);

	if (tdb_key_ctx == NULL) {
		return ldb_module_oom(module);
	}

	if (ltdb->read_only) {
		talloc_free(tdb_key_ctx);
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	tdb_key = ltdb_key_msg(module, tdb_key_ctx, msg);
	if (tdb_key.dptr == NULL) {
		TALLOC_FREE(tdb_key_ctx);
		return LDB_ERR_OTHER;
	}

	ret = ldb_pack_data(ldb_module_get_ctx(module),
			    msg, &ldb_data);
	if (ret == -1) {
		TALLOC_FREE(tdb_key_ctx);
		return LDB_ERR_OTHER;
	}

	ldb_key.data = tdb_key.dptr;
	ldb_key.length = tdb_key.dsize;

	ret = ltdb->kv_ops->store(ltdb, ldb_key, ldb_data, flgs);
	if (ret != 0) {
		bool is_special = ldb_dn_is_special(msg->dn);
		ret = ltdb->kv_ops->error(ltdb);

		/*
		 * LDB_ERR_ENTRY_ALREADY_EXISTS means the DN, not
		 * the GUID, so re-map
		 */
		if (ret == LDB_ERR_ENTRY_ALREADY_EXISTS
		    && !is_special
		    && ltdb->cache->GUID_index_attribute != NULL) {
			ret = LDB_ERR_CONSTRAINT_VIOLATION;
		}
		goto done;
	}

done:
	TALLOC_FREE(tdb_key_ctx);
	talloc_free(ldb_data.data);

	return ret;
}


/*
  check if a attribute is a single valued, for a given element
 */
static bool ldb_tdb_single_valued(const struct ldb_schema_attribute *a,
				  struct ldb_message_element *el)
{
	if (!a) return false;
	if (el != NULL) {
		if (el->flags & LDB_FLAG_INTERNAL_FORCE_SINGLE_VALUE_CHECK) {
			/* override from a ldb module, for example
			   used for the description field, which is
			   marked multi-valued in the schema but which
			   should not actually accept multiple
			   values */
			return true;
		}
		if (el->flags & LDB_FLAG_INTERNAL_DISABLE_SINGLE_VALUE_CHECK) {
			/* override from a ldb module, for example used for
			   deleted linked attribute entries */
			return false;
		}
	}
	if (a->flags & LDB_ATTR_FLAG_SINGLE_VALUE) {
		return true;
	}
	return false;
}

static int ltdb_add_internal(struct ldb_module *module,
			     struct ltdb_private *ltdb,
			     const struct ldb_message *msg,
			     bool check_single_value)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	int ret = LDB_SUCCESS;
	unsigned int i;
	bool valid_dn = false;

	/* Check the new DN is reasonable */
	valid_dn = ldb_dn_validate(msg->dn);
	if (valid_dn == false) {
		ldb_asprintf_errstring(ldb_module_get_ctx(module),
				       "Invalid DN in ADD: %s",
				       ldb_dn_get_linearized(msg->dn));
		return LDB_ERR_INVALID_DN_SYNTAX;
	}

	for (i=0;i<msg->num_elements;i++) {
		struct ldb_message_element *el = &msg->elements[i];
		const struct ldb_schema_attribute *a = ldb_schema_attribute_by_name(ldb, el->name);

		if (el->num_values == 0) {
			ldb_asprintf_errstring(ldb, "attribute '%s' on '%s' specified, but with 0 values (illegal)",
					       el->name, ldb_dn_get_linearized(msg->dn));
			return LDB_ERR_CONSTRAINT_VIOLATION;
		}
		if (check_single_value &&
				el->num_values > 1 &&
				ldb_tdb_single_valued(a, el)) {
			ldb_asprintf_errstring(ldb, "SINGLE-VALUE attribute %s on %s specified more than once",
					       el->name, ldb_dn_get_linearized(msg->dn));
			return LDB_ERR_CONSTRAINT_VIOLATION;
		}

		/* Do not check "@ATTRIBUTES" for duplicated values */
		if (ldb_dn_is_special(msg->dn) &&
		    ldb_dn_check_special(msg->dn, LTDB_ATTRIBUTES)) {
			continue;
		}

		if (check_single_value &&
		    !(el->flags &
		      LDB_FLAG_INTERNAL_DISABLE_SINGLE_VALUE_CHECK)) {
			struct ldb_val *duplicate = NULL;

			ret = ldb_msg_find_duplicate_val(ldb, discard_const(msg),
							 el, &duplicate, 0);
			if (ret != LDB_SUCCESS) {
				return ret;
			}
			if (duplicate != NULL) {
				ldb_asprintf_errstring(
					ldb,
					"attribute '%s': value '%.*s' on '%s' "
					"provided more than once in ADD object",
					el->name,
					(int)duplicate->length,
					duplicate->data,
					ldb_dn_get_linearized(msg->dn));
				return LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS;
			}
		}
	}

	ret = ltdb_store(module, msg, TDB_INSERT);
	if (ret != LDB_SUCCESS) {
		/*
		 * Try really hard to get the right error code for
		 * a re-add situation, as this can matter!
		 */
		if (ret == LDB_ERR_CONSTRAINT_VIOLATION) {
			int ret2;
			struct ldb_dn *dn2 = NULL;
			TALLOC_CTX *mem_ctx = talloc_new(module);
			if (mem_ctx == NULL) {
				return ldb_module_operr(module);
			}
			ret2 = ltdb_search_base(module, mem_ctx,
						msg->dn, &dn2);
			TALLOC_FREE(mem_ctx);
			if (ret2 == LDB_SUCCESS) {
				ret = LDB_ERR_ENTRY_ALREADY_EXISTS;
			}
		}
		if (ret == LDB_ERR_ENTRY_ALREADY_EXISTS) {
			ldb_asprintf_errstring(ldb,
					       "Entry %s already exists",
					       ldb_dn_get_linearized(msg->dn));
		}
		return ret;
	}

	ret = ltdb_index_add_new(module, ltdb, msg);
	if (ret != LDB_SUCCESS) {
		/*
		 * If we failed to index, delete the message again.
		 *
		 * This is particularly important for the GUID index
		 * case, which will only fail for a duplicate DN
		 * in the index add.
		 *
		 * Note that the caller may not cancel the transation
		 * and this means the above add might really show up!
		 */
		ltdb_delete_noindex(module, msg);
		return ret;
	}

	ret = ltdb_modified(module, msg->dn);

	return ret;
}

/*
  add a record to the database
*/
static int ltdb_add(struct ltdb_context *ctx)
{
	struct ldb_module *module = ctx->module;
	struct ldb_request *req = ctx->req;
	void *data = ldb_module_get_private(module);
	struct ltdb_private *ltdb = talloc_get_type(data, struct ltdb_private);
	int ret = LDB_SUCCESS;

	if (ltdb->max_key_length != 0 &&
	    ltdb->cache->GUID_index_attribute == NULL &&
	    !ldb_dn_is_special(req->op.add.message->dn))
	{
		ldb_set_errstring(ldb_module_get_ctx(module),
				  "Must operate ldb_mdb in GUID "
				  "index mode, but " LTDB_IDXGUID " not set.");
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	ret = ltdb_check_special_dn(module, req->op.add.message);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ldb_request_set_state(req, LDB_ASYNC_PENDING);

	if (ltdb_cache_load(module) != 0) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ltdb_add_internal(module, ltdb,
				req->op.add.message, true);

	return ret;
}

static int ltdb_tdb_delete(struct ltdb_private *ltdb, struct ldb_val ldb_key)
{
	TDB_DATA tdb_key = {
		.dptr = ldb_key.data,
		.dsize = ldb_key.length
	};
	bool transaction_active = tdb_transaction_active(ltdb->tdb);
	if (transaction_active == false){
		return LDB_ERR_PROTOCOL_ERROR;
	}
	return tdb_delete(ltdb->tdb, tdb_key);
}

/*
  delete a record from the database, not updating indexes (used for deleting
  index records)
*/
int ltdb_delete_noindex(struct ldb_module *module,
			const struct ldb_message *msg)
{
	void *data = ldb_module_get_private(module);
	struct ltdb_private *ltdb = talloc_get_type(data, struct ltdb_private);
	struct ldb_val ldb_key;
	TDB_DATA tdb_key;
	int ret;
	TALLOC_CTX *tdb_key_ctx = talloc_new(module);

	if (tdb_key_ctx == NULL) {
		return ldb_module_oom(module);
	}

	if (ltdb->read_only) {
		talloc_free(tdb_key_ctx);
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	tdb_key = ltdb_key_msg(module, tdb_key_ctx, msg);
	if (!tdb_key.dptr) {
		TALLOC_FREE(tdb_key_ctx);
		return LDB_ERR_OTHER;
	}

	ldb_key.data = tdb_key.dptr;
	ldb_key.length = tdb_key.dsize;

	ret = ltdb->kv_ops->delete(ltdb, ldb_key);
	TALLOC_FREE(tdb_key_ctx);

	if (ret != 0) {
		ret = ltdb->kv_ops->error(ltdb);
	}

	return ret;
}

static int ltdb_delete_internal(struct ldb_module *module, struct ldb_dn *dn)
{
	struct ldb_message *msg;
	int ret = LDB_SUCCESS;

	msg = ldb_msg_new(module);
	if (msg == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* in case any attribute of the message was indexed, we need
	   to fetch the old record */
	ret = ltdb_search_dn1(module, dn, msg, LDB_UNPACK_DATA_FLAG_NO_DATA_ALLOC);
	if (ret != LDB_SUCCESS) {
		/* not finding the old record is an error */
		goto done;
	}

	ret = ltdb_delete_noindex(module, msg);
	if (ret != LDB_SUCCESS) {
		goto done;
	}

	/* remove any indexed attributes */
	ret = ltdb_index_delete(module, msg);
	if (ret != LDB_SUCCESS) {
		goto done;
	}

	ret = ltdb_modified(module, dn);
	if (ret != LDB_SUCCESS) {
		goto done;
	}

done:
	talloc_free(msg);
	return ret;
}

/*
  delete a record from the database
*/
static int ltdb_delete(struct ltdb_context *ctx)
{
	struct ldb_module *module = ctx->module;
	struct ldb_request *req = ctx->req;
	int ret = LDB_SUCCESS;

	ldb_request_set_state(req, LDB_ASYNC_PENDING);

	if (ltdb_cache_load(module) != 0) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ltdb_delete_internal(module, req->op.del.dn);

	return ret;
}

/*
  find an element by attribute name. At the moment this does a linear search,
  it should be re-coded to use a binary search once all places that modify
  records guarantee sorted order

  return the index of the first matching element if found, otherwise -1
*/
static int find_element(const struct ldb_message *msg, const char *name)
{
	unsigned int i;
	for (i=0;i<msg->num_elements;i++) {
		if (ldb_attr_cmp(msg->elements[i].name, name) == 0) {
			return i;
		}
	}
	return -1;
}


/*
  add an element to an existing record. Assumes a elements array that we
  can call re-alloc on, and assumed that we can re-use the data pointers from
  the passed in additional values. Use with care!

  returns 0 on success, -1 on failure (and sets errno)
*/
static int ltdb_msg_add_element(struct ldb_message *msg,
				struct ldb_message_element *el)
{
	struct ldb_message_element *e2;
	unsigned int i;

	if (el->num_values == 0) {
		/* nothing to do here - we don't add empty elements */
		return 0;
	}

	e2 = talloc_realloc(msg, msg->elements, struct ldb_message_element,
			      msg->num_elements+1);
	if (!e2) {
		errno = ENOMEM;
		return -1;
	}

	msg->elements = e2;

	e2 = &msg->elements[msg->num_elements];

	e2->name = el->name;
	e2->flags = el->flags;
	e2->values = talloc_array(msg->elements,
				  struct ldb_val, el->num_values);
	if (!e2->values) {
		errno = ENOMEM;
		return -1;
	}
	for (i=0;i<el->num_values;i++) {
		e2->values[i] = el->values[i];
	}
	e2->num_values = el->num_values;

	++msg->num_elements;

	return 0;
}

/*
  delete all elements having a specified attribute name
*/
static int msg_delete_attribute(struct ldb_module *module,
				struct ltdb_private *ltdb,
				struct ldb_message *msg, const char *name)
{
	unsigned int i;
	int ret;
	struct ldb_message_element *el;
	bool is_special = ldb_dn_is_special(msg->dn);

	if (!is_special
	    && ltdb->cache->GUID_index_attribute != NULL
	    && ldb_attr_cmp(name, ltdb->cache->GUID_index_attribute) == 0) {
		struct ldb_context *ldb = ldb_module_get_ctx(module);
		ldb_asprintf_errstring(ldb, "Must not modify GUID "
				       "attribute %s (used as DB index)",
				       ltdb->cache->GUID_index_attribute);
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}

	el = ldb_msg_find_element(msg, name);
	if (el == NULL) {
		return LDB_ERR_NO_SUCH_ATTRIBUTE;
	}
	i = el - msg->elements;

	ret = ltdb_index_del_element(module, ltdb, msg, el);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	talloc_free(el->values);
	if (msg->num_elements > (i+1)) {
		memmove(el, el+1, sizeof(*el) * (msg->num_elements - (i+1)));
	}
	msg->num_elements--;
	msg->elements = talloc_realloc(msg, msg->elements,
				       struct ldb_message_element,
				       msg->num_elements);
	return LDB_SUCCESS;
}

/*
  delete all elements matching an attribute name/value

  return LDB Error on failure
*/
static int msg_delete_element(struct ldb_module *module,
			      struct ltdb_private *ltdb,
			      struct ldb_message *msg,
			      const char *name,
			      const struct ldb_val *val)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	unsigned int i;
	int found, ret;
	struct ldb_message_element *el;
	const struct ldb_schema_attribute *a;

	found = find_element(msg, name);
	if (found == -1) {
		return LDB_ERR_NO_SUCH_ATTRIBUTE;
	}

	i = (unsigned int) found;
	el = &(msg->elements[i]);

	a = ldb_schema_attribute_by_name(ldb, el->name);

	for (i=0;i<el->num_values;i++) {
		bool matched;
		if (a->syntax->operator_fn) {
			ret = a->syntax->operator_fn(ldb, LDB_OP_EQUALITY, a,
						     &el->values[i], val, &matched);
			if (ret != LDB_SUCCESS) return ret;
		} else {
			matched = (a->syntax->comparison_fn(ldb, ldb,
							    &el->values[i], val) == 0);
		}
		if (matched) {
			if (el->num_values == 1) {
				return msg_delete_attribute(module,
							    ltdb, msg, name);
			}

			ret = ltdb_index_del_value(module, ltdb, msg, el, i);
			if (ret != LDB_SUCCESS) {
				return ret;
			}

			if (i<el->num_values-1) {
				memmove(&el->values[i], &el->values[i+1],
					sizeof(el->values[i])*
						(el->num_values-(i+1)));
			}
			el->num_values--;

			/* per definition we find in a canonicalised message an
			   attribute value only once. So we are finished here */
			return LDB_SUCCESS;
		}
	}

	/* Not found */
	return LDB_ERR_NO_SUCH_ATTRIBUTE;
}

/*
  modify a record - internal interface

  yuck - this is O(n^2). Luckily n is usually small so we probably
  get away with it, but if we ever have really large attribute lists
  then we'll need to look at this again

  'req' is optional, and is used to specify controls if supplied
*/
int ltdb_modify_internal(struct ldb_module *module,
			 const struct ldb_message *msg,
			 struct ldb_request *req)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	void *data = ldb_module_get_private(module);
	struct ltdb_private *ltdb = talloc_get_type(data, struct ltdb_private);
	struct ldb_message *msg2;
	unsigned int i, j;
	int ret = LDB_SUCCESS, idx;
	struct ldb_control *control_permissive = NULL;
	TALLOC_CTX *mem_ctx = talloc_new(req);

	if (mem_ctx == NULL) {
		return ldb_module_oom(module);
	}
	
	if (req) {
		control_permissive = ldb_request_get_control(req,
					LDB_CONTROL_PERMISSIVE_MODIFY_OID);
	}

	msg2 = ldb_msg_new(mem_ctx);
	if (msg2 == NULL) {
		ret = LDB_ERR_OTHER;
		goto done;
	}

	ret = ltdb_search_dn1(module, msg->dn,
			      msg2,
			      LDB_UNPACK_DATA_FLAG_NO_DATA_ALLOC);
	if (ret != LDB_SUCCESS) {
		goto done;
	}

	for (i=0; i<msg->num_elements; i++) {
		struct ldb_message_element *el = &msg->elements[i], *el2;
		struct ldb_val *vals;
		const struct ldb_schema_attribute *a = ldb_schema_attribute_by_name(ldb, el->name);
		const char *dn;
		uint32_t options = 0;
		if (control_permissive != NULL) {
			options |= LDB_MSG_FIND_COMMON_REMOVE_DUPLICATES;
		}

		switch (msg->elements[i].flags & LDB_FLAG_MOD_MASK) {
		case LDB_FLAG_MOD_ADD:

			if (el->num_values == 0) {
				ldb_asprintf_errstring(ldb,
						       "attribute '%s': attribute on '%s' specified, but with 0 values (illegal)",
						       el->name, ldb_dn_get_linearized(msg2->dn));
				ret = LDB_ERR_CONSTRAINT_VIOLATION;
				goto done;
			}

			/* make a copy of the array so that a permissive
			 * control can remove duplicates without changing the
			 * original values, but do not copy data as we do not
			 * need to keep it around once the operation is
			 * finished */
			if (control_permissive) {
				el = talloc(msg2, struct ldb_message_element);
				if (!el) {
					ret = LDB_ERR_OTHER;
					goto done;
				}
				*el = msg->elements[i];
				el->values = talloc_array(el, struct ldb_val, el->num_values);
				if (el->values == NULL) {
					ret = LDB_ERR_OTHER;
					goto done;
				}
				for (j = 0; j < el->num_values; j++) {
					el->values[j] = msg->elements[i].values[j];
				}
			}

			if (el->num_values > 1 && ldb_tdb_single_valued(a, el)) {
				ldb_asprintf_errstring(ldb, "SINGLE-VALUE attribute %s on %s specified more than once",
						       el->name, ldb_dn_get_linearized(msg2->dn));
				ret = LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS;
				goto done;
			}

			/* Checks if element already exists */
			idx = find_element(msg2, el->name);
			if (idx == -1) {
				if (ltdb_msg_add_element(msg2, el) != 0) {
					ret = LDB_ERR_OTHER;
					goto done;
				}
				ret = ltdb_index_add_element(module, ltdb,
							     msg2,
							     el);
				if (ret != LDB_SUCCESS) {
					goto done;
				}
			} else {
				j = (unsigned int) idx;
				el2 = &(msg2->elements[j]);

				/* We cannot add another value on a existing one
				   if the attribute is single-valued */
				if (ldb_tdb_single_valued(a, el)) {
					ldb_asprintf_errstring(ldb, "SINGLE-VALUE attribute %s on %s specified more than once",
						               el->name, ldb_dn_get_linearized(msg2->dn));
					ret = LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS;
					goto done;
				}

				/* Check that values don't exist yet on multi-
				   valued attributes or aren't provided twice */
				if (!(el->flags &
				      LDB_FLAG_INTERNAL_DISABLE_SINGLE_VALUE_CHECK)) {
					struct ldb_val *duplicate = NULL;
					ret = ldb_msg_find_common_values(ldb,
									 msg2,
									 el,
									 el2,
									 options);

					if (ret ==
					    LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS) {
						ldb_asprintf_errstring(ldb,
							"attribute '%s': value "
							"#%u on '%s' already "
							"exists", el->name, j,
							ldb_dn_get_linearized(msg2->dn));
						goto done;
					} else if (ret != LDB_SUCCESS) {
						goto done;
					}

					ret = ldb_msg_find_duplicate_val(
						ldb, msg2, el, &duplicate, 0);
					if (ret != LDB_SUCCESS) {
						goto done;
					}
					if (duplicate != NULL) {
						ldb_asprintf_errstring(
							ldb,
							"attribute '%s': value "
							"'%.*s' on '%s' "
							"provided more than "
							"once in ADD",
							el->name,
							(int)duplicate->length,
							duplicate->data,
							ldb_dn_get_linearized(msg->dn));
						ret = LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS;
						goto done;
					}
				}

				/* Now combine existing and new values to a new
				   attribute record */
				vals = talloc_realloc(msg2->elements,
						      el2->values, struct ldb_val,
						      el2->num_values + el->num_values);
				if (vals == NULL) {
					ldb_oom(ldb);
					ret = LDB_ERR_OTHER;
					goto done;
				}

				for (j=0; j<el->num_values; j++) {
					vals[el2->num_values + j] =
						ldb_val_dup(vals, &el->values[j]);
				}

				el2->values = vals;
				el2->num_values += el->num_values;

				ret = ltdb_index_add_element(module, ltdb,
							     msg2, el);
				if (ret != LDB_SUCCESS) {
					goto done;
				}
			}

			break;

		case LDB_FLAG_MOD_REPLACE:

			if (el->num_values > 1 && ldb_tdb_single_valued(a, el)) {
				ldb_asprintf_errstring(ldb, "SINGLE-VALUE attribute %s on %s specified more than once",
						       el->name, ldb_dn_get_linearized(msg2->dn));
				ret = LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS;
				goto done;
			}

			/*
			 * We don't need to check this if we have been
			 * pre-screened by the repl_meta_data module
			 * in Samba, or someone else who can claim to
			 * know what they are doing. 
			 */
			if (!(el->flags & LDB_FLAG_INTERNAL_DISABLE_SINGLE_VALUE_CHECK)) {
				struct ldb_val *duplicate = NULL;

				ret = ldb_msg_find_duplicate_val(ldb, msg2, el,
								 &duplicate, 0);
				if (ret != LDB_SUCCESS) {
					goto done;
				}
				if (duplicate != NULL) {
					ldb_asprintf_errstring(
						ldb,
						"attribute '%s': value '%.*s' "
						"on '%s' provided more than "
						"once in REPLACE",
						el->name,
						(int)duplicate->length,
						duplicate->data,
						ldb_dn_get_linearized(msg2->dn));
					ret = LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS;
					goto done;
				}
			}

			/* Checks if element already exists */
			idx = find_element(msg2, el->name);
			if (idx != -1) {
				j = (unsigned int) idx;
				el2 = &(msg2->elements[j]);

				/* we consider two elements to be
				 * equal only if the order
				 * matches. This allows dbcheck to
				 * fix the ordering on attributes
				 * where order matters, such as
				 * objectClass
				 */
				if (ldb_msg_element_equal_ordered(el, el2)) {
					continue;
				}

				/* Delete the attribute if it exists in the DB */
				if (msg_delete_attribute(module, ltdb,
							 msg2,
							 el->name) != 0) {
					ret = LDB_ERR_OTHER;
					goto done;
				}
			}

			/* Recreate it with the new values */
			if (ltdb_msg_add_element(msg2, el) != 0) {
				ret = LDB_ERR_OTHER;
				goto done;
			}

			ret = ltdb_index_add_element(module, ltdb,
						     msg2, el);
			if (ret != LDB_SUCCESS) {
				goto done;
			}

			break;

		case LDB_FLAG_MOD_DELETE:
			dn = ldb_dn_get_linearized(msg2->dn);
			if (dn == NULL) {
				ret = LDB_ERR_OTHER;
				goto done;
			}

			if (msg->elements[i].num_values == 0) {
				/* Delete the whole attribute */
				ret = msg_delete_attribute(module,
							   ltdb,
							   msg2,
							   msg->elements[i].name);
				if (ret == LDB_ERR_NO_SUCH_ATTRIBUTE &&
				    control_permissive) {
					ret = LDB_SUCCESS;
				} else {
					ldb_asprintf_errstring(ldb,
							       "attribute '%s': no such attribute for delete on '%s'",
							       msg->elements[i].name, dn);
				}
				if (ret != LDB_SUCCESS) {
					goto done;
				}
			} else {
				/* Delete specified values from an attribute */
				for (j=0; j < msg->elements[i].num_values; j++) {
					ret = msg_delete_element(module,
								 ltdb,
							         msg2,
							         msg->elements[i].name,
							         &msg->elements[i].values[j]);
					if (ret == LDB_ERR_NO_SUCH_ATTRIBUTE &&
					    control_permissive) {
						ret = LDB_SUCCESS;
					} else if (ret == LDB_ERR_NO_SUCH_ATTRIBUTE) {
						ldb_asprintf_errstring(ldb,
								       "attribute '%s': no matching attribute value while deleting attribute on '%s'",
								       msg->elements[i].name, dn);
					}
					if (ret != LDB_SUCCESS) {
						goto done;
					}
				}
			}
			break;
		default:
			ldb_asprintf_errstring(ldb,
					       "attribute '%s': invalid modify flags on '%s': 0x%x",
					       msg->elements[i].name, ldb_dn_get_linearized(msg->dn),
					       msg->elements[i].flags & LDB_FLAG_MOD_MASK);
			ret = LDB_ERR_PROTOCOL_ERROR;
			goto done;
		}
	}

	ret = ltdb_store(module, msg2, TDB_MODIFY);
	if (ret != LDB_SUCCESS) {
		goto done;
	}

	ret = ltdb_modified(module, msg2->dn);
	if (ret != LDB_SUCCESS) {
		goto done;
	}

done:
	TALLOC_FREE(mem_ctx);
	return ret;
}

/*
  modify a record
*/
static int ltdb_modify(struct ltdb_context *ctx)
{
	struct ldb_module *module = ctx->module;
	struct ldb_request *req = ctx->req;
	int ret = LDB_SUCCESS;

	ret = ltdb_check_special_dn(module, req->op.mod.message);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ldb_request_set_state(req, LDB_ASYNC_PENDING);

	if (ltdb_cache_load(module) != 0) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ltdb_modify_internal(module, req->op.mod.message, req);

	return ret;
}

/*
  rename a record
*/
static int ltdb_rename(struct ltdb_context *ctx)
{
	struct ldb_module *module = ctx->module;
	void *data = ldb_module_get_private(module);
	struct ltdb_private *ltdb = talloc_get_type(data, struct ltdb_private);
	struct ldb_request *req = ctx->req;
	struct ldb_message *msg;
	int ret = LDB_SUCCESS;
	TDB_DATA tdb_key, tdb_key_old;
	struct ldb_dn *db_dn;
	bool valid_dn = false;

	ldb_request_set_state(req, LDB_ASYNC_PENDING);

	if (ltdb_cache_load(ctx->module) != 0) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	msg = ldb_msg_new(ctx);
	if (msg == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* Check the new DN is reasonable */
	valid_dn = ldb_dn_validate(req->op.rename.newdn);
	if (valid_dn == false) {
		ldb_asprintf_errstring(ldb_module_get_ctx(module),
				       "Invalid New DN: %s",
				       ldb_dn_get_linearized(req->op.rename.newdn));
		return LDB_ERR_INVALID_DN_SYNTAX;
	}

	/* we need to fetch the old record to re-add under the new name */
	ret = ltdb_search_dn1(module, req->op.rename.olddn, msg,
			      LDB_UNPACK_DATA_FLAG_NO_DATA_ALLOC);
	if (ret == LDB_ERR_INVALID_DN_SYNTAX) {
		ldb_asprintf_errstring(ldb_module_get_ctx(module),
				       "Invalid Old DN: %s",
				       ldb_dn_get_linearized(req->op.rename.newdn));
		return ret;
	} else if (ret != LDB_SUCCESS) {
		/* not finding the old record is an error */
		return ret;
	}

	/* We need to, before changing the DB, check if the new DN
	 * exists, so we can return this error to the caller with an
	 * unmodified DB
	 *
	 * Even in GUID index mode we use ltdb_key_dn() as we are
	 * trying to figure out if this is just a case rename
	 */
	tdb_key = ltdb_key_dn(module, msg, req->op.rename.newdn);
	if (!tdb_key.dptr) {
		talloc_free(msg);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	tdb_key_old = ltdb_key_dn(module, msg, req->op.rename.olddn);
	if (!tdb_key_old.dptr) {
		talloc_free(msg);
		talloc_free(tdb_key.dptr);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/*
	 * Only declare a conflict if the new DN already exists,
	 * and it isn't a case change on the old DN
	 */
	if (tdb_key_old.dsize != tdb_key.dsize
	    || memcmp(tdb_key.dptr, tdb_key_old.dptr, tdb_key.dsize) != 0) {
		ret = ltdb_search_base(module, msg,
				       req->op.rename.newdn,
				       &db_dn);
		if (ret == LDB_SUCCESS) {
			ret = LDB_ERR_ENTRY_ALREADY_EXISTS;
		} else if (ret == LDB_ERR_NO_SUCH_OBJECT) {
			ret = LDB_SUCCESS;
		}
	}

	/* finding the new record already in the DB is an error */

	if (ret == LDB_ERR_ENTRY_ALREADY_EXISTS) {
		ldb_asprintf_errstring(ldb_module_get_ctx(module),
				       "Entry %s already exists",
				       ldb_dn_get_linearized(req->op.rename.newdn));
	}
	if (ret != LDB_SUCCESS) {
		talloc_free(tdb_key_old.dptr);
		talloc_free(tdb_key.dptr);
		talloc_free(msg);
		return ret;
	}

	talloc_free(tdb_key_old.dptr);
	talloc_free(tdb_key.dptr);

	/* Always delete first then add, to avoid conflicts with
	 * unique indexes. We rely on the transaction to make this
	 * atomic
	 */
	ret = ltdb_delete_internal(module, msg->dn);
	if (ret != LDB_SUCCESS) {
		talloc_free(msg);
		return ret;
	}

	msg->dn = ldb_dn_copy(msg, req->op.rename.newdn);
	if (msg->dn == NULL) {
		talloc_free(msg);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* We don't check single value as we can have more than 1 with
	 * deleted attributes. We could go through all elements but that's
	 * maybe not the most efficient way
	 */
	ret = ltdb_add_internal(module, ltdb, msg, false);

	talloc_free(msg);

	return ret;
}

static int ltdb_tdb_transaction_start(struct ltdb_private *ltdb)
{
	pid_t pid = getpid();

	if (ltdb->pid != pid) {
		ldb_asprintf_errstring(
			ldb_module_get_ctx(ltdb->module),
			__location__": Reusing ldb opend by pid %d in "
			"process %d\n",
			ltdb->pid,
			pid);
		return LDB_ERR_PROTOCOL_ERROR;
	}

	return tdb_transaction_start(ltdb->tdb);
}

static int ltdb_tdb_transaction_cancel(struct ltdb_private *ltdb)
{
	pid_t pid = getpid();

	if (ltdb->pid != pid) {
		ldb_asprintf_errstring(
			ldb_module_get_ctx(ltdb->module),
			__location__": Reusing ldb opend by pid %d in "
			"process %d\n",
			ltdb->pid,
			pid);
		return LDB_ERR_PROTOCOL_ERROR;
	}

	return tdb_transaction_cancel(ltdb->tdb);
}

static int ltdb_tdb_transaction_prepare_commit(struct ltdb_private *ltdb)
{
	pid_t pid = getpid();

	if (ltdb->pid != pid) {
		ldb_asprintf_errstring(
			ldb_module_get_ctx(ltdb->module),
			__location__": Reusing ldb opend by pid %d in "
			"process %d\n",
			ltdb->pid,
			pid);
		return LDB_ERR_PROTOCOL_ERROR;
	}

	return tdb_transaction_prepare_commit(ltdb->tdb);
}

static int ltdb_tdb_transaction_commit(struct ltdb_private *ltdb)
{
	pid_t pid = getpid();

	if (ltdb->pid != pid) {
		ldb_asprintf_errstring(
			ldb_module_get_ctx(ltdb->module),
			__location__": Reusing ldb opend by pid %d in "
			"process %d\n",
			ltdb->pid,
			pid);
		return LDB_ERR_PROTOCOL_ERROR;
	}

	return tdb_transaction_commit(ltdb->tdb);
}

static int ltdb_start_trans(struct ldb_module *module)
{
	void *data = ldb_module_get_private(module);
	struct ltdb_private *ltdb = talloc_get_type(data, struct ltdb_private);

	pid_t pid = getpid();

	if (ltdb->pid != pid) {
		ldb_asprintf_errstring(
			ldb_module_get_ctx(ltdb->module),
			__location__": Reusing ldb opend by pid %d in "
			"process %d\n",
			ltdb->pid,
			pid);
		return LDB_ERR_PROTOCOL_ERROR;
	}

	/* Do not take out the transaction lock on a read-only DB */
	if (ltdb->read_only) {
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	if (ltdb->kv_ops->begin_write(ltdb) != 0) {
		return ltdb->kv_ops->error(ltdb);
	}


	ltdb_index_transaction_start(module);

	ltdb->reindex_failed = false;

	return LDB_SUCCESS;
}

/*
 * Forward declaration to allow prepare_commit to in fact abort the
 * transaction
 */
static int ltdb_del_trans(struct ldb_module *module);

static int ltdb_prepare_commit(struct ldb_module *module)
{
	int ret;
	void *data = ldb_module_get_private(module);
	struct ltdb_private *ltdb = talloc_get_type(data, struct ltdb_private);
	pid_t pid = getpid();

	if (ltdb->pid != pid) {
		ldb_asprintf_errstring(
			ldb_module_get_ctx(module),
			__location__": Reusing ldb opend by pid %d in "
			"process %d\n",
			ltdb->pid,
			pid);
		return LDB_ERR_PROTOCOL_ERROR;
	}

	if (!ltdb->kv_ops->transaction_active(ltdb)) {
		ldb_set_errstring(ldb_module_get_ctx(module),
				  "ltdb_prepare_commit() called "
				  "without transaction active");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/*
	 * Check if the last re-index failed.
	 *
	 * This can happen if for example a duplicate value was marked
	 * unique.  We must not write a partial re-index into the DB.
	 */
	if (ltdb->reindex_failed) {
		/*
		 * We must instead abort the transaction so we get the
		 * old values and old index back
		 */
		ltdb_del_trans(module);
		ldb_set_errstring(ldb_module_get_ctx(module),
				  "Failure during re-index, so "
				  "transaction must be aborted.");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ltdb_index_transaction_commit(module);
	if (ret != LDB_SUCCESS) {
		ltdb->kv_ops->abort_write(ltdb);
		return ret;
	}

	if (ltdb->kv_ops->prepare_write(ltdb) != 0) {
		ret = ltdb->kv_ops->error(ltdb);
		ldb_debug_set(ldb_module_get_ctx(module),
			      LDB_DEBUG_FATAL,
			      "Failure during "
			      "prepare_write): %s -> %s",
			      ltdb->kv_ops->errorstr(ltdb),
			      ldb_strerror(ret));
		return ret;
	}

	ltdb->prepared_commit = true;

	return LDB_SUCCESS;
}

static int ltdb_end_trans(struct ldb_module *module)
{
	int ret;
	void *data = ldb_module_get_private(module);
	struct ltdb_private *ltdb = talloc_get_type(data, struct ltdb_private);

	if (!ltdb->prepared_commit) {
		ret = ltdb_prepare_commit(module);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	ltdb->prepared_commit = false;

	if (ltdb->kv_ops->finish_write(ltdb) != 0) {
		ret = ltdb->kv_ops->error(ltdb);
		ldb_asprintf_errstring(ldb_module_get_ctx(module),
				       "Failure during tdb_transaction_commit(): %s -> %s",
				       ltdb->kv_ops->errorstr(ltdb),
				       ldb_strerror(ret));
		return ret;
	}

	return LDB_SUCCESS;
}

static int ltdb_del_trans(struct ldb_module *module)
{
	void *data = ldb_module_get_private(module);
	struct ltdb_private *ltdb = talloc_get_type(data, struct ltdb_private);


	if (ltdb_index_transaction_cancel(module) != 0) {
		ltdb->kv_ops->abort_write(ltdb);
		return ltdb->kv_ops->error(ltdb);
	}

	ltdb->kv_ops->abort_write(ltdb);
	return LDB_SUCCESS;
}

/*
  return sequenceNumber from @BASEINFO
*/
static int ltdb_sequence_number(struct ltdb_context *ctx,
				struct ldb_extended **ext)
{
	struct ldb_context *ldb;
	struct ldb_module *module = ctx->module;
	struct ldb_request *req = ctx->req;
	void *data = ldb_module_get_private(module);
	struct ltdb_private *ltdb = talloc_get_type(data, struct ltdb_private);
	TALLOC_CTX *tmp_ctx = NULL;
	struct ldb_seqnum_request *seq;
	struct ldb_seqnum_result *res;
	struct ldb_message *msg = NULL;
	struct ldb_dn *dn;
	const char *date;
	int ret = LDB_SUCCESS;

	ldb = ldb_module_get_ctx(module);

	seq = talloc_get_type(req->op.extended.data,
				struct ldb_seqnum_request);
	if (seq == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ldb_request_set_state(req, LDB_ASYNC_PENDING);

	if (ltdb->kv_ops->lock_read(module) != 0) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	res = talloc_zero(req, struct ldb_seqnum_result);
	if (res == NULL) {
		ret = LDB_ERR_OPERATIONS_ERROR;
		goto done;
	}

	tmp_ctx = talloc_new(req);
	if (tmp_ctx == NULL) {
		ret = LDB_ERR_OPERATIONS_ERROR;
		goto done;
	}

	dn = ldb_dn_new(tmp_ctx, ldb, LTDB_BASEINFO);
	if (dn == NULL) {
		ret = LDB_ERR_OPERATIONS_ERROR;
		goto done;
	}

	msg = ldb_msg_new(tmp_ctx);
	if (msg == NULL) {
		ret = LDB_ERR_OPERATIONS_ERROR;
		goto done;
	}

	ret = ltdb_search_dn1(module, dn, msg, 0);
	if (ret != LDB_SUCCESS) {
		goto done;
	}

	switch (seq->type) {
	case LDB_SEQ_HIGHEST_SEQ:
		res->seq_num = ldb_msg_find_attr_as_uint64(msg, LTDB_SEQUENCE_NUMBER, 0);
		break;
	case LDB_SEQ_NEXT:
		res->seq_num = ldb_msg_find_attr_as_uint64(msg, LTDB_SEQUENCE_NUMBER, 0);
		res->seq_num++;
		break;
	case LDB_SEQ_HIGHEST_TIMESTAMP:
		date = ldb_msg_find_attr_as_string(msg, LTDB_MOD_TIMESTAMP, NULL);
		if (date) {
			res->seq_num = ldb_string_to_time(date);
		} else {
			res->seq_num = 0;
			/* zero is as good as anything when we don't know */
		}
		break;
	}

	*ext = talloc_zero(req, struct ldb_extended);
	if (*ext == NULL) {
		ret = LDB_ERR_OPERATIONS_ERROR;
		goto done;
	}
	(*ext)->oid = LDB_EXTENDED_SEQUENCE_NUMBER;
	(*ext)->data = talloc_steal(*ext, res);

done:
	talloc_free(tmp_ctx);

	ltdb->kv_ops->unlock_read(module);
	return ret;
}

static void ltdb_request_done(struct ltdb_context *ctx, int error)
{
	struct ldb_context *ldb;
	struct ldb_request *req;
	struct ldb_reply *ares;

	ldb = ldb_module_get_ctx(ctx->module);
	req = ctx->req;

	/* if we already returned an error just return */
	if (ldb_request_get_status(req) != LDB_SUCCESS) {
		return;
	}

	ares = talloc_zero(req, struct ldb_reply);
	if (!ares) {
		ldb_oom(ldb);
		req->callback(req, NULL);
		return;
	}
	ares->type = LDB_REPLY_DONE;
	ares->error = error;

	req->callback(req, ares);
}

static void ltdb_timeout(struct tevent_context *ev,
			  struct tevent_timer *te,
			  struct timeval t,
			  void *private_data)
{
	struct ltdb_context *ctx;
	ctx = talloc_get_type(private_data, struct ltdb_context);

	if (!ctx->request_terminated) {
		/* request is done now */
		ltdb_request_done(ctx, LDB_ERR_TIME_LIMIT_EXCEEDED);
	}

	if (ctx->spy) {
		/* neutralize the spy */
		ctx->spy->ctx = NULL;
		ctx->spy = NULL;
	}
	talloc_free(ctx);
}

static void ltdb_request_extended_done(struct ltdb_context *ctx,
					struct ldb_extended *ext,
					int error)
{
	struct ldb_context *ldb;
	struct ldb_request *req;
	struct ldb_reply *ares;

	ldb = ldb_module_get_ctx(ctx->module);
	req = ctx->req;

	/* if we already returned an error just return */
	if (ldb_request_get_status(req) != LDB_SUCCESS) {
		return;
	}

	ares = talloc_zero(req, struct ldb_reply);
	if (!ares) {
		ldb_oom(ldb);
		req->callback(req, NULL);
		return;
	}
	ares->type = LDB_REPLY_DONE;
	ares->response = ext;
	ares->error = error;

	req->callback(req, ares);
}

static void ltdb_handle_extended(struct ltdb_context *ctx)
{
	struct ldb_extended *ext = NULL;
	int ret;

	if (strcmp(ctx->req->op.extended.oid,
		   LDB_EXTENDED_SEQUENCE_NUMBER) == 0) {
		/* get sequence number */
		ret = ltdb_sequence_number(ctx, &ext);
	} else {
		/* not recognized */
		ret = LDB_ERR_UNSUPPORTED_CRITICAL_EXTENSION;
	}

	ltdb_request_extended_done(ctx, ext, ret);
}

struct kv_ctx {
	ldb_kv_traverse_fn kv_traverse_fn;
	void *ctx;
	struct ltdb_private *ltdb;
	int (*parser)(struct ldb_val key,
		      struct ldb_val data,
		      void *private_data);
};

static int ldb_tdb_traverse_fn_wrapper(struct tdb_context *tdb, TDB_DATA tdb_key, TDB_DATA tdb_data, void *ctx)
{
	struct kv_ctx *kv_ctx = ctx;
	struct ldb_val key = {
		.length = tdb_key.dsize,
		.data = tdb_key.dptr,
	};
	struct ldb_val data = {
		.length = tdb_data.dsize,
		.data = tdb_data.dptr,
	};
	return kv_ctx->kv_traverse_fn(kv_ctx->ltdb, key, data, kv_ctx->ctx);
}

static int ltdb_tdb_traverse_fn(struct ltdb_private *ltdb, ldb_kv_traverse_fn fn, void *ctx)
{
	struct kv_ctx kv_ctx = {
		.kv_traverse_fn = fn,
		.ctx = ctx,
		.ltdb = ltdb
	};
	if (tdb_transaction_active(ltdb->tdb)) {
		return tdb_traverse(ltdb->tdb, ldb_tdb_traverse_fn_wrapper, &kv_ctx);
	} else {
		return tdb_traverse_read(ltdb->tdb, ldb_tdb_traverse_fn_wrapper, &kv_ctx);
	}
}

static int ltdb_tdb_update_in_iterate(struct ltdb_private *ltdb,
				      struct ldb_val ldb_key,
				      struct ldb_val ldb_key2,
				      struct ldb_val ldb_data, void *state)
{
	int tdb_ret;
	struct ldb_context *ldb;
	struct ltdb_reindex_context *ctx = (struct ltdb_reindex_context *)state;
	struct ldb_module *module = ctx->module;
	TDB_DATA key = {
		.dptr = ldb_key.data,
		.dsize = ldb_key.length
	};
	TDB_DATA key2 = {
		.dptr = ldb_key2.data,
		.dsize = ldb_key2.length
	};
	TDB_DATA data = {
		.dptr = ldb_data.data,
		.dsize = ldb_data.length
	};

	ldb = ldb_module_get_ctx(module);

	tdb_ret = tdb_delete(ltdb->tdb, key);
	if (tdb_ret != 0) {
		ldb_debug(ldb, LDB_DEBUG_ERROR,
			  "Failed to delete %*.*s "
			  "for rekey as %*.*s: %s",
			  (int)key.dsize, (int)key.dsize,
			  (const char *)key.dptr,
			  (int)key2.dsize, (int)key2.dsize,
			  (const char *)key.dptr,
			  tdb_errorstr(ltdb->tdb));
		ctx->error = ltdb_err_map(tdb_error(ltdb->tdb));
		return -1;
	}
	tdb_ret = tdb_store(ltdb->tdb, key2, data, 0);
	if (tdb_ret != 0) {
		ldb_debug(ldb, LDB_DEBUG_ERROR,
			  "Failed to rekey %*.*s as %*.*s: %s",
			  (int)key.dsize, (int)key.dsize,
			  (const char *)key.dptr,
			  (int)key2.dsize, (int)key2.dsize,
			  (const char *)key.dptr,
			  tdb_errorstr(ltdb->tdb));
		ctx->error = ltdb_err_map(tdb_error(ltdb->tdb));
		return -1;
	}
	return tdb_ret;
}

static int ltdb_tdb_parse_record_wrapper(TDB_DATA tdb_key, TDB_DATA tdb_data,
					 void *ctx)
{
	struct kv_ctx *kv_ctx = ctx;
	struct ldb_val key = {
		.length = tdb_key.dsize,
		.data = tdb_key.dptr,
	};
	struct ldb_val data = {
		.length = tdb_data.dsize,
		.data = tdb_data.dptr,
	};

	return kv_ctx->parser(key, data, kv_ctx->ctx);
}

static int ltdb_tdb_parse_record(struct ltdb_private *ltdb,
				 struct ldb_val ldb_key,
				 int (*parser)(struct ldb_val key,
					       struct ldb_val data,
					       void *private_data),
				 void *ctx)
{
	struct kv_ctx kv_ctx = {
		.parser = parser,
		.ctx = ctx,
		.ltdb = ltdb
	};
	TDB_DATA key = {
		.dptr = ldb_key.data,
		.dsize = ldb_key.length
	};
	int ret;

	if (tdb_transaction_active(ltdb->tdb) == false &&
	    ltdb->read_lock_count == 0) {
		return LDB_ERR_PROTOCOL_ERROR;
	}

	ret = tdb_parse_record(ltdb->tdb, key, ltdb_tdb_parse_record_wrapper,
			       &kv_ctx);
	if (ret == 0) {
		return LDB_SUCCESS;
	}
	return ltdb_err_map(tdb_error(ltdb->tdb));
}

static const char * ltdb_tdb_name(struct ltdb_private *ltdb)
{
	return tdb_name(ltdb->tdb);
}

static bool ltdb_tdb_changed(struct ltdb_private *ltdb)
{
	int seq = tdb_get_seqnum(ltdb->tdb);
	bool has_changed = (seq != ltdb->tdb_seqnum);

	ltdb->tdb_seqnum = seq;

	return has_changed;
}

static bool ltdb_transaction_active(struct ltdb_private *ltdb)
{
	return tdb_transaction_active(ltdb->tdb);
}

static const struct kv_db_ops key_value_ops = {
	.store = ltdb_tdb_store,
	.delete = ltdb_tdb_delete,
	.iterate = ltdb_tdb_traverse_fn,
	.update_in_iterate = ltdb_tdb_update_in_iterate,
	.fetch_and_parse = ltdb_tdb_parse_record,
	.lock_read = ltdb_lock_read,
	.unlock_read = ltdb_unlock_read,
	.begin_write = ltdb_tdb_transaction_start,
	.prepare_write = ltdb_tdb_transaction_prepare_commit,
	.finish_write = ltdb_tdb_transaction_commit,
	.abort_write = ltdb_tdb_transaction_cancel,
	.error = ltdb_error,
	.errorstr = ltdb_errorstr,
	.name = ltdb_tdb_name,
	.has_changed = ltdb_tdb_changed,
	.transaction_active = ltdb_transaction_active,
};

static void ltdb_callback(struct tevent_context *ev,
			  struct tevent_timer *te,
			  struct timeval t,
			  void *private_data)
{
	struct ltdb_context *ctx;
	int ret;

	ctx = talloc_get_type(private_data, struct ltdb_context);

	if (ctx->request_terminated) {
		goto done;
	}

	switch (ctx->req->operation) {
	case LDB_SEARCH:
		ret = ltdb_search(ctx);
		break;
	case LDB_ADD:
		ret = ltdb_add(ctx);
		break;
	case LDB_MODIFY:
		ret = ltdb_modify(ctx);
		break;
	case LDB_DELETE:
		ret = ltdb_delete(ctx);
		break;
	case LDB_RENAME:
		ret = ltdb_rename(ctx);
		break;
	case LDB_EXTENDED:
		ltdb_handle_extended(ctx);
		goto done;
	default:
		/* no other op supported */
		ret = LDB_ERR_PROTOCOL_ERROR;
	}

	if (!ctx->request_terminated) {
		/* request is done now */
		ltdb_request_done(ctx, ret);
	}

done:
	if (ctx->spy) {
		/* neutralize the spy */
		ctx->spy->ctx = NULL;
		ctx->spy = NULL;
	}
	talloc_free(ctx);
}

static int ltdb_request_destructor(void *ptr)
{
	struct ltdb_req_spy *spy = talloc_get_type(ptr, struct ltdb_req_spy);

	if (spy->ctx != NULL) {
		spy->ctx->spy = NULL;
		spy->ctx->request_terminated = true;
		spy->ctx = NULL;
	}

	return 0;
}

static int ltdb_handle_request(struct ldb_module *module,
			       struct ldb_request *req)
{
	struct ldb_control *control_permissive;
	struct ldb_context *ldb;
	struct tevent_context *ev;
	struct ltdb_context *ac;
	struct tevent_timer *te;
	struct timeval tv;
	unsigned int i;

	ldb = ldb_module_get_ctx(module);

	control_permissive = ldb_request_get_control(req,
					LDB_CONTROL_PERMISSIVE_MODIFY_OID);

	for (i = 0; req->controls && req->controls[i]; i++) {
		if (req->controls[i]->critical &&
		    req->controls[i] != control_permissive) {
			ldb_asprintf_errstring(ldb, "Unsupported critical extension %s",
					       req->controls[i]->oid);
			return LDB_ERR_UNSUPPORTED_CRITICAL_EXTENSION;
		}
	}

	if (req->starttime == 0 || req->timeout == 0) {
		ldb_set_errstring(ldb, "Invalid timeout settings");
		return LDB_ERR_TIME_LIMIT_EXCEEDED;
	}

	ev = ldb_handle_get_event_context(req->handle);

	ac = talloc_zero(ldb, struct ltdb_context);
	if (ac == NULL) {
		ldb_oom(ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ac->module = module;
	ac->req = req;

	tv.tv_sec = 0;
	tv.tv_usec = 0;
	te = tevent_add_timer(ev, ac, tv, ltdb_callback, ac);
	if (NULL == te) {
		talloc_free(ac);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (req->timeout > 0) {
		tv.tv_sec = req->starttime + req->timeout;
		tv.tv_usec = 0;
		ac->timeout_event = tevent_add_timer(ev, ac, tv,
						     ltdb_timeout, ac);
		if (NULL == ac->timeout_event) {
			talloc_free(ac);
			return LDB_ERR_OPERATIONS_ERROR;
		}
	}

	/* set a spy so that we do not try to use the request context
	 * if it is freed before ltdb_callback fires */
	ac->spy = talloc(req, struct ltdb_req_spy);
	if (NULL == ac->spy) {
		talloc_free(ac);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	ac->spy->ctx = ac;

	talloc_set_destructor((TALLOC_CTX *)ac->spy, ltdb_request_destructor);

	return LDB_SUCCESS;
}

static int ltdb_init_rootdse(struct ldb_module *module)
{
	/* ignore errors on this - we expect it for non-sam databases */
	ldb_mod_register_control(module, LDB_CONTROL_PERMISSIVE_MODIFY_OID);

	/* there can be no module beyond the backend, just return */
	return LDB_SUCCESS;
}


static int generic_lock_read(struct ldb_module *module)
{
	void *data = ldb_module_get_private(module);
	struct ltdb_private *ltdb = talloc_get_type(data, struct ltdb_private);
	return ltdb->kv_ops->lock_read(module);
}

static int generic_unlock_read(struct ldb_module *module)
{
	void *data = ldb_module_get_private(module);
	struct ltdb_private *ltdb = talloc_get_type(data, struct ltdb_private);
	return ltdb->kv_ops->unlock_read(module);
}

static const struct ldb_module_ops ltdb_ops = {
	.name              = "tdb",
	.init_context      = ltdb_init_rootdse,
	.search            = ltdb_handle_request,
	.add               = ltdb_handle_request,
	.modify            = ltdb_handle_request,
	.del               = ltdb_handle_request,
	.rename            = ltdb_handle_request,
	.extended          = ltdb_handle_request,
	.start_transaction = ltdb_start_trans,
	.end_transaction   = ltdb_end_trans,
	.prepare_commit    = ltdb_prepare_commit,
	.del_transaction   = ltdb_del_trans,
	.read_lock         = generic_lock_read,
	.read_unlock       = generic_unlock_read,
};

int init_store(struct ltdb_private *ltdb,
		      const char *name,
		      struct ldb_context *ldb,
		      const char *options[],
		      struct ldb_module **_module)
{
	if (getenv("LDB_WARN_UNINDEXED")) {
		ltdb->warn_unindexed = true;
	}

	if (getenv("LDB_WARN_REINDEX")) {
		ltdb->warn_reindex = true;
	}

	ltdb->sequence_number = 0;

	ltdb->pid = getpid();

	ltdb->module = ldb_module_new(ldb, ldb, name, &ltdb_ops);
	if (!ltdb->module) {
		ldb_oom(ldb);
		talloc_free(ltdb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	ldb_module_set_private(ltdb->module, ltdb);
	talloc_steal(ltdb->module, ltdb);

	if (ltdb_cache_load(ltdb->module) != 0) {
		ldb_asprintf_errstring(ldb, "Unable to load ltdb cache "
				       "records for backend '%s'", name);
		talloc_free(ltdb->module);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	*_module = ltdb->module;
	/*
	 * Set or override the maximum key length
	 *
	 * The ldb_mdb code will have set this to 511, but our tests
	 * set this even smaller (to make the tests more practical).
	 *
	 * This must only be used for the selftest as the length
	 * becomes encoded in the index keys.
	 */
	{
		const char *len_str =
			ldb_options_find(ldb, options,
					 "max_key_len_for_self_test");
		if (len_str != NULL) {
			unsigned len = strtoul(len_str, NULL, 0);
			ltdb->max_key_length = len;
		}
	}

	/*
	 * Override full DB scans
	 *
	 * A full DB scan is expensive on a large database.  This
	 * option is for testing to show that the full DB scan is not
	 * triggered.
	 */
	{
		const char *len_str =
			ldb_options_find(ldb, options,
					 "disable_full_db_scan_for_self_test");
		if (len_str != NULL) {
			ltdb->disable_full_db_scan = true;
		}
	}

	return LDB_SUCCESS;
}

/*
  connect to the database
*/
int ltdb_connect(struct ldb_context *ldb, const char *url,
		 unsigned int flags, const char *options[],
		 struct ldb_module **_module)
{
	const char *path;
	int tdb_flags, open_flags;
	struct ltdb_private *ltdb;

	/*
	 * We hold locks, so we must use a private event context
	 * on each returned handle
	 */
	ldb_set_require_private_event_context(ldb);

	/* parse the url */
	if (strchr(url, ':')) {
		if (strncmp(url, "tdb://", 6) != 0) {
			ldb_debug(ldb, LDB_DEBUG_ERROR,
				  "Invalid tdb URL '%s'", url);
			return LDB_ERR_OPERATIONS_ERROR;
		}
		path = url+6;
	} else {
		path = url;
	}

	tdb_flags = TDB_DEFAULT | TDB_SEQNUM | TDB_DISALLOW_NESTING;

	/* check for the 'nosync' option */
	if (flags & LDB_FLG_NOSYNC) {
		tdb_flags |= TDB_NOSYNC;
	}

	/* and nommap option */
	if (flags & LDB_FLG_NOMMAP) {
		tdb_flags |= TDB_NOMMAP;
	}

	ltdb = talloc_zero(ldb, struct ltdb_private);
	if (!ltdb) {
		ldb_oom(ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (flags & LDB_FLG_RDONLY) {
		/*
		 * This is weird, but because we can only have one tdb
		 * in this process, and the other one could be
		 * read-write, we can't use the tdb readonly.  Plus a
		 * read only tdb prohibits the all-record lock.
		 */
		open_flags = O_RDWR;

		ltdb->read_only = true;

	} else if (flags & LDB_FLG_DONT_CREATE_DB) {
		/*
		 * This is used by ldbsearch to prevent creation of the database
		 * if the name is wrong
		 */
		open_flags = O_RDWR;
	} else {
		/*
		 * This is the normal case
		 */
		open_flags = O_CREAT | O_RDWR;
	}

	ltdb->kv_ops = &key_value_ops;

	errno = 0;
	/* note that we use quite a large default hash size */
	ltdb->tdb = ltdb_wrap_open(ltdb, path, 10000,
				   tdb_flags, open_flags,
				   ldb_get_create_perms(ldb), ldb);
	if (!ltdb->tdb) {
		ldb_asprintf_errstring(ldb,
				       "Unable to open tdb '%s': %s", path, strerror(errno));
		ldb_debug(ldb, LDB_DEBUG_ERROR,
			  "Unable to open tdb '%s': %s", path, strerror(errno));
		talloc_free(ltdb);
		if (errno == EACCES || errno == EPERM) {
			return LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS;
		}
		return LDB_ERR_OPERATIONS_ERROR;
	}

	return init_store(ltdb, "ldb_tdb backend", ldb, options, _module);
}
