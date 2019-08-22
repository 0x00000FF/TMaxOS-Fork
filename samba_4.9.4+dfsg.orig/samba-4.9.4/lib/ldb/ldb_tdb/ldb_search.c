/* 
   ldb database library

   Copyright (C) Andrew Tridgell  2004

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
 *  Name: ldb
 *
 *  Component: ldb search functions
 *
 *  Description: functions to search ldb+tdb databases
 *
 *  Author: Andrew Tridgell
 */

#include "ldb_tdb.h"
#include "ldb_private.h"
#include <tdb.h>

/*
  add one element to a message
*/
static int msg_add_element(struct ldb_message *ret, 
			   const struct ldb_message_element *el,
			   int check_duplicates)
{
	unsigned int i;
	struct ldb_message_element *e2, *elnew;

	if (check_duplicates && ldb_msg_find_element(ret, el->name)) {
		/* its already there */
		return 0;
	}

	e2 = talloc_realloc(ret, ret->elements, struct ldb_message_element, ret->num_elements+1);
	if (!e2) {
		return -1;
	}
	ret->elements = e2;
	
	elnew = &e2[ret->num_elements];

	elnew->name = talloc_strdup(ret->elements, el->name);
	if (!elnew->name) {
		return -1;
	}

	if (el->num_values) {
		elnew->values = talloc_array(ret->elements, struct ldb_val, el->num_values);
		if (!elnew->values) {
			return -1;
		}
	} else {
		elnew->values = NULL;
	}

	for (i=0;i<el->num_values;i++) {
		elnew->values[i] = ldb_val_dup(elnew->values, &el->values[i]);
		if (elnew->values[i].length != el->values[i].length) {
			return -1;
		}
	}

	elnew->num_values = el->num_values;
	elnew->flags = el->flags;

	ret->num_elements++;

	return 0;
}

/*
  add the special distinguishedName element
*/
static int msg_add_distinguished_name(struct ldb_message *msg)
{
	struct ldb_message_element el;
	struct ldb_val val;
	int ret;

	el.flags = 0;
	el.name = "distinguishedName";
	el.num_values = 1;
	el.values = &val;
	el.flags = 0;
	val.data = (uint8_t *)ldb_dn_alloc_linearized(msg, msg->dn);
	if (val.data == NULL) {
		return -1;
	}
	val.length = strlen((char *)val.data);

	ret = msg_add_element(msg, &el, 1);
	return ret;
}

/*
  search the database for a single simple dn.
  return LDB_ERR_NO_SUCH_OBJECT on record-not-found
  and LDB_SUCCESS on success
*/
int ltdb_search_base(struct ldb_module *module,
		     TALLOC_CTX *mem_ctx,
		     struct ldb_dn *dn,
		     struct ldb_dn **ret_dn)
{
	int exists;
	int ret;
	struct ldb_message *msg = NULL;

	if (ldb_dn_is_null(dn)) {
		return LDB_ERR_NO_SUCH_OBJECT;
	}

	/*
	 * We can't use tdb_exists() directly on a key when the TDB
	 * key is the GUID one, not the DN based one.  So we just do a
	 * normal search and avoid most of the allocation with the
	 * LDB_UNPACK_DATA_FLAG_NO_DN and
	 * LDB_UNPACK_DATA_FLAG_NO_ATTRS flags
	 */
	msg = ldb_msg_new(module);
	if (msg == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ltdb_search_dn1(module, dn,
			      msg,
			      LDB_UNPACK_DATA_FLAG_NO_ATTRS);
	if (ret == LDB_SUCCESS) {
		const char *dn_linearized
			= ldb_dn_get_linearized(dn);
		const char *msg_dn_linearlized
			= ldb_dn_get_linearized(msg->dn);

		if (strcmp(dn_linearized, msg_dn_linearlized) == 0) {
			/*
			 * Re-use the full incoming DN for
			 * subtree checks
			 */
			*ret_dn = dn;
		} else {
			/*
			 * Use the string DN from the unpack, so that
			 * we have a case-exact match of the base
			 */
			*ret_dn = talloc_steal(mem_ctx, msg->dn);
		}
		exists = true;
	} else if (ret == LDB_ERR_NO_SUCH_OBJECT) {
		exists = false;
	} else {
		talloc_free(msg);
		return ret;
	}
	talloc_free(msg);
	if (exists) {
		return LDB_SUCCESS;
	}
	return LDB_ERR_NO_SUCH_OBJECT;
}

struct ltdb_parse_data_unpack_ctx {
	struct ldb_message *msg;
	struct ldb_module *module;
	unsigned int unpack_flags;
};

static int ltdb_parse_data_unpack(struct ldb_val key,
				  struct ldb_val data,
				  void *private_data)
{
	struct ltdb_parse_data_unpack_ctx *ctx = private_data;
	unsigned int nb_elements_in_db;
	int ret;
	struct ldb_context *ldb = ldb_module_get_ctx(ctx->module);
	struct ldb_val data_parse = data;

	if (ctx->unpack_flags & LDB_UNPACK_DATA_FLAG_NO_DATA_ALLOC) {
		/*
		 * If we got LDB_UNPACK_DATA_FLAG_NO_DATA_ALLOC
		 * we need at least do a memdup on the whole
		 * data buffer as that may change later
		 * and the caller needs a stable result.
		 */
		data_parse.data = talloc_memdup(ctx->msg,
						data.data,
						data.length);
		if (data_parse.data == NULL) {
			ldb_debug(ldb, LDB_DEBUG_ERROR,
				  "Unable to allocate data(%d) for %*.*s\n",
				  (int)data.length,
				  (int)key.length, (int)key.length, key.data);
			return LDB_ERR_OPERATIONS_ERROR;
		}
	}

	ret = ldb_unpack_data_only_attr_list_flags(ldb, &data_parse,
						   ctx->msg,
						   NULL, 0,
						   ctx->unpack_flags,
						   &nb_elements_in_db);
	if (ret == -1) {
		if (data_parse.data != data.data) {
			talloc_free(data_parse.data);
		}

		ldb_debug(ldb, LDB_DEBUG_ERROR, "Invalid data for index %*.*s\n",
			  (int)key.length, (int)key.length, key.data);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	return ret;
}

/*
  search the database for a single simple dn, returning all attributes
  in a single message

  return LDB_ERR_NO_SUCH_OBJECT on record-not-found
  and LDB_SUCCESS on success
*/
int ltdb_search_key(struct ldb_module *module, struct ltdb_private *ltdb,
		    const struct TDB_DATA tdb_key,
		    struct ldb_message *msg,
		    unsigned int unpack_flags)
{
	int ret;
	struct ltdb_parse_data_unpack_ctx ctx = {
		.msg = msg,
		.module = module,
		.unpack_flags = unpack_flags
	};
	struct ldb_val ldb_key = {
		.data = tdb_key.dptr,
		.length = tdb_key.dsize
	};

	memset(msg, 0, sizeof(*msg));

	msg->num_elements = 0;
	msg->elements = NULL;

	ret = ltdb->kv_ops->fetch_and_parse(ltdb, ldb_key,
					    ltdb_parse_data_unpack, &ctx);

	if (ret == -1) {
		ret = ltdb->kv_ops->error(ltdb);
		if (ret == LDB_SUCCESS) {
			/*
			 * Just to be sure we don't turn errors
			 * into success
			 */
			return LDB_ERR_OPERATIONS_ERROR;
		}
		return ret;
	} else if (ret != LDB_SUCCESS) {
		return ret;
	}

	return LDB_SUCCESS;
}

/*
  search the database for a single simple dn, returning all attributes
  in a single message

  return LDB_ERR_NO_SUCH_OBJECT on record-not-found
  and LDB_SUCCESS on success
*/
int ltdb_search_dn1(struct ldb_module *module, struct ldb_dn *dn, struct ldb_message *msg,
		    unsigned int unpack_flags)
{
	void *data = ldb_module_get_private(module);
	struct ltdb_private *ltdb = talloc_get_type(data, struct ltdb_private);
	int ret;
	uint8_t guid_key[LTDB_GUID_KEY_SIZE];
	TDB_DATA tdb_key = {
		.dptr = guid_key,
		.dsize = sizeof(guid_key)
	};
	TALLOC_CTX *tdb_key_ctx = NULL;

	bool valid_dn = ldb_dn_validate(dn);
	if (valid_dn == false) {
		ldb_asprintf_errstring(ldb_module_get_ctx(module),
				       "Invalid Base DN: %s",
				       ldb_dn_get_linearized(dn));
		return LDB_ERR_INVALID_DN_SYNTAX;
	}

	if (ltdb->cache->GUID_index_attribute == NULL ||
		ldb_dn_is_special(dn)) {

		tdb_key_ctx = talloc_new(msg);
		if (!tdb_key_ctx) {
			return ldb_module_oom(module);
		}

		/* form the key */
		tdb_key = ltdb_key_dn(module, tdb_key_ctx, dn);
		if (!tdb_key.dptr) {
			TALLOC_FREE(tdb_key_ctx);
			return LDB_ERR_OPERATIONS_ERROR;
		}
	} else {
		/*
		 * Look in the index to find the key for this DN.
		 *
		 * the tdb_key memory is allocated above, msg is just
		 * used for internal memory.
		 *
		 */
		ret = ltdb_key_dn_from_idx(module, ltdb,
					   msg,
					   dn, &tdb_key);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	ret = ltdb_search_key(module, ltdb, tdb_key, msg, unpack_flags);

	TALLOC_FREE(tdb_key_ctx);

	if (ret != LDB_SUCCESS) {
		return ret;
	}

	if ((unpack_flags & LDB_UNPACK_DATA_FLAG_NO_DN) == 0) {
		if (!msg->dn) {
			msg->dn = ldb_dn_copy(msg, dn);
		}
		if (!msg->dn) {
			return LDB_ERR_OPERATIONS_ERROR;
		}
	}

	return LDB_SUCCESS;
}

/*
  filter the specified list of attributes from a message
  removing not requested attrs from the new message constructed.

  The reason this makes a new message is that the old one may not be
  individually allocated, which is what our callers expect.

 */
int ltdb_filter_attrs(TALLOC_CTX *mem_ctx,
		      const struct ldb_message *msg, const char * const *attrs,
		      struct ldb_message **filtered_msg)
{
	unsigned int i;
	bool keep_all = false;
	bool add_dn = false;
	uint32_t num_elements;
	uint32_t elements_size;
	struct ldb_message *msg2;

	msg2 = ldb_msg_new(mem_ctx);
	if (msg2 == NULL) {
		goto failed;
	}

	msg2->dn = ldb_dn_copy(msg2, msg->dn);
	if (msg2->dn == NULL) {
		goto failed;
	}

	if (attrs) {
		/* check for special attrs */
		for (i = 0; attrs[i]; i++) {
			int cmp = strcmp(attrs[i], "*");
			if (cmp == 0) {
				keep_all = true;
				break;
			}
			cmp = ldb_attr_cmp(attrs[i], "distinguishedName");
			if (cmp == 0) {
				add_dn = true;
			}
		}
	} else {
		keep_all = true;
	}

	if (keep_all) {
		add_dn = true;
		elements_size = msg->num_elements + 1;

	/* Shortcuts for the simple cases */
	} else if (add_dn && i == 1) {
		if (msg_add_distinguished_name(msg2) != 0) {
			goto failed;
		}
		*filtered_msg = msg2;
		return 0;
	} else if (i == 0) {
		*filtered_msg = msg2;
		return 0;

	/* Otherwise we are copying at most as many element as we have attributes */
	} else {
		elements_size = i;
	}

	msg2->elements = talloc_array(msg2, struct ldb_message_element,
				      elements_size);
	if (msg2->elements == NULL) goto failed;

	num_elements = 0;

	for (i = 0; i < msg->num_elements; i++) {
		struct ldb_message_element *el = &msg->elements[i];
		struct ldb_message_element *el2 = &msg2->elements[num_elements];
		unsigned int j;

		if (keep_all == false) {
			bool found = false;
			for (j = 0; attrs[j]; j++) {
				int cmp = ldb_attr_cmp(el->name, attrs[j]);
				if (cmp == 0) {
					found = true;
					break;
				}
			}
			if (found == false) {
				continue;
			}
		}
		*el2 = *el;
		el2->name = talloc_strdup(msg2->elements, el->name);
		if (el2->name == NULL) {
			goto failed;
		}
		el2->values = talloc_array(msg2->elements, struct ldb_val, el->num_values);
		if (el2->values == NULL) {
			goto failed;
		}
		for (j=0;j<el->num_values;j++) {
			el2->values[j] = ldb_val_dup(el2->values, &el->values[j]);
			if (el2->values[j].data == NULL && el->values[j].length != 0) {
				goto failed;
			}
		}
		num_elements++;

		/* Pidginhole principle: we can't have more elements
		 * than the number of attributes if they are unique in
		 * the DB */
		if (num_elements > elements_size) {
			goto failed;
		}
	}

	msg2->num_elements = num_elements;

	if (add_dn) {
		if (msg_add_distinguished_name(msg2) != 0) {
			goto failed;
		}
	}

	if (msg2->num_elements > 0) {
		msg2->elements = talloc_realloc(msg2, msg2->elements,
						struct ldb_message_element,
						msg2->num_elements);
		if (msg2->elements == NULL) {
			goto failed;
		}
	} else {
		talloc_free(msg2->elements);
		msg2->elements = NULL;
	}

	*filtered_msg = msg2;

	return 0;
failed:
	TALLOC_FREE(msg2);
	return -1;
}

/*
  search function for a non-indexed search
 */
static int search_func(struct ltdb_private *ltdb, struct ldb_val key, struct ldb_val val, void *state)
{
	struct ldb_context *ldb;
	struct ltdb_context *ac;
	struct ldb_message *msg, *filtered_msg;
	int ret;
	bool matched;
	unsigned int nb_elements_in_db;
	TDB_DATA tdb_key = {
		.dptr = key.data,
		.dsize = key.length
	};

	ac = talloc_get_type(state, struct ltdb_context);
	ldb = ldb_module_get_ctx(ac->module);

	if (ltdb_key_is_record(tdb_key) == false) {
		return 0;
	}

	msg = ldb_msg_new(ac);
	if (!msg) {
		ac->error = LDB_ERR_OPERATIONS_ERROR;
		return -1;
	}

	/* unpack the record */
	ret = ldb_unpack_data_only_attr_list_flags(ldb, &val,
						   msg,
						   NULL, 0,
						   LDB_UNPACK_DATA_FLAG_NO_DATA_ALLOC|
						   LDB_UNPACK_DATA_FLAG_NO_VALUES_ALLOC,
						   &nb_elements_in_db);
	if (ret == -1) {
		talloc_free(msg);
		ac->error = LDB_ERR_OPERATIONS_ERROR;
		return -1;
	}

	if (!msg->dn) {
		msg->dn = ldb_dn_new(msg, ldb,
				     (char *)key.data + 3);
		if (msg->dn == NULL) {
			talloc_free(msg);
			ac->error = LDB_ERR_OPERATIONS_ERROR;
			return -1;
		}
	}

	/* see if it matches the given expression */
	ret = ldb_match_msg_error(ldb, msg,
				  ac->tree, ac->base, ac->scope, &matched);
	if (ret != LDB_SUCCESS) {
		talloc_free(msg);
		ac->error = LDB_ERR_OPERATIONS_ERROR;
		return -1;
	}
	if (!matched) {
		talloc_free(msg);
		return 0;
	}

	/* filter the attributes that the user wants */
	ret = ltdb_filter_attrs(ac, msg, ac->attrs, &filtered_msg);
	talloc_free(msg);

	if (ret == -1) {
		ac->error = LDB_ERR_OPERATIONS_ERROR;
		return -1;
	}

	ret = ldb_module_send_entry(ac->req, filtered_msg, NULL);
	if (ret != LDB_SUCCESS) {
		ac->request_terminated = true;
		/* the callback failed, abort the operation */
		ac->error = LDB_ERR_OPERATIONS_ERROR;
		return -1;
	}

	return 0;
}


/*
  search the database with a LDAP-like expression.
  this is the "full search" non-indexed variant
*/
static int ltdb_search_full(struct ltdb_context *ctx)
{
	void *data = ldb_module_get_private(ctx->module);
	struct ltdb_private *ltdb = talloc_get_type(data, struct ltdb_private);
	int ret;

	ctx->error = LDB_SUCCESS;
	ret = ltdb->kv_ops->iterate(ltdb, search_func, ctx);

	if (ret < 0) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	return ctx->error;
}

static int ltdb_search_and_return_base(struct ltdb_private *ltdb,
				       struct ltdb_context *ctx)
{
	struct ldb_message *msg, *filtered_msg;
	struct ldb_context *ldb = ldb_module_get_ctx(ctx->module);
	const char *dn_linearized;
	const char *msg_dn_linearlized;
	int ret;
	bool matched;

	msg = ldb_msg_new(ctx);
	if (!msg) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	ret = ltdb_search_dn1(ctx->module, ctx->base, msg,
			      LDB_UNPACK_DATA_FLAG_NO_DATA_ALLOC|
			      LDB_UNPACK_DATA_FLAG_NO_VALUES_ALLOC);

	if (ret == LDB_ERR_NO_SUCH_OBJECT) {
		if (ltdb->check_base == false) {
			/*
			 * In this case, we are done, as no base
			 * checking is allowed in this DB
			 */
			talloc_free(msg);
			return LDB_SUCCESS;
		}
		ldb_asprintf_errstring(ldb,
				       "No such Base DN: %s",
				       ldb_dn_get_linearized(ctx->base));
	}
	if (ret != LDB_SUCCESS) {
		talloc_free(msg);
		return ret;
	}


	/*
	 * We use this, not ldb_match_msg_error() as we know
	 * we matched on the scope BASE, as we just fetched
	 * the base DN
	 */

	ret = ldb_match_message(ldb, msg,
				ctx->tree,
				ctx->scope,
				&matched);
	if (ret != LDB_SUCCESS) {
		talloc_free(msg);
		return ret;
	}
	if (!matched) {
		talloc_free(msg);
		return LDB_SUCCESS;
	}

	dn_linearized = ldb_dn_get_linearized(ctx->base);
	msg_dn_linearlized = ldb_dn_get_linearized(msg->dn);

	if (strcmp(dn_linearized, msg_dn_linearlized) == 0) {
		/*
		 * If the DN is exactly the same string, then
		 * re-use the full incoming DN for the
		 * returned result, as it has already been
		 * casefolded
		 */
		msg->dn = ctx->base;
	}

	/*
	 * filter the attributes that the user wants.
	 *
	 * This copies msg->dn including the casefolding, so the above
	 * assignment is safe
	 */
	ret = ltdb_filter_attrs(ctx, msg, ctx->attrs, &filtered_msg);

	/*
	 * Remove any extended components possibly copied in from
	 * msg->dn, we just want the casefold components
	 */
	ldb_dn_remove_extended_components(filtered_msg->dn);
	talloc_free(msg);

	if (ret == -1) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ldb_module_send_entry(ctx->req, filtered_msg, NULL);
	if (ret != LDB_SUCCESS) {
		/* Regardless of success or failure, the msg
		 * is the callbacks responsiblity, and should
		 * not be talloc_free()'ed */
		ctx->request_terminated = true;
		return ret;
	}

	return LDB_SUCCESS;
}

/*
  search the database with a LDAP-like expression.
  choses a search method
*/
int ltdb_search(struct ltdb_context *ctx)
{
	struct ldb_context *ldb;
	struct ldb_module *module = ctx->module;
	struct ldb_request *req = ctx->req;
	void *data = ldb_module_get_private(module);
	struct ltdb_private *ltdb = talloc_get_type(data, struct ltdb_private);
	int ret;

	ldb = ldb_module_get_ctx(module);

	ldb_request_set_state(req, LDB_ASYNC_PENDING);

	if (ltdb->kv_ops->lock_read(module) != 0) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (ltdb_cache_load(module) != 0) {
		ltdb->kv_ops->unlock_read(module);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (req->op.search.tree == NULL) {
		ltdb->kv_ops->unlock_read(module);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ctx->tree = req->op.search.tree;
	ctx->scope = req->op.search.scope;
	ctx->base = req->op.search.base;
	ctx->attrs = req->op.search.attrs;

	if ((req->op.search.base == NULL) || (ldb_dn_is_null(req->op.search.base) == true)) {

		/* Check what we should do with a NULL dn */
		switch (req->op.search.scope) {
		case LDB_SCOPE_BASE:
			ldb_asprintf_errstring(ldb, 
					       "NULL Base DN invalid for a base search");
			ret = LDB_ERR_INVALID_DN_SYNTAX;
			break;
		case LDB_SCOPE_ONELEVEL:
			ldb_asprintf_errstring(ldb, 
					       "NULL Base DN invalid for a one-level search");
			ret = LDB_ERR_INVALID_DN_SYNTAX;	
			break;
		case LDB_SCOPE_SUBTREE:
		default:
			/* We accept subtree searches from a NULL base DN, ie over the whole DB */
			ret = LDB_SUCCESS;
		}
	} else if (ldb_dn_is_valid(req->op.search.base) == false) {

		/* We don't want invalid base DNs here */
		ldb_asprintf_errstring(ldb, 
				       "Invalid Base DN: %s", 
				       ldb_dn_get_linearized(req->op.search.base));
		ret = LDB_ERR_INVALID_DN_SYNTAX;

	} else if (req->op.search.scope == LDB_SCOPE_BASE) {

		/*
		 * If we are LDB_SCOPE_BASE, do just one search and
		 * return early.  This is critical to ensure we do not
		 * go into the index code for special DNs, as that
		 * will try to look up an index record for a special
		 * record (which doesn't exist).
		 */
		ret = ltdb_search_and_return_base(ltdb, ctx);

		ltdb->kv_ops->unlock_read(module);

		return ret;

	} else if (ltdb->check_base) {
		/*
		 * This database has been marked as
		 * 'checkBaseOnSearch', so do a spot check of the base
		 * dn.  Also optimise the subsequent filter by filling
		 * in the ctx->base to be exactly case correct
		 */
		ret = ltdb_search_base(module, ctx,
				       req->op.search.base,
				       &ctx->base);
		
		if (ret == LDB_ERR_NO_SUCH_OBJECT) {
			ldb_asprintf_errstring(ldb, 
					       "No such Base DN: %s", 
					       ldb_dn_get_linearized(req->op.search.base));
		}
			
	} else if (ldb_dn_validate(req->op.search.base) == false) {

		/* We don't want invalid base DNs here */
		ldb_asprintf_errstring(ldb,
				       "Invalid Base DN: %s",
				       ldb_dn_get_linearized(req->op.search.base));
		ret = LDB_ERR_INVALID_DN_SYNTAX;

	} else {
		/* If we are not checking the base DN life is easy */
		ret = LDB_SUCCESS;
	}

	if (ret == LDB_SUCCESS) {
		uint32_t match_count = 0;

		ret = ltdb_search_indexed(ctx, &match_count);
		if (ret == LDB_ERR_NO_SUCH_OBJECT) {
			/* Not in the index, therefore OK! */
			ret = LDB_SUCCESS;
			
		}
		/* Check if we got just a normal error.
		 * In that case proceed to a full search unless we got a
		 * callback error */
		if ( ! ctx->request_terminated && ret != LDB_SUCCESS) {
			/* Not indexed, so we need to do a full scan */
			if (ltdb->warn_unindexed || ltdb->disable_full_db_scan) {
				/* useful for debugging when slow performance
				 * is caused by unindexed searches */
				char *expression = ldb_filter_from_tree(ctx, ctx->tree);
				ldb_debug(ldb, LDB_DEBUG_ERROR, "ldb FULL SEARCH: %s SCOPE: %s DN: %s",
							expression,
							req->op.search.scope==LDB_SCOPE_BASE?"base":
							req->op.search.scope==LDB_SCOPE_ONELEVEL?"one":
							req->op.search.scope==LDB_SCOPE_SUBTREE?"sub":"UNKNOWN",
							ldb_dn_get_linearized(req->op.search.base));

				talloc_free(expression);
			}

			if (match_count != 0) {
				/* the indexing code gave an error
				 * after having returned at least one
				 * entry. This means the indexes are
				 * corrupt or a database record is
				 * corrupt. We cannot continue with a
				 * full search or we may return
				 * duplicate entries
				 */
				ltdb->kv_ops->unlock_read(module);
				return LDB_ERR_OPERATIONS_ERROR;
			}

			if (ltdb->disable_full_db_scan) {
				ldb_set_errstring(ldb,
						  "ldb FULL SEARCH disabled");
				ltdb->kv_ops->unlock_read(module);
				return LDB_ERR_INAPPROPRIATE_MATCHING;
			}

			ret = ltdb_search_full(ctx);
			if (ret != LDB_SUCCESS) {
				ldb_set_errstring(ldb, "Indexed and full searches both failed!\n");
			}
		}
	}

	ltdb->kv_ops->unlock_read(module);

	return ret;
}

