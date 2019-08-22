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
 *  Component: ldb tdb cache functions
 *
 *  Description: cache special records in a ldb/tdb
 *
 *  Author: Andrew Tridgell
 */

#include "ldb_tdb.h"
#include "ldb_private.h"

#define LTDB_FLAG_CASE_INSENSITIVE (1<<0)
#define LTDB_FLAG_INTEGER          (1<<1)
#define LTDB_FLAG_UNIQUE_INDEX     (1<<2)

/* valid attribute flags */
static const struct {
	const char *name;
	int value;
} ltdb_valid_attr_flags[] = {
	{ "CASE_INSENSITIVE", LTDB_FLAG_CASE_INSENSITIVE },
	{ "INTEGER", LTDB_FLAG_INTEGER },
	{ "HIDDEN", 0 },
	{ "UNIQUE_INDEX",  LTDB_FLAG_UNIQUE_INDEX},
	{ "NONE", 0 },
	{ NULL, 0 }
};


/*
  de-register any special handlers for @ATTRIBUTES
*/
static void ltdb_attributes_unload(struct ldb_module *module)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);

	ldb_schema_attribute_remove_flagged(ldb, LDB_ATTR_FLAG_FROM_DB);

}

/*
  add up the attrib flags for a @ATTRIBUTES element
*/
static int ltdb_attributes_flags(struct ldb_message_element *el, unsigned *v)
{
	unsigned int i;
	unsigned value = 0;
	for (i=0;i<el->num_values;i++) {
		unsigned int j;
		for (j=0;ltdb_valid_attr_flags[j].name;j++) {
			if (strcmp(ltdb_valid_attr_flags[j].name, 
				   (char *)el->values[i].data) == 0) {
				value |= ltdb_valid_attr_flags[j].value;
				break;
			}
		}
		if (ltdb_valid_attr_flags[j].name == NULL) {
			return -1;
		}
	}
	*v = value;
	return 0;
}

static int ldb_schema_attribute_compare(const void *p1, const void *p2)
{
	const struct ldb_schema_attribute *sa1 = (const struct ldb_schema_attribute *)p1;
	const struct ldb_schema_attribute *sa2 = (const struct ldb_schema_attribute *)p2;
	return ldb_attr_cmp(sa1->name, sa2->name);
}

/*
  register any special handlers from @ATTRIBUTES
*/
static int ltdb_attributes_load(struct ldb_module *module)
{
	struct ldb_schema_attribute *attrs;
	struct ldb_context *ldb;
	struct ldb_message *attrs_msg = NULL;
	struct ldb_dn *dn;
	unsigned int i;
	unsigned int num_loaded_attrs = 0;
	int r;

	ldb = ldb_module_get_ctx(module);

	if (ldb->schema.attribute_handler_override) {
		/* we skip loading the @ATTRIBUTES record when a module is supplying
		   its own attribute handling */
		return 0;
	}

	attrs_msg = ldb_msg_new(module);
	if (attrs_msg == NULL) {
		goto failed;
	}

	dn = ldb_dn_new(module, ldb, LTDB_ATTRIBUTES);
	if (dn == NULL) goto failed;

	r = ltdb_search_dn1(module, dn, attrs_msg,
			    LDB_UNPACK_DATA_FLAG_NO_DATA_ALLOC
			    |LDB_UNPACK_DATA_FLAG_NO_VALUES_ALLOC
			    |LDB_UNPACK_DATA_FLAG_NO_DN);
	talloc_free(dn);
	if (r != LDB_SUCCESS && r != LDB_ERR_NO_SUCH_OBJECT) {
		goto failed;
	}
	if (r == LDB_ERR_NO_SUCH_OBJECT || attrs_msg->num_elements == 0) {
		TALLOC_FREE(attrs_msg);
		return 0;
	}

	attrs = talloc_array(attrs_msg,
			     struct ldb_schema_attribute,
			     attrs_msg->num_elements
			     + ldb->schema.num_attributes);
	if (attrs == NULL) {
		goto failed;
	}

	memcpy(attrs,
	       ldb->schema.attributes,
	       sizeof(ldb->schema.attributes[0]) * ldb->schema.num_attributes);

	/* mapping these flags onto ldap 'syntaxes' isn't strictly correct,
	   but its close enough for now */
	for (i=0;i<attrs_msg->num_elements;i++) {
		unsigned flags = 0, attr_flags = 0;
		const char *syntax;
		const struct ldb_schema_syntax *s;
		const struct ldb_schema_attribute *a =
			ldb_schema_attribute_by_name(ldb,
						     attrs_msg->elements[i].name);
		if (a != NULL && a->flags & LDB_ATTR_FLAG_FIXED) {
			/* Must already be set in the array, and kept */
			continue;
		}

		if (ltdb_attributes_flags(&attrs_msg->elements[i], &flags) != 0) {
			ldb_debug(ldb, LDB_DEBUG_ERROR,
				  "Invalid @ATTRIBUTES element for '%s'",
				  attrs_msg->elements[i].name);
			goto failed;
		}

		if (flags & LTDB_FLAG_UNIQUE_INDEX) {
			attr_flags = LDB_ATTR_FLAG_UNIQUE_INDEX;
		}
		flags &= ~LTDB_FLAG_UNIQUE_INDEX;

		/* These are not currently flags, each is exclusive */
		if (flags == LTDB_FLAG_CASE_INSENSITIVE) {
			syntax = LDB_SYNTAX_DIRECTORY_STRING;
		} else if (flags == LTDB_FLAG_INTEGER) {
			syntax = LDB_SYNTAX_INTEGER;
		} else if (flags == 0) {
			syntax = LDB_SYNTAX_OCTET_STRING;
		} else {
			ldb_debug(ldb, LDB_DEBUG_ERROR, 
				  "Invalid flag combination 0x%x for '%s' "
				  "in @ATTRIBUTES",
				  flags, attrs_msg->elements[i].name);
			goto failed;
		}

		s = ldb_standard_syntax_by_name(ldb, syntax);
		if (s == NULL) {
			ldb_debug(ldb, LDB_DEBUG_ERROR, 
				  "Invalid attribute syntax '%s' for '%s' "
				  "in @ATTRIBUTES",
				  syntax, attrs_msg->elements[i].name);
			goto failed;
		}

		attr_flags |= LDB_ATTR_FLAG_ALLOCATED | LDB_ATTR_FLAG_FROM_DB;

		r = ldb_schema_attribute_fill_with_syntax(ldb,
							  attrs,
							  attrs_msg->elements[i].name,
							  attr_flags, s,
							  &attrs[num_loaded_attrs + ldb->schema.num_attributes]);
		if (r != 0) {
			goto failed;
		}
		num_loaded_attrs++;
	}

	attrs = talloc_realloc(attrs_msg,
			       attrs, struct ldb_schema_attribute,
			       num_loaded_attrs + ldb->schema.num_attributes);
	if (attrs == NULL) {
		goto failed;
	}
	TYPESAFE_QSORT(attrs, num_loaded_attrs + ldb->schema.num_attributes,
		       ldb_schema_attribute_compare);
	talloc_unlink(ldb, ldb->schema.attributes);
	ldb->schema.attributes = talloc_steal(ldb, attrs);
	ldb->schema.num_attributes = num_loaded_attrs + ldb->schema.num_attributes;
	TALLOC_FREE(attrs_msg);

	return 0;
failed:
	TALLOC_FREE(attrs_msg);
	return -1;
}

/*
  register any index records we find for the DB
*/
static int ltdb_index_load(struct ldb_module *module,
			   struct ltdb_private *ltdb)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct ldb_dn *indexlist_dn;
	int r, lmdb_subdb_version;

	if (ldb->schema.index_handler_override) {
		/*
		 * we skip loading the @INDEXLIST record when a module is
		 * supplying its own attribute handling
		 */
		ltdb->cache->attribute_indexes = true;
		ltdb->cache->one_level_indexes = ldb->schema.one_level_indexes;
		ltdb->cache->GUID_index_attribute
			= ldb->schema.GUID_index_attribute;
		ltdb->cache->GUID_index_dn_component
			= ldb->schema.GUID_index_dn_component;
		return 0;
	}

	talloc_free(ltdb->cache->indexlist);

	ltdb->cache->indexlist = ldb_msg_new(ltdb->cache);
	if (ltdb->cache->indexlist == NULL) {
		return -1;
	}
	ltdb->cache->one_level_indexes = false;
	ltdb->cache->attribute_indexes = false;

	indexlist_dn = ldb_dn_new(ltdb, ldb, LTDB_INDEXLIST);
	if (indexlist_dn == NULL) {
		return -1;
	}

	r = ltdb_search_dn1(module, indexlist_dn, ltdb->cache->indexlist,
			    LDB_UNPACK_DATA_FLAG_NO_DATA_ALLOC
			    |LDB_UNPACK_DATA_FLAG_NO_VALUES_ALLOC
			    |LDB_UNPACK_DATA_FLAG_NO_DN);
	TALLOC_FREE(indexlist_dn);

	if (r != LDB_SUCCESS && r != LDB_ERR_NO_SUCH_OBJECT) {
		return -1;
	}

	if (ldb_msg_find_element(ltdb->cache->indexlist, LTDB_IDXONE) != NULL) {
		ltdb->cache->one_level_indexes = true;
	}
	if (ldb_msg_find_element(ltdb->cache->indexlist, LTDB_IDXATTR) != NULL) {
		ltdb->cache->attribute_indexes = true;
	}
	ltdb->cache->GUID_index_attribute
		= ldb_msg_find_attr_as_string(ltdb->cache->indexlist,
					      LTDB_IDXGUID, NULL);
	ltdb->cache->GUID_index_dn_component
		= ldb_msg_find_attr_as_string(ltdb->cache->indexlist,
					      LTDB_IDX_DN_GUID, NULL);

	lmdb_subdb_version
		= ldb_msg_find_attr_as_int(ltdb->cache->indexlist,
					   LTDB_IDX_LMDB_SUBDB, 0);

	if (lmdb_subdb_version != 0) {
		ldb_set_errstring(ldb,
				  "FATAL: This ldb_mdb database has "
				  "been written in a new verson of LDB "
				  "using a sub-database index that "
				  "is not understood by ldb "
				  LDB_VERSION);
		return -1;
	}

	return 0;
}

/*
  initialise the baseinfo record
*/
static int ltdb_baseinfo_init(struct ldb_module *module)
{
	struct ldb_context *ldb;
	void *data = ldb_module_get_private(module);
	struct ltdb_private *ltdb = talloc_get_type(data, struct ltdb_private);
	struct ldb_message *msg;
	struct ldb_message_element el;
	struct ldb_val val;
	int ret;
	/* the initial sequence number must be different from the one
	   set in ltdb_cache_free(). Thanks to Jon for pointing this
	   out. */
	const char *initial_sequence_number = "1";

	ldb = ldb_module_get_ctx(module);

	ltdb->sequence_number = atof(initial_sequence_number);

	msg = ldb_msg_new(ltdb);
	if (msg == NULL) {
		goto failed;
	}

	msg->num_elements = 1;
	msg->elements = &el;
	msg->dn = ldb_dn_new(msg, ldb, LTDB_BASEINFO);
	if (!msg->dn) {
		goto failed;
	}
	el.name = talloc_strdup(msg, LTDB_SEQUENCE_NUMBER);
	if (!el.name) {
		goto failed;
	}
	el.values = &val;
	el.num_values = 1;
	el.flags = 0;
	val.data = (uint8_t *)talloc_strdup(msg, initial_sequence_number);
	if (!val.data) {
		goto failed;
	}
	val.length = 1;
	
	ret = ltdb_store(module, msg, TDB_INSERT);

	talloc_free(msg);

	return ret;

failed:
	talloc_free(msg);
	errno = ENOMEM;
	return LDB_ERR_OPERATIONS_ERROR;
}

/*
  free any cache records
 */
static void ltdb_cache_free(struct ldb_module *module)
{
	void *data = ldb_module_get_private(module);
	struct ltdb_private *ltdb = talloc_get_type(data, struct ltdb_private);

	ltdb->sequence_number = 0;
	talloc_free(ltdb->cache);
	ltdb->cache = NULL;
}

/*
  force a cache reload
*/
int ltdb_cache_reload(struct ldb_module *module)
{
	ltdb_attributes_unload(module);
	ltdb_cache_free(module);
	return ltdb_cache_load(module);
}

/*
  load the cache records
*/
int ltdb_cache_load(struct ldb_module *module)
{
	struct ldb_context *ldb;
	void *data = ldb_module_get_private(module);
	struct ltdb_private *ltdb = talloc_get_type(data, struct ltdb_private);
	struct ldb_dn *baseinfo_dn = NULL, *options_dn = NULL;
	uint64_t seq;
	struct ldb_message *baseinfo = NULL, *options = NULL;
	const struct ldb_schema_attribute *a;
	bool have_write_txn = false;
	int r;

	ldb = ldb_module_get_ctx(module);

	/* a very fast check to avoid extra database reads */
	if (ltdb->cache != NULL && !ltdb->kv_ops->has_changed(ltdb)) {
		return 0;
	}

	if (ltdb->cache == NULL) {
		ltdb->cache = talloc_zero(ltdb, struct ltdb_cache);
		if (ltdb->cache == NULL) goto failed;
	}

	baseinfo = ldb_msg_new(ltdb->cache);
	if (baseinfo == NULL) goto failed;

	baseinfo_dn = ldb_dn_new(baseinfo, ldb, LTDB_BASEINFO);
	if (baseinfo_dn == NULL) goto failed;

	r = ltdb->kv_ops->lock_read(module);
	if (r != LDB_SUCCESS) {
		goto failed;
	}
	r= ltdb_search_dn1(module, baseinfo_dn, baseinfo, 0);
	if (r != LDB_SUCCESS && r != LDB_ERR_NO_SUCH_OBJECT) {
		goto failed_and_unlock;
	}

	/* possibly initialise the baseinfo */
	if (r == LDB_ERR_NO_SUCH_OBJECT) {

		/* Give up the read lock, try again with a write lock */
		r = ltdb->kv_ops->unlock_read(module);
		if (r != LDB_SUCCESS) {
			goto failed;
		}

		if (ltdb->kv_ops->begin_write(ltdb) != 0) {
			goto failed;
		}

		have_write_txn = true;

		/* error handling for ltdb_baseinfo_init() is by
		   looking for the record again. */
		ltdb_baseinfo_init(module);

		if (ltdb_search_dn1(module, baseinfo_dn, baseinfo, 0) != LDB_SUCCESS) {
			goto failed_and_unlock;
		}

	}

	/* Ignore the result, and update the sequence number */
	ltdb->kv_ops->has_changed(ltdb);

	/* if the current internal sequence number is the same as the one
	   in the database then assume the rest of the cache is OK */
	seq = ldb_msg_find_attr_as_uint64(baseinfo, LTDB_SEQUENCE_NUMBER, 0);
	if (seq == ltdb->sequence_number) {
		goto done;
	}
	ltdb->sequence_number = seq;

	/* Read an interpret database options */

	options = ldb_msg_new(ltdb->cache);
	if (options == NULL) goto failed_and_unlock;

	options_dn = ldb_dn_new(options, ldb, LTDB_OPTIONS);
	if (options_dn == NULL) goto failed_and_unlock;

	r= ltdb_search_dn1(module, options_dn, options, 0);
	talloc_free(options_dn);
	if (r != LDB_SUCCESS && r != LDB_ERR_NO_SUCH_OBJECT) {
		goto failed_and_unlock;
	}
	
	/* set flags if they do exist */
	if (r == LDB_SUCCESS) {
		ltdb->check_base = ldb_msg_find_attr_as_bool(options,
							     LTDB_CHECK_BASE,
							     false);
		ltdb->disallow_dn_filter = ldb_msg_find_attr_as_bool(options,
								     LTDB_DISALLOW_DN_FILTER,
								     false);
	} else {
		ltdb->check_base = false;
		ltdb->disallow_dn_filter = false;
	}

	/*
	 * ltdb_attributes_unload() calls internally talloc_free() on
	 * any non-fixed elemnts in ldb->schema.attributes.
	 *
	 * NOTE WELL: This is per-ldb, not per module, so overwrites
	 * the handlers across all databases when used under Samba's
	 * partition module.
	 */
	ltdb_attributes_unload(module);

	if (ltdb_index_load(module, ltdb) == -1) {
		goto failed_and_unlock;
	}

	/*
	 * NOTE WELL: This is per-ldb, not per module, so overwrites
	 * the handlers across all databases when used under Samba's
	 * partition module.
	 */
	if (ltdb_attributes_load(module) == -1) {
		goto failed_and_unlock;
	}

	ltdb->GUID_index_syntax = NULL;
	if (ltdb->cache->GUID_index_attribute != NULL) {
		/*
		 * Now the attributes are loaded, set the guid_index_syntax.
		 * This can't fail, it will return a default at worst
		 */
		a = ldb_schema_attribute_by_name(ldb,
						 ltdb->cache->GUID_index_attribute);
		ltdb->GUID_index_syntax = a->syntax;
	}

done:
	if (have_write_txn) {
		if (ltdb->kv_ops->finish_write(ltdb) != 0) {
			goto failed;
		}
	} else {
		ltdb->kv_ops->unlock_read(module);
	}

	talloc_free(options);
	talloc_free(baseinfo);
	return 0;

failed_and_unlock:
	if (have_write_txn) {
		ltdb->kv_ops->abort_write(ltdb);
	} else {
		ltdb->kv_ops->unlock_read(module);
	}

failed:
	talloc_free(options);
	talloc_free(baseinfo);
	return -1;
}


/*
  increase the sequence number to indicate a database change
*/
int ltdb_increase_sequence_number(struct ldb_module *module)
{
	struct ldb_context *ldb;
	void *data = ldb_module_get_private(module);
	struct ltdb_private *ltdb = talloc_get_type(data, struct ltdb_private);
	struct ldb_message *msg;
	struct ldb_message_element el[2];
	struct ldb_val val;
	struct ldb_val val_time;
	time_t t = time(NULL);
	char *s = NULL;
	int ret;

	ldb = ldb_module_get_ctx(module);

	msg = ldb_msg_new(ltdb);
	if (msg == NULL) {
		errno = ENOMEM;
		return LDB_ERR_OPERATIONS_ERROR;
	}

	s = talloc_asprintf(msg, "%llu", ltdb->sequence_number+1);
	if (!s) {
		talloc_free(msg);
		errno = ENOMEM;
		return LDB_ERR_OPERATIONS_ERROR;
	}

	msg->num_elements = ARRAY_SIZE(el);
	msg->elements = el;
	msg->dn = ldb_dn_new(msg, ldb, LTDB_BASEINFO);
	if (msg->dn == NULL) {
		talloc_free(msg);
		errno = ENOMEM;
		return LDB_ERR_OPERATIONS_ERROR;
	}
	el[0].name = talloc_strdup(msg, LTDB_SEQUENCE_NUMBER);
	if (el[0].name == NULL) {
		talloc_free(msg);
		errno = ENOMEM;
		return LDB_ERR_OPERATIONS_ERROR;
	}
	el[0].values = &val;
	el[0].num_values = 1;
	el[0].flags = LDB_FLAG_MOD_REPLACE;
	val.data = (uint8_t *)s;
	val.length = strlen(s);

	el[1].name = talloc_strdup(msg, LTDB_MOD_TIMESTAMP);
	if (el[1].name == NULL) {
		talloc_free(msg);
		errno = ENOMEM;
		return LDB_ERR_OPERATIONS_ERROR;
	}
	el[1].values = &val_time;
	el[1].num_values = 1;
	el[1].flags = LDB_FLAG_MOD_REPLACE;

	s = ldb_timestring(msg, t);
	if (s == NULL) {
		talloc_free(msg);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	val_time.data = (uint8_t *)s;
	val_time.length = strlen(s);

	ret = ltdb_modify_internal(module, msg, NULL);

	talloc_free(msg);

	if (ret == LDB_SUCCESS) {
		ltdb->sequence_number += 1;
	}

	/* updating the tdb_seqnum here avoids us reloading the cache
	   records due to our own modification */
	ltdb->kv_ops->has_changed(ltdb);

	return ret;
}

int ltdb_check_at_attributes_values(const struct ldb_val *value)
{
	unsigned int i;

	for (i = 0; ltdb_valid_attr_flags[i].name != NULL; i++) {
		if ((strcmp(ltdb_valid_attr_flags[i].name, (char *)value->data) == 0)) {
			return 0;
		}
	}

	return -1;
}

