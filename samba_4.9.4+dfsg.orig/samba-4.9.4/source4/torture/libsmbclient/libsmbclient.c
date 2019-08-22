/*
   Unix SMB/CIFS implementation.
   SMB torture tester
   Copyright (C) Guenther Deschner 2010

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "torture/smbtorture.h"
#include "auth/credentials/credentials.h"
#include "lib/cmdline/popt_common.h"
#include <libsmbclient.h>
#include "torture/libsmbclient/proto.h"
#include "lib/param/loadparm.h"
#include "lib/param/param_global.h"
#include "dynconfig.h"

/* test string to compare with when debug_callback is called */
#define TEST_STRING "smbc_setLogCallback test"

/* Dummy log callback function */
static void debug_callback(void *private_ptr, int level, const char *msg)
{
	bool *found = private_ptr;
	if (strstr(msg, TEST_STRING) != NULL) {
		*found = true;
	}
	return;
}

bool torture_libsmbclient_init_context(struct torture_context *tctx,
				       SMBCCTX **ctx_p)
{
	SMBCCTX *ctx;

	ctx = smbc_new_context();
	torture_assert(tctx, ctx, "failed to get new context");
	torture_assert(tctx, smbc_init_context(ctx), "failed to init context");

	smbc_setDebug(ctx, DEBUGLEVEL);
	smbc_setOptionDebugToStderr(ctx, 1);

	smbc_setUser(ctx,
		     cli_credentials_get_username(popt_get_cmdline_credentials()));

	*ctx_p = ctx;

	return true;
}

static bool torture_libsmbclient_version(struct torture_context *tctx)
{
	torture_comment(tctx, "Testing smbc_version\n");

	torture_assert(tctx, smbc_version(), "failed to get version");

	return true;
}

static bool torture_libsmbclient_initialize(struct torture_context *tctx)
{
	SMBCCTX *ctx;
	bool ret = false;

	torture_comment(tctx, "Testing smbc_new_context\n");

	ctx = smbc_new_context();
	torture_assert(tctx, ctx, "failed to get new context");

	torture_comment(tctx, "Testing smbc_init_context\n");

	torture_assert(tctx, smbc_init_context(ctx), "failed to init context");

	smbc_setLogCallback(ctx, &ret, debug_callback);
	DEBUG(0, (TEST_STRING"\n"));
	torture_assert(tctx, ret, "Failed debug_callback not called");
	ret = false;
	smbc_setLogCallback(ctx, NULL, NULL);
	DEBUG(0, (TEST_STRING"\n"));
	torture_assert(tctx, !ret, "Failed debug_callback called");

	smbc_free_context(ctx, 1);

	return true;
}

static bool torture_libsmbclient_setConfiguration(struct torture_context *tctx)
{
	SMBCCTX *ctx;
	struct loadparm_global *global_config = NULL;
	const char *new_smb_conf = torture_setting_string(tctx,
				"replace_smbconf",
				"");

	ctx = smbc_new_context();
	torture_assert(tctx, ctx, "failed to get new context");

	torture_assert(tctx, smbc_init_context(ctx), "failed to init context");

	torture_comment(tctx, "Testing smbc_setConfiguration - new file %s\n",
		new_smb_conf);

	global_config = get_globals();
	torture_assert(tctx, global_config, "Global Config is NULL");

	/* check configuration before smbc_setConfiguration call */
	torture_comment(tctx, "'workgroup' before setConfiguration %s\n",
			global_config->workgroup);
	torture_comment(tctx, "'client min protocol' before "
			"setConfiguration %d\n",
			global_config->client_min_protocol);
	torture_comment(tctx, "'client max protocol' before "
			"setConfiguration %d\n",
			global_config->_client_max_protocol);
	torture_comment(tctx, "'client signing' before setConfiguration %d\n",
			global_config->client_signing);
	torture_comment(tctx, "'deadtime' before setConfiguration %d\n",
			global_config->deadtime);

	torture_assert_int_equal(tctx, smbc_setConfiguration(ctx, new_smb_conf),
			0, "setConfiguration conf file not found");

	/* verify configuration */
	torture_assert_str_equal(tctx, global_config->workgroup,
			"NEW_WORKGROUP",
			"smbc_setConfiguration failed, "
			"'workgroup' not updated");
	torture_assert_int_equal(tctx, global_config->client_min_protocol, 7,
			"smbc_setConfiguration failed, 'client min protocol' "
			"not updated");
	torture_assert_int_equal(tctx, global_config->_client_max_protocol, 13,
			"smbc_setConfiguration failed, 'client max protocol' "
			"not updated");
	torture_assert_int_equal(tctx, global_config->client_signing, 1,
			"smbc_setConfiguration failed, 'client signing' "
			"not updated");
	torture_assert_int_equal(tctx, global_config->deadtime, 5,
			"smbc_setConfiguration failed, 'deadtime' not updated");

	/* Restore configuration to default */
	smbc_setConfiguration(ctx, get_dyn_CONFIGFILE());

	smbc_free_context(ctx, 1);

	return true;
}

static bool test_opendir(struct torture_context *tctx,
			 SMBCCTX *ctx,
			 const char *fname,
			 bool expect_success)
{
	int handle, ret;

	torture_comment(tctx, "Testing smbc_opendir(%s)\n", fname);

	handle = smbc_opendir(fname);
	if (!expect_success) {
		return true;
	}
	if (handle < 0) {
		torture_fail(tctx, talloc_asprintf(tctx, "failed to obain file handle for '%s'", fname));
	}

	ret = smbc_closedir(handle);
	torture_assert_int_equal(tctx, ret, 0,
		talloc_asprintf(tctx, "failed to close file handle for '%s'", fname));

	return true;
}

static bool torture_libsmbclient_opendir(struct torture_context *tctx)
{
	int i;
	SMBCCTX *ctx;
	bool ret = true;
	const char *bad_urls[] = {
		"",
		NULL,
		"smb",
		"smb:",
		"smb:/",
		"smb:///",
		"bms://",
		":",
		":/",
		"://",
		":///",
		"/",
		"//",
		"///"
	};
	const char *good_urls[] = {
		"smb://",
		"smb://WORKGROUP",
		"smb://WORKGROUP/"
	};

	torture_assert(tctx, torture_libsmbclient_init_context(tctx, &ctx), "");
	smbc_set_context(ctx);

	for (i=0; i < ARRAY_SIZE(bad_urls); i++) {
		ret &= test_opendir(tctx, ctx, bad_urls[i], false);
	}
	for (i=0; i < ARRAY_SIZE(good_urls); i++) {
		ret &= test_opendir(tctx, ctx, good_urls[i], true);
	}

	smbc_free_context(ctx, 1);

	return ret;
}

static bool torture_libsmbclient_readdirplus(struct torture_context *tctx)
{
	SMBCCTX *ctx;
	int ret = -1;
	int dhandle = -1;
	int fhandle = -1;
	bool found = false;
	const char *filename = NULL;
	const char *smburl = torture_setting_string(tctx, "smburl", NULL);

	if (smburl == NULL) {
		torture_fail(tctx,
			"option --option=torture:smburl="
			"smb://user:password@server/share missing\n");
	}

	torture_assert(tctx, torture_libsmbclient_init_context(tctx, &ctx), "");
	smbc_set_context(ctx);

	filename = talloc_asprintf(tctx,
				"%s/test_readdirplus.txt",
				smburl);
	if (filename == NULL) {
		torture_fail(tctx,
			"talloc fail\n");
	}
	/* Ensure the file doesn't exist. */
	smbc_unlink(filename);

	/* Create it. */
	fhandle = smbc_creat(filename, 0666);
	if (fhandle < 0) {
		torture_fail(tctx,
			talloc_asprintf(tctx,
				"failed to create file '%s': %s",
				filename,
				strerror(errno)));
	}
	ret = smbc_close(fhandle);
	torture_assert_int_equal(tctx,
		ret,
		0,
		talloc_asprintf(tctx,
			"failed to close handle for '%s'",
			filename));

	dhandle = smbc_opendir(smburl);
	if (dhandle < 0) {
		int saved_errno = errno;
		smbc_unlink(filename);
		torture_fail(tctx,
			talloc_asprintf(tctx,
				"failed to obtain "
				"directory handle for '%s' : %s",
				smburl,
				strerror(saved_errno)));
	}

	/* Readdirplus to ensure we see the new file. */
	for (;;) {
		const struct libsmb_file_info *exstat =
			smbc_readdirplus(dhandle);
		if (exstat == NULL) {
			break;
		}
		if (strcmp(exstat->name, "test_readdirplus.txt") == 0) {
			found = true;
			break;
		}
	}

	/* Remove it again. */
	smbc_unlink(filename);
	ret = smbc_closedir(dhandle);
	torture_assert_int_equal(tctx,
		ret,
		0,
		talloc_asprintf(tctx,
			"failed to close directory handle for '%s'",
			smburl));

	smbc_free_context(ctx, 1);

	if (!found) {
		torture_fail(tctx,
			talloc_asprintf(tctx,
				"failed to find file '%s'",
				filename));
	}

	return true;
}

bool torture_libsmbclient_configuration(struct torture_context *tctx)
{
	SMBCCTX *ctx;
	bool ok = true;

	ctx = smbc_new_context();
	torture_assert(tctx, ctx, "failed to get new context");
	torture_assert(tctx, smbc_init_context(ctx), "failed to init context");

	torture_comment(tctx, "Testing smbc_(set|get)Debug\n");
	smbc_setDebug(ctx, DEBUGLEVEL);
	torture_assert_int_equal_goto(tctx,
				      smbc_getDebug(ctx),
				      DEBUGLEVEL,
				      ok,
				      done,
				      "failed to set DEBUGLEVEL");

	torture_comment(tctx, "Testing smbc_(set|get)NetbiosName\n");
	smbc_setNetbiosName(ctx, discard_const("torture_netbios"));
	torture_assert_str_equal_goto(tctx,
				      smbc_getNetbiosName(ctx),
				      "torture_netbios",
				      ok,
				      done,
				      "failed to set NetbiosName");

	torture_comment(tctx, "Testing smbc_(set|get)Workgroup\n");
	smbc_setWorkgroup(ctx, discard_const("torture_workgroup"));
	torture_assert_str_equal_goto(tctx,
				      smbc_getWorkgroup(ctx),
				      "torture_workgroup",
				      ok,
				      done,
				      "failed to set Workgroup");

	torture_comment(tctx, "Testing smbc_(set|get)User\n");
	smbc_setUser(ctx, "torture_user");
	torture_assert_str_equal_goto(tctx,
				      smbc_getUser(ctx),
				      "torture_user",
				      ok,
				      done,
				      "failed to set User");

	torture_comment(tctx, "Testing smbc_(set|get)Timeout\n");
	smbc_setTimeout(ctx, 12345);
	torture_assert_int_equal_goto(tctx,
				      smbc_getTimeout(ctx),
				      12345,
				      ok,
				      done,
				      "failed to set Timeout");

done:
	smbc_free_context(ctx, 1);

	return ok;
}

bool torture_libsmbclient_options(struct torture_context *tctx)
{
	SMBCCTX *ctx;
	bool ok = true;

	ctx = smbc_new_context();
	torture_assert(tctx, ctx, "failed to get new context");
	torture_assert(tctx, smbc_init_context(ctx), "failed to init context");

	torture_comment(tctx, "Testing smbc_(set|get)OptionDebugToStderr\n");
	smbc_setOptionDebugToStderr(ctx, true);
	torture_assert_goto(tctx,
			    smbc_getOptionDebugToStderr(ctx),
			    ok,
			    done,
			    "failed to set OptionDebugToStderr");

	torture_comment(tctx, "Testing smbc_(set|get)OptionFullTimeNames\n");
	smbc_setOptionFullTimeNames(ctx, true);
	torture_assert_goto(tctx,
			    smbc_getOptionFullTimeNames(ctx),
			    ok,
			    done,
			    "failed to set OptionFullTimeNames");

	torture_comment(tctx, "Testing smbc_(set|get)OptionOpenShareMode\n");
	smbc_setOptionOpenShareMode(ctx, SMBC_SHAREMODE_DENY_ALL);
	torture_assert_int_equal_goto(tctx,
				      smbc_getOptionOpenShareMode(ctx),
				      SMBC_SHAREMODE_DENY_ALL,
				      ok,
				      done,
				      "failed to set OptionOpenShareMode");

	torture_comment(tctx, "Testing smbc_(set|get)OptionUserData\n");
	smbc_setOptionUserData(ctx, (void *)discard_const("torture_user_data"));
	torture_assert_str_equal_goto(tctx,
				      (const char*)smbc_getOptionUserData(ctx),
				      "torture_user_data",
				      ok,
				      done,
				      "failed to set OptionUserData");

	torture_comment(tctx,
			"Testing smbc_(set|get)OptionSmbEncryptionLevel\n");
	smbc_setOptionSmbEncryptionLevel(ctx, SMBC_ENCRYPTLEVEL_REQUEST);
	torture_assert_int_equal_goto(tctx,
				      smbc_getOptionSmbEncryptionLevel(ctx),
				      SMBC_ENCRYPTLEVEL_REQUEST,
				      ok,
				      done,
				      "failed to set OptionSmbEncryptionLevel");

	torture_comment(tctx, "Testing smbc_(set|get)OptionCaseSensitive\n");
	smbc_setOptionCaseSensitive(ctx, false);
	torture_assert_goto(tctx,
			    !smbc_getOptionCaseSensitive(ctx),
			    ok,
			    done,
			    "failed to set OptionCaseSensitive");

	torture_comment(tctx,
			"Testing smbc_(set|get)OptionBrowseMaxLmbCount\n");
	smbc_setOptionBrowseMaxLmbCount(ctx, 2);
	torture_assert_int_equal_goto(tctx,
				      smbc_getOptionBrowseMaxLmbCount(ctx),
				      2,
				      ok,
				      done,
				      "failed to set OptionBrowseMaxLmbCount");

	torture_comment(tctx,
		       "Testing smbc_(set|get)OptionUrlEncodeReaddirEntries\n");
	smbc_setOptionUrlEncodeReaddirEntries(ctx, true);
	torture_assert_goto(tctx,
			    smbc_getOptionUrlEncodeReaddirEntries(ctx),
			    ok,
			    done,
			    "failed to set OptionUrlEncodeReaddirEntries");

	torture_comment(tctx,
			"Testing smbc_(set|get)OptionOneSharePerServer\n");
	smbc_setOptionOneSharePerServer(ctx, true);
	torture_assert_goto(tctx,
			    smbc_getOptionOneSharePerServer(ctx),
			    ok,
			    done,
			    "failed to set OptionOneSharePerServer");

	torture_comment(tctx, "Testing smbc_(set|get)OptionUseKerberos\n");
	smbc_setOptionUseKerberos(ctx, false);
	torture_assert_goto(tctx,
			    !smbc_getOptionUseKerberos(ctx),
			    ok,
			    done,
			    "failed to set OptionUseKerberos");

	torture_comment(tctx,
			"Testing smbc_(set|get)OptionFallbackAfterKerberos\n");
	smbc_setOptionFallbackAfterKerberos(ctx, false);
	torture_assert_goto(tctx,
			    !smbc_getOptionFallbackAfterKerberos(ctx),
			    ok,
			    done,
			    "failed to set OptionFallbackAfterKerberos");

	torture_comment(tctx,
			"Testing smbc_(set|get)OptionNoAutoAnonymousLogin\n");
	smbc_setOptionNoAutoAnonymousLogin(ctx, true);
	torture_assert_goto(tctx,
			    smbc_getOptionNoAutoAnonymousLogin(ctx),
			    ok,
			    done,
			    "failed to set OptionNoAutoAnonymousLogin");

	torture_comment(tctx, "Testing smbc_(set|get)OptionUseCCache\n");
	smbc_setOptionUseCCache(ctx, true);
	torture_assert_goto(tctx,
			    smbc_getOptionUseCCache(ctx),
			    ok,
			    done,
			    "failed to set OptionUseCCache");

done:
	smbc_free_context(ctx, 1);

	return ok;
}

NTSTATUS torture_libsmbclient_init(TALLOC_CTX *ctx)
{
	struct torture_suite *suite;

	suite = torture_suite_create(ctx, "libsmbclient");

	torture_suite_add_simple_test(suite, "version", torture_libsmbclient_version);
	torture_suite_add_simple_test(suite, "initialize", torture_libsmbclient_initialize);
	torture_suite_add_simple_test(suite, "configuration", torture_libsmbclient_configuration);
	torture_suite_add_simple_test(suite, "setConfiguration", torture_libsmbclient_setConfiguration);
	torture_suite_add_simple_test(suite, "options", torture_libsmbclient_options);
	torture_suite_add_simple_test(suite, "opendir", torture_libsmbclient_opendir);
	torture_suite_add_simple_test(suite, "readdirplus",
		torture_libsmbclient_readdirplus);

	suite->description = talloc_strdup(suite, "libsmbclient interface tests");

	torture_register_suite(ctx, suite);

	return NT_STATUS_OK;
}
