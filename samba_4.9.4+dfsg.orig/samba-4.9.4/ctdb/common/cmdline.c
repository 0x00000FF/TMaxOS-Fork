/*
   Command line processing

   Copyright (C) Amitay Isaacs  2018

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#include "replace.h"

#include <popt.h>
#include <talloc.h>
#include <tevent.h>

#include "lib/util/debug.h"

#include "common/cmdline.h"

#define CMDLINE_MAX_LEN		80

struct cmdline_context {
	const char *prog;
	struct poptOption *options;
	struct cmdline_command *commands;
	int max_len;
	poptContext pc;
	int argc, arg0;
	const char **argv;
	struct cmdline_command *match_cmd;
};

static bool cmdline_show_help = false;

static void cmdline_popt_help(poptContext pc,
			      enum poptCallbackReason reason,
			      struct poptOption *key,
			      const char *arg,
			      void *data)
{
	if (key->shortName == 'h') {
		cmdline_show_help = true;
	}
}

struct poptOption cmdline_help_options[] = {
	{ NULL, '\0', POPT_ARG_CALLBACK, cmdline_popt_help, 0, NULL, NULL },
	{ "help", 'h', 0, NULL, 'h', "Show this help message", NULL },
	POPT_TABLEEND
};

#define CMDLINE_HELP_OPTIONS \
	{ NULL, '\0', POPT_ARG_INCLUDE_TABLE, cmdline_help_options, \
	  0, "Help Options:", NULL }

static bool cmdline_option_check(struct poptOption *option)
{
	if (option->longName == NULL) {
		D_ERR("Option has no long name\n");
		return false;
	}

	if (option->argInfo != POPT_ARG_STRING &&
	    option->argInfo != POPT_ARG_INT &&
	    option->argInfo != POPT_ARG_LONG &&
	    option->argInfo != POPT_ARG_VAL &&
	    option->argInfo != POPT_ARG_FLOAT &&
	    option->argInfo != POPT_ARG_DOUBLE) {
		D_ERR("Option '%s' has unsupported type\n", option->longName);
		return false;
	}

	if (option->arg == NULL) {
		D_ERR("Option '%s' has invalid arg\n", option->longName);
		return false;
	}

	if (option->descrip == NULL) {
		D_ERR("Option '%s' has no help msg\n", option->longName);
		return false;
	}

	return true;
}

static bool cmdline_options_check(struct poptOption *options)
{
	int i;
	bool ok;

	if (options == NULL) {
		return true;
	}

	i = 0;
	while (options[i].longName != NULL || options[i].shortName != '\0') {
		ok = cmdline_option_check(&options[i]);
		if (!ok) {
			return false;
		}
		i++;
	}

	return true;
}

static int cmdline_options_define(TALLOC_CTX *mem_ctx,
				  struct poptOption *user_options,
				  struct poptOption **result)
{
	struct poptOption *options;
	int count, i;

	count = (user_options == NULL ? 2 : 3);

	options = talloc_array(mem_ctx, struct poptOption, count);
	if (options == NULL) {
		return ENOMEM;
	}

	i = 0;
	options[i++] = (struct poptOption) CMDLINE_HELP_OPTIONS;
	if (user_options != NULL) {
		options[i++] = (struct poptOption) {
			.argInfo = POPT_ARG_INCLUDE_TABLE,
			.arg = user_options,
			.descrip = "Options:",
		};
	}
	options[i++] = (struct poptOption) POPT_TABLEEND;

	*result = options;
	return 0;
}

static bool cmdline_command_check(struct cmdline_command *cmd, int *max_len)
{
	size_t len;

	if (cmd->name == NULL) {
		return false;
	}

	if (cmd->fn == NULL) {
		D_ERR("Command '%s' has no implementation function\n",
		      cmd->name);
		return false;
	}

	if (cmd->msg_help == NULL) {
		D_ERR("Command '%s' has no help msg\n", cmd->name);
		return false;
	}

	len = strlen(cmd->name);
	if (cmd->msg_args != NULL) {
		len += strlen(cmd->msg_args);
	}
	if (len > CMDLINE_MAX_LEN) {
		D_ERR("Command '%s' is too long (%zu)\n", cmd->name, len);
		return false;
	}

	if (len > *max_len) {
		*max_len = (int)len;
	}

	len = strlen(cmd->msg_help);
	if (len > CMDLINE_MAX_LEN) {
		D_ERR("Command '%s' help too long (%zu)\n", cmd->name, len);
		return false;
	}

	return true;
}

static bool cmdline_commands_check(struct cmdline_command *commands,
				   int *max_len)
{
	int i;
	bool ok;

	if (commands == NULL) {
		return false;
	}

	for (i=0; commands[i].name != NULL; i++) {
		ok = cmdline_command_check(&commands[i], max_len);
		if (!ok) {
			return false;
		}
	}

	return true;
}

static int cmdline_context_destructor(struct cmdline_context *cmdline);

int cmdline_init(TALLOC_CTX *mem_ctx,
		 const char *prog,
		 struct poptOption *options,
		 struct cmdline_command *commands,
		 struct cmdline_context **result)
{
	struct cmdline_context *cmdline;
	int ret, max_len = 0;
	bool ok;

	if (prog == NULL) {
		return EINVAL;
	}

	ok = cmdline_options_check(options);
	if (!ok) {
		return EINVAL;
	}

	ok = cmdline_commands_check(commands, &max_len);
	if (!ok) {
		return EINVAL;
	}

	cmdline = talloc_zero(mem_ctx, struct  cmdline_context);
	if (cmdline == NULL) {
		return ENOMEM;
	}

	cmdline->prog = talloc_strdup(cmdline, prog);
	if (cmdline->prog == NULL) {
		talloc_free(cmdline);
		return ENOMEM;
	}

	ret = cmdline_options_define(cmdline, options, &cmdline->options);
	if (ret != 0) {
		talloc_free(cmdline);
		return ret;
	}
	cmdline->commands = commands;
	cmdline->max_len = max_len;

	cmdline->argc = 1;
	cmdline->argv = talloc_array(cmdline, const char *, 2);
	if (cmdline->argv == NULL) {
		talloc_free(cmdline);
		return ENOMEM;
	}
	cmdline->argv[0] = cmdline->prog;
	cmdline->argv[1] = NULL;

	/* Dummy popt context for generating help */
	cmdline->pc = poptGetContext(cmdline->prog,
				     cmdline->argc,
				     cmdline->argv,
				     cmdline->options,
				     0);
	if (cmdline->pc == NULL) {
		talloc_free(cmdline);
		return ENOMEM;
	}

	talloc_set_destructor(cmdline, cmdline_context_destructor);

	*result = cmdline;
	return 0;
}

static int cmdline_context_destructor(struct cmdline_context *cmdline)
{
	if (cmdline->pc != NULL) {
		poptFreeContext(cmdline->pc);
	}

	return 0;
}

static int cmdline_parse_options(struct cmdline_context *cmdline,
				 int argc,
				 const char **argv)
{
	int opt;

	if (cmdline->pc != NULL) {
		poptFreeContext(cmdline->pc);
	}

	cmdline->pc = poptGetContext(cmdline->prog,
				     argc,
				     argv,
				     cmdline->options,
				     0);
	if (cmdline->pc == NULL) {
		return ENOMEM;
	}

	while ((opt = poptGetNextOpt(cmdline->pc)) != -1) {
		D_ERR("Invalid option %s: %s\n",
		      poptBadOption(cmdline->pc, 0),
		      poptStrerror(opt));
		return EINVAL;
	}

	/* Set up remaining arguments for commands */
	cmdline->argc = 0;
	cmdline->argv = poptGetArgs(cmdline->pc);
	if (cmdline->argv != NULL) {
		while (cmdline->argv[cmdline->argc] != NULL) {
			cmdline->argc++;
		}
	}

	return 0;
}

static int cmdline_match(struct cmdline_context *cmdline)
{
	int i;

	if (cmdline->argc == 0 || cmdline->argv == NULL) {
		cmdline->match_cmd = NULL;
		return EINVAL;
	}

	for (i=0; cmdline->commands[i].name != NULL; i++) {
		struct cmdline_command *cmd;
		char name[CMDLINE_MAX_LEN+1];
		size_t len;
		char *t, *str;
		int n = 0;
		bool match = false;

		cmd = &cmdline->commands[i];
		len = strlcpy(name, cmd->name, sizeof(name));
		if (len >= sizeof(name)) {
			D_ERR("Skipping long command '%s'\n", cmd->name);
			continue;
		}

		str = name;
		while ((t = strtok(str, " ")) != NULL) {
			if (n >= cmdline->argc) {
				match = false;
				break;
			}
			if (cmdline->argv[n] == NULL) {
				match = false;
				break;
			}
			if (strcmp(cmdline->argv[n], t) == 0) {
				match = true;
				cmdline->arg0 = n+1;
			} else {
				match = false;
				break;
			}

			n += 1;
			str = NULL;
		}

		if (match) {
			cmdline->match_cmd = cmd;
			return 0;
		}
	}

	cmdline->match_cmd = NULL;
	return ENOENT;
}

int cmdline_parse(struct cmdline_context *cmdline,
		  int argc,
		  const char **argv,
		  bool parse_options)
{
	int ret;

	if (argc < 2) {
		return EINVAL;
	}

	cmdline_show_help = false;

	if (parse_options) {
		ret = cmdline_parse_options(cmdline, argc, argv);
		if (ret != 0) {
			return ret;
		}
	} else {
		cmdline->argc = argc;
		cmdline->argv = argv;
	}

	ret = cmdline_match(cmdline);
	if (!cmdline_show_help && ret != 0) {
		return ret;
	}

	return 0;
}

static void cmdline_usage_command(struct cmdline_context *cmdline,
				  struct cmdline_command *cmd,
				  bool print_all)
{
	int len;

	len = (int)strlen(cmd->name);

	printf("  %s ", cmd->name);
	if (print_all) {
		printf("%-*s",
		       cmdline->max_len-len,
		       cmd->msg_args == NULL ? "" : cmd->msg_args);
	} else {
		printf("%s", cmd->msg_args == NULL ? "" : cmd->msg_args);
	}
	printf("     %s\n", cmd->msg_help);
}

static void cmdline_usage_full(struct cmdline_context *cmdline)
{
	int i;

	poptSetOtherOptionHelp(cmdline->pc, "[<options>] <command> [<args>]");
	poptPrintHelp(cmdline->pc, stdout, 0);

	printf("\nCommands:\n");
	for (i=0; cmdline->commands[i].name != NULL; i++) {
		cmdline_usage_command(cmdline, &cmdline->commands[i], true);

	}
}

void cmdline_usage(struct cmdline_context *cmdline, const char *cmd_name)
{
	struct cmdline_command *cmd = NULL;
	int i;

	if (cmd_name == NULL) {
		cmdline_usage_full(cmdline);
		return;
	}

	for (i=0; cmdline->commands[i].name != NULL; i++) {
		if (strcmp(cmdline->commands[i].name, cmd_name) == 0) {
			cmd = &cmdline->commands[i];
			break;
		}
	}

	if (cmd == NULL) {
		cmdline_usage_full(cmdline);
		return;
	}

	poptSetOtherOptionHelp(cmdline->pc, "<command> [<args>]");
	poptPrintUsage(cmdline->pc, stdout, 0);

	printf("\n");
	cmdline_usage_command(cmdline, cmd, false);
}

int cmdline_run(struct cmdline_context *cmdline,
		void *private_data,
		int *result)
{
	struct cmdline_command *cmd = cmdline->match_cmd;
	TALLOC_CTX *tmp_ctx;
	int ret;

	if (cmdline_show_help) {
		const char *name = NULL;

		if (cmd != NULL) {
			name = cmdline->match_cmd->name;
		}

		cmdline_usage(cmdline, name);

		if (result != NULL) {
			*result = 0;
		}
		return EAGAIN;
	}

	if (cmd == NULL) {
		return ENOENT;
	}

	tmp_ctx = talloc_new(cmdline);
	if (tmp_ctx == NULL) {
		return ENOMEM;
	}

	ret = cmd->fn(tmp_ctx,
		      cmdline->argc - cmdline->arg0,
		      &cmdline->argv[cmdline->arg0],
		      private_data);

	talloc_free(tmp_ctx);

	if (result != NULL) {
		*result = ret;
	}
	return 0;
}
