%{
/* prologue */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>

#include "irqd.h"
#include "cpu.h"
#include "interface.h"

/* #define YYERROR_VERBOSE	1 */

void yyerror(char *);
void yyerr_printf(const char *, ...);
int yyget_lineno(void);

static struct cpuset *g_cpuset;
%}

/* create a pure, reentrant parser */
%define api.pure
/* %locations */

%union {
	char *str;
	int val;
}

%token<val> T_NUM
%token<str> T_ID T_STR;
%token T_CPUSET T_DEVS T_IFACE T_IFACE_AUTO_ASSIGN T_STRATEGY
%token ';' '(' ')' '{' '}' ','

%% /* grammar rules and actions */

input: /* empty */
	| input stmt;

stmt: cmd ';';

cmd: cpuset;

cpuset: T_CPUSET T_STR T_NUM T_NUM {
		assert(g_cpuset == NULL);
		if ((g_cpuset = cpuset_new($2, $3, $4)) == NULL) {
			yyerr_printf("cpuset invalid");
			YYERROR;
		}
	} '{' cpuset_blk '}' {
		int ret;

		if (!g_cpuset->cs_strategy)
			cpuset_set_strategy(g_cpuset, "evenly");
		if ((ret = cpuset_list_add(g_cpuset)) < 0) {
			yyerr_printf("%s", strerror(-ret));
			cpuset_free(g_cpuset);
			YYERROR;
		}
		g_cpuset = NULL;
	};
cpuset_blk: /* empty */ | cpuset_blk cpuset_cmds ';';
cpuset_cmds: devs | strategy;

devs: T_DEVS '{' devs_blk '}';
devs_blk: /* empty */ | devs_blk devs_cmds ';';
devs_cmds: iface | iface_auto_assign;
iface: T_IFACE T_STR {
		struct interface *iface = if_new($2, g_cpuset);
		int ret;

		assert(g_cpuset != NULL);
		if ((ret = cpuset_add_device(g_cpuset, if_to_dev(iface))) < 0) {
			yyerr_printf("%s: %s", $2, strerror(-ret));
			if_free(iface);
			YYERROR;
		}

		if_register(iface);
	};
iface_auto_assign: T_IFACE_AUTO_ASSIGN {
		assert(g_cpuset != NULL);
		if (cpuset_set_auto_assign(g_cpuset) < 0) {
			yyerr_printf("%s: only one cpuset can have 'auto' status",
				g_cpuset->cs_name);
			YYERROR;
		}
	};
strategy: T_STRATEGY T_STR {
		g_assert(g_cpuset != NULL);
		if (cpuset_set_strategy(g_cpuset, $2) < 0) {
			yyerr_printf("%s: unknown strategy", $2);
			YYERROR;
		}
	};

%%

/* epilogue */

void
yyerror(char *msg)
{
	fprintf(stderr, "line %d: %s\n", yyget_lineno(), msg);
}

void
yyerr_printf(const char *fmt, ...)
{
	va_list ap;

	fprintf(stderr, "line %d: ", yyget_lineno());
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
}

