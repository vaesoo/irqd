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

static int cfg_if_add(const char *, struct cpuset *, const struct range *);

static struct cpuset *g_cpuset;
static struct range g_range;
%}

/* create a pure, reentrant parser */
%define api.pure
/* %locations */

%union {
	char *str;
	int val;
	struct range *range;
}

%token<val> T_NUM
%token<str> T_ID T_STR;
%token T_CPUSET T_DEVS T_IFACE T_IFACE_AUTO_ASSIGN T_STRATEGY
%token T_INIT_STEER_CPUS
%token ':' ';' '(' ')' '{' '}' ','
%type<range> range

%% /* grammar rules and actions */

input: /* empty */
	| input stmt;

stmt: cmd ';';

cmd: cpuset;

cpuset: T_CPUSET T_STR range {
		assert(g_cpuset == NULL);
		if ((g_cpuset = cpuset_new($2, $3)) == NULL) {
			yyerr_printf("cpuset invalid");
			YYERROR;
		}
	} '{' cpuset_blk '}' {
		int ret;

		if (!g_cpuset->cs_strategy.s_type)
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

	/* FIXME don't allow whitespace here */
range: T_NUM ':' T_NUM {
		g_range.rg_from = $1;
		g_range.rg_to = $3;
		if (!range_valid(&g_range)) {
			/* TODO range invalid */
			YYERROR;
		}

		$$ = &g_range;
	} | T_NUM {
		g_range.rg_from = g_range.rg_to = $1;
		if (!range_valid(&g_range)) {
			/* TODO invalid range error */
			YYERROR;
		}
		$$ = &g_range;
	};

devs: T_DEVS '{' devs_blk '}';
devs_blk: /* empty */ | devs_blk devs_cmds ';';
devs_cmds: iface | iface_auto_assign;
iface: T_IFACE T_STR range {
		if (cfg_if_add($2, g_cpuset, $3) < 0) {
			/* failed to create interface */
			YYERROR;
		}
	} | T_IFACE T_STR {
		if (cfg_if_add($2, g_cpuset, NULL) < 0) {
			/* failed to create interface */
			YYERROR;
		}
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
		assert(g_cpuset != NULL);
		if (cpuset_set_strategy(g_cpuset, $2) < 0) {
			yyerr_printf("%s: unknown strategy", $2);
			YYERROR;
		}
	} opt_strategy_blk;
opt_strategy_blk: /* empty */ | '{' strategy_blk '}';
strategy_blk: /* empty */ | strategy_blk strategy_cmds ';';
strategy_cmds: init_steer_cpus;
init_steer_cpus: T_INIT_STEER_CPUS T_NUM {
		assert(g_cpuset != NULL);
		/* TODO check value */
		g_cpuset->cs_strategy.u.evenly.init_steer_cpus = $2;
	};

%%

/* epilogue */

static int
cfg_if_add(const char *name, struct cpuset *set, const struct range *range)
{
	struct interface *iface;

	assert(set != NULL);

	if ((iface = if_new(name, set)) == NULL)
		goto err;
	if (cpuset_add_device(set, if_to_dev(iface)) < 0)
		goto err;

	if (range && if_assign_fixed_range(iface, range) < 0)
			goto err;

	return if_register(iface);

err:
	if_free(iface);
	return -1;
}

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

