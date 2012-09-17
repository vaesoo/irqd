  /* definitions */

%{
#include "cfg_grammar.h"

/* #define T(msg)		puts(msg) */
#define T(msg)

#define STR_LEN			4096
%}

%option noyywrap yylineno
%option bison-bridge
/* %option bison-locations */

%x STRING
%x COMMENT

DIGIT	[0-9]
ID		[a-zA-Z][a-zA-Z0-9-]+

	char str_buf[STR_LEN], *pch;

%%
  /* rule section */

[ \t]+		/* empty */
\n			/* empty */
\/\/.*\n	/* single line comment */
{DIGIT}+	yylval->val = atoi(yytext);  T("NUM");  return T_NUM;
cpuset		T("CPUSET");  return T_CPUSET;
devices		T("DEVS");  return T_DEVS;
interface	T("IFACE");  return T_IFACE;
interface-auto-assign	return T_IFACE_AUTO_ASSIGN;
strategy	T("STRATEGY");  return T_STRATEGY;
{ID}		yylval->str = strdup(yytext);  T("ID");  return T_ID;
\"			pch = str_buf;  BEGIN(STRING);
"/*"		BEGIN(COMMENT);
\/			T("SLASH");  return '/';
=			T("EQ");  return '=';
,			T("COMMA");  return ',';
;			T("SEM");  return ';';
\{			T("{");  return '{';
\}			T("}");  return '}';
<STRING>\"	{
			BEGIN(0);
			*pch = '\0';
			yylval->str = strdup(str_buf);
			T("STR");
			return T_STR;
	}
<STRING>[\r\n]+	/* skip */
<STRING>.	{
			if (pch - str_buf + 1 >= STR_LEN)
				YY_FATAL_ERROR("string too long");
			*pch++ = yytext[0];
	}
<COMMENT>{
"*\/"	BEGIN(0);
[^*\n]+
}
.			/* ignore everything else */

%%

