# -*- Makefile -*-

CLEANFILES = cfg_lex.c cfg_grammar.c cfg_grammar.h

BUILT_SOURCES = cfg_grammar.h

AM_YFLAGS = -d
# -d: enable debug
AM_LFLAGS = -o$(LEX_OUTPUT_ROOT).c

AM_CFLAGS  = ${regular_CFLAGS} ${libglib_CFLAGS} ${libnl_CFLAGS} \
             -D_GNU_SOURCE=1

sbin_PROGRAMS = irqd

irqd_SOURCES = irqd.c strategy.c interface.c cpu.c event.c log.c \
	cfg_grammar.y cfg_lex.l
irqd_LDADD   = ${libglib_LIBS} ${libnl_LIBS} -lrt
