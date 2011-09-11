# -*- Makefile -*-

AM_CFLAGS  = ${regular_CFLAGS} ${libglib_CFLAGS} ${libnl_CFLAGS} \
             -D_GNU_SOURCE=1

sbin_PROGRAMS = irqd

irqd_SOURCES = irqd.c strategy.c interface.c cpu.c event.c log.c
irqd_LDADD   = ${libglib_LIBS} ${libnl_LIBS} -lrt
