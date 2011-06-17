# Makefile
#
# Holger Eitzenberger <heitzenberger@astaro.com>, 2011.

DESTDIR ?=
PREFIX ?= /usr

GLIB_CFLAGS := $(shell pkg-config --cflags glib-2.0)
GLIB_LDLIBS := $(shell pkg-config --libs glib-2.0)

CC = gcc
CFLAGS = $(OPTFLAGS) -D_GNU_SOURCE $(GLIB_CFLAGS)
LDLIBS = $(OPTFLAGS) $(GLIB_LDLIBS) -lrt -lnl


.PHONY: clean distclean all install

all: irqd

irqd: irqd.o strategy.o interface.o cpu.o event.o log.o

install:
	install -m 0755 -D irqd $(DESTDIR)$(PREFIX)/sbin/irqd

clean:
	$(RM) *.o

distclean: clean
	$(RM) irqd

TAGS: *.[ch]
	etags *.[ch]
