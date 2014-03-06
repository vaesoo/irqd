AC_INIT([irqd], [0.7.0])
AC_PROG_INSTALL
AM_INIT_AUTOMAKE([-Wall foreign])
AC_PROG_CC
AC_PROG_LEX
AC_PROG_YACC

regular_CPPFLAGS="-D_FORTIFY_SOURCE=2 -D_LARGEFILE_SOURCE=1 -D_LARGE_FILES \
	-D_FILE_OFFSET_BITS=64 -D_REENTRANT";
regular_CFLAGS="-Wall -Waggregate-return \
	-Wmissing-declarations -Wmissing-prototypes -Wredundant-decls \
	-Wshadow -Wstrict-prototypes -Winline -pipe"
AC_SUBST([regular_CPPFLAGS])
AC_SUBST([regular_CFLAGS])

PKG_CHECK_MODULES([libglib], [glib-2.0])
PKG_CHECK_MODULES([libnl], [libnl-route-3.0])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
