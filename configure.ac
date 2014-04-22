dnl Process this file with autoconf to produce a configure script.

AC_PREREQ([2.59])
AC_INIT([zje], [1.0], [mingshun@gutspot.com])

AC_CANONICAL_SYSTEM
AC_COPYRIGHT([Copyright (C) 2011,2012 mingshun.])
AM_INIT_AUTOMAKE

# Checks for architectures.
AC_MSG_CHECKING([for target architecture])
case $target in
	i?86-*linux**)
		AC_MSG_RESULT([yes])
		;;
	i86_64-*linux**)
		AC_MSG_RESULT([no])
		;;
	arm-*linux**)
		AC_MSG_RESULT([no])
		;;
	*)
		AC_MSG_RESULT([no])
		;;
esac

# Checks for programs.
AC_PROG_CC
AC_PROG_CC_STDC
AC_GNU_SOURCE

# Checks for libraries.
AC_CHECK_LIB([ssl], [SSL_library_init])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h stdlib.h string.h sys/ioctl.h sys/socket.h sys/time.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_UID_T
AC_C_INLINE
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([atexit dup2 ftruncate getpagesize memset mkdir modf socket strerror strtol strtoul asprintf])

AC_CONFIG_FILES([Makefile deps/Makefile src/Makefile])
AC_CONFIG_SUBDIRS([deps/jansson-2.4])
AC_OUTPUT
