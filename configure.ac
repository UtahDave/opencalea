dnl Process this file with autoconf to produce a configure script.
 	
AC_PREREQ(2.59)
	
AC_INIT([open_calea], [0.5], [mkarir@merit.edu])
AC_CONFIG_SRCDIR(src/tap.c)
AM_INIT_AUTOMAKE([1.9 foreign])

AC_PROG_CC
	
# check for standard header files
AC_HEADER_STDC
AC_CHECK_HEADERS(stdio.h math.h time.h netdb.h netinet/in.h arpa/inet.h)

# check for glib
#PKG_CHECK_MODULES(GLIB, glib-2.0 >= 2.6, AC_MSG_RESULT([found]), AC_MSG_ERROR([g lib-2.0 >= 2.6 not found]))
#AC_SUBST(GLIB_CFLAGS)
#AC_SUBST(GLIB_LIBS)

# check for libpcap
AC_CHECK_LIB(pcap, bpf_validate, PCAP_LIBS="-lpcap", AC_MSG_ERROR([libpcap not f ound]))
AC_SUBST(PCAP_LIBS)

# check for math library
AC_CHECK_LIB(m, pow, MATH_LIBS="-lm", AC_MSG_ERROR([libm not found]))
AC_SUBST(MATH_LIBS)

AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT

