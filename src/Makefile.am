## Makefile.am -- Process this file with automake to produce Makefile.in
AM_CFLAGS = -g -O2 -Wall
bin_PROGRAMS = tap lea_collector controller collector
tap_SOURCES = tap.c tap.h common.h calea.c calea.h log_debug.c log_debug.h
tap_CFLAGS = $(AM_CFLAGS)
tap_LDADD = -lpcap

lea_collector_SOURCES = lea_collector.c lea_collector.h common.h log_debug.c log_debug.h
lea_collector_CFLAGS = $(AM_CFLAGS)
lea_collector_LDADD = -lpcap

controller_SOURCES = controller.c common.h process_registry.c process_registry.h log_debug.c log_debug.h
controller_CFLAGS = $(AM_CFLAGS)
controller_LDADD = -lpthread

collector_SOURCES = collector.c common.h process_registry.c process_registry.h log_debug.c log_debug.h
collector_CFLAGS = $(AM_CFLAGS)
collector_LDADD = -lpthread
