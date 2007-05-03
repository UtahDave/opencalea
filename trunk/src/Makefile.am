## Makefile.am -- Process this file with automake to produce Makefile.in
AM_CFLAGS = -g -O2 -Wall -Iasn.1/T1.678/CCDeliveryHeader -Iasn.1/T1.IAS/CmII -Iasn.1/T1.678/VoP
bin_PROGRAMS = tap df_collector lea_collector controller collector

tap_SOURCES = tap.c tap.h common.h calea.c calea.h log_debug.c log_debug.h cc_apdu.c packet_data_header_report.c directsignalreporting.c util.h util.c
tap_CFLAGS = $(AM_CFLAGS) $(GLIB_CFLAGS)
tap_LDADD = -lpcap -Lasn.1/T1.678/CCDeliveryHeader -lCCDeliveryHeader -Lasn.1/T1.IAS/CmII -lCmII -Lasn.1/T1.678/VoP -lVoP $(GLIB_LIBS) 

df_collector_SOURCES = df_collector.c common.h log_debug.c log_debug.h util.h calea.c util.c
df_collector_CFLAGS = $(AM_CFLAGS) $(GLIB_CFLAGS)
df_collector_LDADD = -lpcap -lpthread $(GLIB_LIBS)

lea_collector_SOURCES = lea_collector.c lea_collector.h common.h log_debug.c log_debug.h util.h calea.c util.c
lea_collector_CFLAGS = $(AM_CFLAGS) $(GLIB_CFLAGS)
lea_collector_LDADD = -lpcap $(GLIB_LIBS)

controller_SOURCES = controller.c common.h process_registry.c process_registry.h log_debug.c log_debug.h util.h util.c
controller_CFLAGS = $(AM_CFLAGS) $(GLIB_CFLAGS)
controller_LDADD = -lpthread $(GLIB_LIBS)

collector_SOURCES = collector.c common.h process_registry.c process_registry.h log_debug.c log_debug.h util.h util.c
collector_CFLAGS = $(AM_CFLAGS) $(GLIB_CFLAGS)
collector_LDADD = -lpthread $(GLIB_LIBS)
