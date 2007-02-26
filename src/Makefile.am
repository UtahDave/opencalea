## Makefile.am -- Process this file with automake to produce Makefile.in
AM_CFLAGS = -g -O2 -Wall
bin_PROGRAMS = tap lea_collection 
tap_SOURCES = tap.c tap.h calea.c calea.h
tap_CFLAGS = $(AM_CFLAGS)
tap_LDADD = -lpcap

lea_collection_SOURCES = lea_collection.c lea_collection.h 
lea_collection_CFLAGS = $(AM_CFLAGS)
lea_collection_LDADD = -lpcap
