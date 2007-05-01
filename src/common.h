/*
 * Copyright (c) 2007, Merit Network, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Merit Network, Inc. nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY MERIT NETWORK, INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL MERIT NETWORK, INC. BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _CALEA_COMMON_H
#define _CALEA_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <search.h>
#include <syslog.h>
#include <stdarg.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#define __FAVOR_BSD
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <pwd.h>
#include <grp.h>
#include <glib.h>

#include "log_debug.h"
#include "util.h"

/* Compile Time Defaults */

#ifndef DEF_OPENCALEA_CONF
#define DEF_OPENCALEA_CONF "/etc/opencalea/opencalea.conf"
#endif

#ifndef DEF_SYSLOG_FACILITY
#define DEF_SYSLOG_FACILITY LOG_USER
#endif

#ifndef DEF_DEBUG_LEVEL
#define DEF_DEBUG_LEVEL 5
#endif

#ifndef DEF_LOG_LEVEL
#define DEF_LOG_LEVEL 1
#endif


#ifndef Controller_PORT
#define Controller_PORT 41800
#endif

#ifndef Collector_PORT
#define Collector_PORT 41805	/* deprecated - collector will be gone soon */
#endif

#ifndef CmII_PORT
#define CmII_PORT 41810
#endif

#ifndef CmC_PORT
#define CmC_PORT 41815
#endif

#ifndef DF_CONTROL_PORT
#define DF_CONTROL_PORT 41816
#endif

#ifndef LEA_COLLECTOR_CmII_PORT
#define LEA_COLLECTOR_CmII_PORT 41817
#endif

#ifndef LEA_COLLECTOR_CmC_PORT
#define LEA_COLLECTOR_CmC_PORT 41818
#endif

#define MAX_CONTENT_ID_LENGTH 128
#define MAX_CASE_ID_LENGTH 128
#define MAX_IAP_SYSTEM_ID_LENGTH 128
#define MAX_SUBJECT_ID_LENGTH 128
#define MAX_SESSION_ID_LENGTH 128
#define TS_LENGTH 23  // time in ascii "YYYY-MM-DDThh:mm:ss.sss"

#define DEF_USER "calea"
#define DEF_GROUP "calea"
#define DEF_TAP_USER DEF_USER
#define DEF_TAP_GROUP DEF_GROUP

/* temporary */
#define TAP "./tap"

/* valid command codes */
#define TAP_START              1
#define TAP_STOP               2
#define SHOW_PROCESS_REGISTRY  3
#define CLOSE_SESSION          4
#define CONNECT                5
#define PING                   6
#define NOP                    7

/* valid repsonse codes */
#define ACK                   0
#define NACK                  1 
#define QUIT                  2 

#define MAX_MSGSIZE 2048       /* max size of control message/response */

#define min(a,b)        ((a) < (b) ? (a) : (b))
#define max(a,b)        ((a) > (b) ? (a) : (b))


#endif
