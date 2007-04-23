/*
 * Copyright (c) 2007, Jesse Norell <jesse@kci.net>
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

#ifndef _LOG_DEBUG_H
#define _LOG_DEBUG_H

#define MAX_LOG_MSG_LEN 1024
#define MAX_DEBUG_MSG_LEN 1024
#define MAX_LOG_DEBUG_MSG_LEN 1024    // Max of the previous 2
#define ERROR_DEBUG_FUNC debug_1
#define ERROR_LOG_FUNC log_2

extern FILE *debug_file;
extern FILE *log_file;

void setdebug ( int, char *, int );
void setlog ( int, char *, int  );

extern void (*debug_1)( char *, ... );
extern void (*debug_2)( char *, ... );
extern void (*debug_3)( char *, ... );
extern void (*debug_4)( char *, ... );
extern void (*debug_5)( char *, ... );

extern void (*log_1)( char *, ... );
extern void (*log_2)( char *, ... );
extern void (*log_3)( char *, ... );
extern void (*log_4)( char *, ... );
extern void (*log_5)( char *, ... );

void my_debug ( char *, ... );
void my_log ( char *, ... );

void error ( char *, ... );
void die ( char *, ... );
void pdie ( char * );

#endif
