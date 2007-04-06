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

#include "common.h"
#include "log_debug.h"

#include <fcntl.h>
#include <sys/stat.h>

extern char *prog_name;
extern int syslog_facility;

FILE *debug_fp = NULL;
FILE *log_fp = NULL;
int debug_fd = (int) NULL;
int log_fd = (int) NULL;

int debug_level = DEF_DEBUG_LEVEL;
int log_level = DEF_LOG_LEVEL;

int debug_to_file = 0;
int log_to_file = 0;

/* we want a high performance "do nothing" */
static void my_nulllog ( char *msg, ... ) { }

void (*debug_1)( char *, ... ) = &my_nulllog;
void (*debug_2)( char *, ... ) = &my_nulllog;
void (*debug_3)( char *, ... ) = &my_nulllog;
void (*debug_4)( char *, ... ) = &my_nulllog;
void (*debug_5)( char *, ... ) = &my_nulllog;

void (*log_1)( char *, ... ) = &my_nulllog;
void (*log_2)( char *, ... ) = &my_nulllog;
void (*log_3)( char *, ... ) = &my_nulllog;
void (*log_4)( char *, ... ) = &my_nulllog;
void (*log_5)( char *, ... ) = &my_nulllog;

void my_debug ( char *format, ... ) {
    va_list ap;
    char msg[MAX_DEBUG_MSG_LEN];
    char *append = NULL;
    char myname[64];
    char *curtime;
    time_t tim;

    va_start( ap, format );
    vsnprintf ( msg, MAX_DEBUG_MSG_LEN, format, ap );
    va_end( ap );

    append = ( msg [ strlen ( msg ) ] != '\n' ) ? "\n" : "\0";

    if ( debug_to_file ) {
        if ( ( tim = time ( NULL ) ) == -1 ) {
            perror ( "time" );
            exit ( -1 );
        }
        curtime = ctime ( &tim );
        curtime[ strlen ( curtime ) - 1 ] = 0;        // remove \n
        if ( fprintf ( debug_fp, "%s  %s%s", curtime, msg, append ) == -1 ) {
            perror ( "fprintf" );
            exit ( -1 );
        }
    } else {
        snprintf ( myname, 64, "%s debug", prog_name );
        openlog ( myname, LOG_PID, syslog_facility );
        syslog ( LOG_DEBUG, "%s", msg );
    }
}

void my_log ( char *format, ... ) {
    va_list ap;
    char msg[MAX_LOG_MSG_LEN];
    char *append = NULL;
    char *curtime;
    time_t tim;

    va_start( ap, format );
    vsnprintf ( msg, MAX_LOG_MSG_LEN, format, ap );
    va_end( ap );

    append = ( msg [ strlen ( msg ) ] != '\n' ) ? "\n" : "\0";

    if ( log_to_file ) {
        if ( ( tim = time ( NULL ) ) == -1 ) {
            perror ( "time" );
            exit ( -1 );
        }
        curtime = ctime ( &tim );
        curtime[ strlen ( curtime ) - 1 ] = 0;        // remove \n
        if ( fprintf ( log_fp, "%s  %s%s", curtime, msg, append ) == -1 ) {
            perror ( "fprintf" );
            exit ( -1 );
        }
    } else {
        openlog (prog_name, LOG_PID, syslog_facility);

        switch ( log_level ) {
            case 1:
                syslog ( LOG_ALERT, "%s", msg );
                break;
            case 2:
                syslog ( LOG_ERR, "%s", msg );
                break;
            case 3:
                syslog ( LOG_WARNING, "%s", msg );
                break;
            case 4:
                syslog ( LOG_NOTICE, "%s", msg );
                break;
            case 5:
                syslog ( LOG_INFO, "%s", msg );
                break;
            default:
                fprintf ( stderr, 
                    "program error, log_level is %d",
                    log_level );
                exit ( -1 );
        }
    }
}

/*
 * level: set debug level
 * debug_to: use 'syslog', 'stdout', 'stderr'
 *           or a filename
 */
void setdebug ( int level, char *debug_to ) {
    
    if ( ( debug_fd && debug_to_file ) 
        && ( debug_fp != stdout )
        && ( debug_fp != stderr )
        ) {
        if ( fclose ( debug_fp ) == EOF ) {
            perror ( "fclose" );
            exit ( -1 );
        }
        debug_to_file = 0;
        debug_fp = NULL;
        debug_fd = (int) NULL;
    }

    if ( ! strcmp ( debug_to, "syslog" ) ) {
        debug_to_file = 0;
        debug_fp = NULL;
        debug_fd = (int) NULL;
    } else if ( ! strcmp ( debug_to, "stdout" ) ) {
        debug_to_file = 1;
        debug_fp = stdout;
        debug_fd = 1;
    } else if ( ! strcmp ( debug_to, "stderr" ) ) {
        debug_to_file = 1;
        debug_fp = stderr;
        debug_fd = 2;
    } else {
        debug_to_file = 1;
        debug_fd = open ( debug_to, O_WRONLY|O_APPEND|O_CREAT, 0640 );
        if ( debug_fd == -1 ) {
            perror ( "open" );
            exit ( -1 );
        }
        if ( ( debug_fp = fdopen ( debug_fd, "w" ) ) == NULL ) {
            perror ( "fdopen" );
            exit ( -1 );
        }
    }

    level = ( level < 0 ) ? 1 : level;
    level = ( level > 5 ) ? 5 : level;

    debug_level = level;

    debug_1 = debug_2 = debug_3 = debug_4 = debug_5 = &my_nulllog;

    switch ( level ) {
        case 5:
            debug_5 = &my_debug;
        case 4:
            debug_4 = &my_debug;
        case 3:
            debug_3 = &my_debug;
        case 2:
            debug_2 = &my_debug;
        case 1:
            debug_1 = &my_debug;
    }
}

/*
 * level: set log level
 * log_to: use 'syslog', 'stdout', 'stderr'
 *         or a filename
 */
void setlog ( int level, char *log_to ) {

    if ( ( log_fd && log_to_file ) 
        && ( log_fp != stdout )
        && ( log_fp != stderr )
        ) {
        if ( fclose ( log_fp ) == EOF ) {
            perror ( "fclose" );
            exit ( -1 );
        }
        log_to_file = 0;
        log_fp = NULL;
        log_fd = (int) NULL;
    }

    if ( ! strcmp ( log_to, "syslog" ) ) {
        log_to_file = 0;
        log_fp = NULL;
        log_fd = (int) NULL;
    } else if ( ! strcmp ( log_to, "stdout" ) ) {
        log_to_file = 1;
        log_fp = stdout;
        log_fd = 1;
    } else if ( ! strcmp ( log_to, "stderr" ) ) {
        log_to_file = 1;
        log_fp = stderr;
        log_fd = 2;
    } else {
        log_to_file = 1;
        log_fd = open ( log_to, O_WRONLY|O_APPEND|O_CREAT, 0640 );
        if ( log_fd == -1 ) {
            perror ( "open" );
            exit ( -1 );
        }
        if ( ( log_fp = fdopen ( log_fd, "w" ) ) == NULL ) {
            perror ( "fdopen" );
            exit ( -1 );
        }
    }

    level = ( level < 0 ) ? 1 : level;
    level = ( level > 5 ) ? 5 : level;

    log_level = level;

    log_1 = log_2 = log_3 = log_4 = log_5 = &my_nulllog;

    switch ( level ) {
        case 5:
            log_5 = &my_log;
        case 4:
            log_4 = &my_log;
        case 3:
            log_3 = &my_log;
        case 2:
            log_2 = &my_log;
        case 1:
            log_1 = &my_log;
    }
}

void error ( char *format, ... ) {
    va_list ap;
    char msg[MAX_LOG_DEBUG_MSG_LEN];
    char *append = NULL;

    va_start( ap, format );
    vsnprintf ( msg, MAX_DEBUG_MSG_LEN, format, ap );
    va_end( ap );

    ERROR_DEBUG_FUNC ( msg );
    ERROR_LOGG_FUNC ( msg );

    append = ( msg [ strlen ( msg ) ] != '\n' ) ? "\n" : "\0";

    extern FILE *debug_fp;
    extern FILE *log_fp;
    if ( ( debug_fp != stdout ) && ( debug_fp != stderr ) 
         && ( log_fp != stdout ) && ( log_fp != stderr ) ) {
        fprintf ( stderr, "%s%s\n", msg, append );
    }
}

/* error and die */
void die ( char *format, ... ) {
    va_list ap;
    char *msg = NULL;
    char *append = NULL;

    if ( ! ( msg = malloc ( MAX_LOG_DEBUG_MSG_LEN ) ) ) {
        perror ( "malloc" );
        exit ( -1 );
    }

    va_start( ap, format );
    vsnprintf ( msg, MAX_DEBUG_MSG_LEN, format, ap );
    va_end( ap );

    ERROR_DEBUG_FUNC ( msg );
    ERROR_LOGG_FUNC ( msg );

    append = ( msg [ strlen ( msg ) ] != '\n' ) ? "\n" : "\0";

    extern FILE *debug_fp;
    extern FILE *log_fp;
    if ( ( debug_fp != stdout ) && ( debug_fp != stderr ) 
         && ( log_fp != stdout ) && ( log_fp != stderr ) ) {
        fprintf ( stderr, "%s%s\n", msg, append );
    }

    exit( -1 );
}

/* mimic perror() and die */
void pdie ( char *msg ) {
    char *mymsg;

    if ( ! ( mymsg = malloc ( MAX_LOG_DEBUG_MSG_LEN ) ) ) {
        perror ( "malloc" );
        exit ( -1 );
    }

    snprintf ( mymsg, MAX_LOG_DEBUG_MSG_LEN, "%s: %s\n",
        msg, strerror ( errno ) );

    die ( mymsg );
    free ( mymsg );
}

