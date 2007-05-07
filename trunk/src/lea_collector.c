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
#include "calea.h"
#include "lea_collector.h"

#include <pcap.h>
#include <net/ethernet.h>

char *prog_name = "lea_collector";
int syslog_facility = DEF_SYSLOG_FACILITY;

FILE *cmii_fp = NULL;
FILE *cmc_fp = NULL;
struct pcap_dumper *pd = NULL;

void print_packet( const u_char *packet, u_short  size ) {
    int i = 0;   
    char msg[ MAX_LOG_DEBUG_MSG_LEN ];
    char hexbyte[4];

    debug_5 ( "Packet: size: %d", size );

    msg[0] = '\0';
    for( i=0; i < size; i++ ) {
        sprintf ( hexbyte, "%02x ", packet[i] );
        strncat ( msg, hexbyte, 3 );
        if ( ( strlen ( msg ) + 3 > MAX_LOG_DEBUG_MSG_LEN ) ) {
            debug_5 ( msg );
            msg[0] = '\0';
        }
    }
    debug_5 ( msg );
}

void signal_handler ( int sigval ) {

    if (cmii_fp)
        fclose ( cmii_fp );
    if (pd)
        pcap_dump_close ( pd );

    exit ( 1 );
}

void usage ( void ) {

    printf ( "Usage: lea_collector -t cmii-capture-file " );
    printf ( "[-f cmc-capture-file] " );
    printf ( "[-b bind-addr] " );
    printf ( "[-u user] [-g group] " );
    printf ( " [-m cmc-port] [-n cmii-port] [-x]" );
    printf ( " [-v [...]] [-D debug-file]" );
    printf ( " [-l log-level ] [-L logfile]" );
    printf ( "\n" );


}

int main ( int argc, char *argv[] ) {
  
    int n;
    char buf[10000];
    u_int len;
    char *cmc_capture_file = NULL;
    char *cmii_capture_file = NULL;
    char *bindaddr = NULL;
    struct addrinfo hints, *res, *res0;
    int i=0;
    char *cmc_port = 0;
    char *cmii_port = 0;
    int cooked_format = 0;
    int change_user = 0;
    int change_group = 0;
    struct passwd *pwent;
    struct group *grent;
    char user[32] = DEF_USER;
    char group[32] = DEF_GROUP;
    int log_level_set = 0;
    int debug_level_set = 0;
    char *debug_file = NULL;
    char *log_file = NULL;

    fd_set sock_fds;
    int num_sock_fds;
    int max_fd;

    setdebug( DEF_DEBUG_LEVEL, "syslog", 1 );
    setlog( DEF_LOG_LEVEL, "syslog", 1 );

    /* command line options processing */
    while (( i = getopt ( argc, argv, "t:f:b:hm:n:xu:g:vD:l:L:" )) != -1 ) {

        switch ( i ) {
            case 'f':   // cmc capture file 
                if ( ( cmc_capture_file = strdup ( optarg ) ) == NULL )
                    pdie ( "strdup" );
                debug_5 ( "got opt %c: %s", i, optarg );
                break;
            case 't':   // cmii capture file
                if ( ( cmii_capture_file = strdup ( optarg ) ) == NULL )
                    pdie ( "strdup" );
                debug_5 ( "got opt %c: %s", i, optarg );
                break;
            case 'b':   // address to bind sure
                if ( ( bindaddr = strdup ( optarg ) ) == NULL )
                    pdie ( "strdup" );
                debug_5 ( "got opt %c: %s", i, optarg );
                break;
            case 'u':   // username
                strncpy ( (char *)user, optarg, 31 );
                debug_5 ( "got opt %c: %s", i, optarg );
                change_user = 1;
                break;
            case 'g':   // group name
                strncpy ( &group[0], optarg, 31 );
                debug_5 ( "got opt %c: %s", i, optarg );
                change_group = 1;
                break;
           case 'm':   // cmc port 
                if ( ( cmc_port = strdup ( optarg ) ) == NULL )
                    pdie ( "strdup" );
                debug_5 ( "got opt %c: %s", i, optarg );
                break; 
            case 'n':   // cmii port 
                if ( ( cmii_port = strdup ( optarg ) ) == NULL )
                    pdie ( "strdup" );
                debug_5 ( "got opt %c: %s", i, optarg );
                break; 
            case 'x':   // what is this?
                cooked_format = 1;
                break; 
            case 'v':   // debug ('d' was taken)
                debug_level_set++;
                debug_5 ( "got opt %c, debug level now %d",
                    i, debug_level_set );
                break;
            case 'D':   // debug file
                if ( ( debug_file = strdup ( optarg ) ) == NULL )
                    pdie ( "strdup" );
                debug_5 ( "got opt %c: %s", i, optarg );
                break;
            case 'l':   // log level
                errno = 0;
                log_level_set = (int)strtol(optarg, (char **)NULL, 0);
                if ( log_level_set <= 0 ) {
                    if ( errno )
                        pdie ( "strtol(log_level_set)" );
                    else
                        die ( "invalid log_level_set" );
                }
                debug_5 ( "got opt %c: %d", i, log_level_set );
                break;
            case 'L':   // logfile
                if ( ( log_file = strdup ( optarg ) ) == NULL )
                    pdie ( "strdup" );
                debug_5 ( "got opt %c: %s", i, optarg );
                break;
            case 'h':   // help
                usage();
                exit ( 0 ); 
            default:
                usage ();
                exit ( 1 );
        }
    }

    /* do as much as possible after dropping privs */
    if ( debug_file && strlen ( debug_file ) ) {
        debug_level_set = ( debug_level_set ) ? debug_level_set : DEF_DEBUG_LEVEL;
        debug_3 ( "resetting debug level (%d) and destination (%s)",
            debug_level_set, debug_file );
        setdebug( debug_level_set, debug_file, 1 );
    } else {
        debug_3 ( "resetting debug level (%d)", debug_level_set );
        setdebug( debug_level_set, "syslog", 1 );
    }
    if ( log_file && strlen ( log_file ) ) {
        log_level_set = ( log_level_set ) ? log_level_set : DEF_LOG_LEVEL;
        debug_3 ( "resetting log level (%d) and destination (%s)",
            log_level_set, log_file );
        setlog( log_level_set, log_file, 1 );
    } else {
        debug_3 ( "resetting log level (%d)", log_level_set );
        setlog( log_level_set, "syslog", 1 );
    }

    if ( cmii_capture_file == NULL ) {
        usage();
        die ( "cmii capture file not specified (need -t)." );
    }
    if ( cmc_capture_file == NULL ) {
        usage();
        die ( "cmc capture file not specified (need -f)." );
    }

    /* drop privs if running as root or told to do so */
    if ( ((uid_t)geteuid() == 0) || change_user ) {
        debug_3 ( "changing userid to: %s", user );
        errno = 0;
        if (! (pwent = getpwnam(user)) ) {
            if (errno) {
                pdie ( "getpwnam" );
            } else {
                die ( "User %s not found\n", user );
            }
        }
        if ( setuid(pwent->pw_uid) < 0 )
            pdie ( "setuid" );
    }
    if ( ((uid_t)geteuid() == 0) || change_group ) {
        debug_3 ( "changing group id to: %s", group );
        errno = 0;
        if (! (grent = getgrnam(group)) ) {
            if (errno) {
                pdie ( "getgrnam" );
            } else {
                die ( "Group %s not found\n", group );
            }
        }
        if (setgid(grent->gr_gid) < 0)
            pdie ( "setgid" );
    }

    if ( cmii_port == NULL ) {
        if ( ! ( cmii_port = malloc ( 64 ) ) )
            perror ( "malloc" );
        snprintf ( cmii_port, 64, "%d", LEA_COLLECTOR_CmII_PORT );
        debug_5 ( "using default cmii port (%s)", cmii_port );
    }

    if ( cmc_capture_file == NULL ) {
        log_2 ( "CmC capture file not specified, CmC collection disabled." );
        debug_2 ( "CmC capture file not specified, CmC collection disabled." );
    } else { 
        if ( cmc_port == NULL ) {
            if ( ! ( cmc_port = malloc ( 64 ) ) )
                perror ( "malloc" );
            snprintf ( cmc_port, 64, "%d", LEA_COLLECTOR_CmC_PORT );
            debug_5 ( "using default cmc port (%s)", cmc_port );
        }

        memset ( &hints, 0, sizeof ( hints ) );
        hints.ai_family = PF_INET;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_flags = AI_PASSIVE;

        debug_5 ( "calling getaddrinfo" );
        i = getaddrinfo ( bindaddr, cmc_port, &hints, &res0 );
        if ( i ) {
            die ( "getaddrinfo: %s", gai_strerror( i ) );
        }

        cmc_receiver_socket = -1;
        for (res = res0; res; res = res->ai_next) {
            memset ( (char *)&cmc_receiver_addr, '\0', sizeof(cmc_receiver_addr) );

            cmc_receiver_addr.sin_family = res->ai_family;
            cmc_receiver_addr.sin_port   = ((struct sockaddr_in *)res->ai_addr)->sin_port;
            cmc_receiver_addr.sin_addr.s_addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr;

            debug_5 ( "trying cmc_receiver_addr %s:%d",
                inet_ntoa ( cmc_receiver_addr.sin_addr ), htons ( cmc_receiver_addr.sin_port ) );

            debug_5 ( "creating cmc_receiver_socket" );
            cmc_receiver_socket = socket( res->ai_family, res->ai_socktype, res->ai_protocol );
            if (cmc_receiver_socket < 0) {
                debug_5 ( "socket: %s", strerror ( errno ) );
                strncpy ( buf, "socket", 10000 );
                if ( res->ai_next )
                    debug_5 ( "socket failed, trying next ip addr" );
                continue;
            }

            debug_5 ( "binding cmc_receiver_socket" );
            if ( bind ( cmc_receiver_socket, res->ai_addr, res->ai_addrlen ) < 0 ) {
                strncpy ( buf, "bind", 10000 );
                debug_5 ( "bind: %s", strerror ( errno ) );
                if ( close( cmc_receiver_socket ) == -1 )
                    pdie ( "close" );
                cmc_receiver_socket = -1;
                if ( res->ai_next )
                    debug_5 ( "connect failed, trying next ip addr" );
                continue;
            }

            debug_5 ( "connect succeeded" );
            break;
        }
        if ( cmc_receiver_socket < 0 ) {
            pdie ( buf );
        }

        freeaddrinfo(res0);
    }

    memset ( &hints, 0, sizeof ( hints ) );
    hints.ai_family = PF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;

    debug_5 ( "calling getaddrinfo" );
    i = getaddrinfo ( bindaddr, cmii_port, &hints, &res0 );
    if ( i ) {
        die ( "getaddrinfo: %s", gai_strerror( i ) );
    }

    cmii_receiver_socket = -1;
    for (res = res0; res; res = res->ai_next) {
        memset ( (char *)&cmii_receiver_addr, '\0', sizeof(cmii_receiver_addr) );

        cmii_receiver_addr.sin_family = res->ai_family;
        cmii_receiver_addr.sin_port   = ((struct sockaddr_in *)res->ai_addr)->sin_port;
        cmii_receiver_addr.sin_addr.s_addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr;

        debug_5 ( "trying cmii_receiver_addr %s:%d",
            inet_ntoa ( cmii_receiver_addr.sin_addr ), htons ( cmii_receiver_addr.sin_port ) );

        debug_5 ( "creating cmii_receiver_socket" );
        cmii_receiver_socket = socket( res->ai_family, res->ai_socktype, res->ai_protocol );
        if (cmii_receiver_socket < 0) {
            debug_5 ( "socket: %s", strerror ( errno ) );
            strncpy ( buf, "socket", 10000 );
            if ( res->ai_next )
                debug_5 ( "socket failed, trying next ip addr" );
            continue;
        }

        debug_5 ( "binding cmii_receiver_socket" );
        if ( bind ( cmii_receiver_socket, res->ai_addr, res->ai_addrlen ) < 0 ) {
            strncpy ( buf, "bind", 10000 );
            debug_5 ( "bind: %s", strerror ( errno ) );
            if ( close( cmii_receiver_socket ) == -1 )
                pdie ( "close" );
            cmii_receiver_socket = -1;
            if ( res->ai_next )
                debug_5 ( "connect failed, trying next ip addr" );
            continue;
        }

        debug_5 ( "connect succeeded" );
        break;
    }
    if ( cmii_receiver_socket < 0 ) {
        pdie ( buf );
    }

    freeaddrinfo(res0);

    // debug_3 ( "setting SIGINT signal handler" );
    // signal (SIGINT, signal_handler);

    FD_ZERO( &sock_fds );
    FD_SET( cmii_receiver_socket, &sock_fds );
    FD_SET( cmc_receiver_socket, &sock_fds );
    max_fd = max(cmii_receiver_socket, cmc_receiver_socket);

    debug_5 ( "opening cmii_capture_file" );
    cmii_fp = fopen ( cmii_capture_file , "wb" );

    if (cmii_fp == NULL) {
        pdie ( "CmII fopen" );
    }

    debug_5 ( "opening cmc_capture_file" );
    cmc_fp = fopen ( cmc_capture_file , "wb" );

    if (cmc_fp == NULL) {
        pdie ( "CmC fopen" );
    }

    debug_2 ( "entering receiver select loop" );
    len = sizeof ( struct sockaddr );
    while ( 1 ) {
        FD_SET( cmii_receiver_socket, &sock_fds );
        FD_SET( cmc_receiver_socket, &sock_fds );
        num_sock_fds = select( max_fd+1 , &sock_fds, NULL, NULL, NULL);
        if ( num_sock_fds < 0 ) {
            pdie ( "lea_collector: select " );
        } else if ( num_sock_fds == 0 ) {
            debug_5 ( "lea_collector: select returned with 0 descriptors ready" );
        } else {
            /* read data on sockets */
            if ( FD_ISSET( cmii_receiver_socket, &sock_fds )) {
                debug_5 ( "lea_collector: CmII socket ready" );
                if ((n = recvfrom ( cmii_receiver_socket, buf, 10000, 0, (struct sockaddr*) &cmii_receiver_addr, &len)) == -1) { 
                    pdie ( "lea_collector: cmii recvfrom" );
                } else {
                    debug_5 ( "lea_collector: cmii recvfrom returned %d bytes", n );
                } 
             
                fwrite( buf, n, 1, cmii_fp);
            }

            if ( FD_ISSET( cmc_receiver_socket, &sock_fds )) {
                debug_5 ( "lea_collector: CmC socket ready" );
                if ((n = recvfrom ( cmc_receiver_socket, buf, 10000, 0, (struct sockaddr*) &cmc_receiver_addr, &len)) == -1) { 
                    pdie ( "lea_collector: cmc recvfrom " );
                } else {
                    debug_5 ( "lea_collector: cmc recvfrom returned %d bytes", n );
            	}

				fwrite( buf, n, 1, cmc_fp);
            }
       }
        
    } /* while */

    return 0;
}
