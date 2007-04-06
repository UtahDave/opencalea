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
    printf ( "[-u user] [-g group] " );
    printf ( " [-m cmc-port] [-n cmii-port] [-x cooked-format]" );
    printf ( " [-v [...]] [-D debug-file]" );
    printf ( " [-l log-level ] [-L logfile]" );
    printf ( "\n" );


}

int main ( int argc, char *argv[] ) {
  
    int n;
    char buf[10000];
    u_int len;
    struct pcap *pt;
    struct pcap_pkthdr h;
    CmC *cmcpkt;
    CmII *cmiipkt;
    struct tm mytm;
    time_t usec;
    char ts[TS_LENGTH+1];
    char contentID[MAX_CONTENT_ID_LENGTH+1];
    char caseID[MAX_CASE_ID_LENGTH+1];
    char IAPSystemID[MAX_IAP_SYSTEM_ID_LENGTH+1];
    char *capture_file = NULL;
    char *cmii_capture_file = NULL;
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

    setdebug( DEF_DEBUG_LEVEL, "syslog" );
    setlog( DEF_LOG_LEVEL, "syslog" );

    /* command line options processing */
    while (( i = getopt ( argc, argv, "t:f:hm:n:xu:g:vD:l:L:" )) != -1 ) {

        switch ( i ) {
            case 'f':   // pcap capture file 
                if ( ( capture_file = strdup ( optarg ) ) == NULL )
                    pdie ( "strdup" );
                debug_5 ( "got opt %c: %s", i, optarg );
                break;
            case 't':   // cmii capture file
                if ( ( cmii_capture_file = strdup ( optarg ) ) == NULL )
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
            case 'x':   // cmii port 
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
                exit (-1); 
            default:
                usage ();
                exit ( 1 );
        }
    }

    if ( debug_file && strlen ( debug_file ) ) {
        debug_level_set = ( debug_level_set ) ? debug_level_set : DEF_DEBUG_LEVEL;
        debug_5 ( "resetting debug level (%d) and destination (%s)",
            debug_level_set, debug_file );
        setdebug( debug_level_set, debug_file );
    } else {
        debug_5 ( "resetting debug level (%d)", debug_level_set );
        setdebug( debug_level_set, "syslog" );
    }
    if ( log_file && strlen ( log_file ) ) {
        log_level_set = ( log_level_set ) ? log_level_set : DEF_LOG_LEVEL;
        debug_5 ( "resetting log level (%d) and destination (%s)",
            log_level_set, log_file );
        setlog( log_level_set, log_file );
    } else {
        debug_5 ( "resetting log level (%d)", log_level_set );
        setlog( log_level_set, "syslog" );
    }

    if ( cmii_capture_file == NULL ) {
        error ( "cmii capture file not specified (need -f)." );
        usage();
        exit(-1);
    }
    if ( capture_file == NULL ) {
        log_2 ( "CmC capture file not specified, CmC collection disabled." );
        debug_2 ( "CmC capture file not specified, CmC collection disabled." );
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
        snprintf ( cmii_port, 64, "%d", CmII_PORT );
        debug_5 ( "using default cmii port (%s)", cmii_port );
    }

    if ( capture_file != NULL ) {
        if ( cmc_port == NULL ) {
            if ( ! ( cmc_port = malloc ( 64 ) ) )
                perror ( "malloc" );
            snprintf ( cmc_port, 64, "%d", CmC_PORT );
            debug_5 ( "using default cmc port (%s)", cmc_port );
        }
/*
        debug_5 ( "creating cmc_receiver_socket" );
        if ( ( cmc_receiver_socket = socket ( PF_INET, SOCK_DGRAM, 0 ) ) == -1 )
            pdie ( "socket" );

        memset ( (char *)&cmc_receiver_addr, '\0', sizeof(cmc_receiver_addr) );

        cmc_receiver_addr.sin_family = AF_INET;
        cmc_receiver_addr.sin_port = htons ( cmc_port );
        cmc_receiver_addr.sin_addr.s_addr = INADDR_ANY;

        if ( bind ( cmc_receiver_socket, 
                    (struct sockaddr *) &cmc_receiver_addr, 
                    sizeof ( struct sockaddr)) == -1 ) {
            perror ( "bind" );
            exit ( 1 );
        }
*/


        memset ( &hints, 0, sizeof ( hints ) );
        hints.ai_family = PF_INET;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_flags = AI_PASSIVE;

        debug_5 ( "calling getaddrinfo" );
        i = getaddrinfo ( NULL, cmc_port, &hints, &res0 );
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

/*
    cmii_receiver_socket = socket ( PF_INET, SOCK_DGRAM, 0 );
    if ( cmii_receiver_socket == -1 ) {
        perror ( "socket" );
        exit ( 1 );
    }

    memset ( (char *)&cmii_receiver_addr, '\0', sizeof(cmii_receiver_addr) );

    cmii_receiver_addr.sin_family = AF_INET;
    cmii_receiver_addr.sin_port = htons ( cmii_port );
    cmii_receiver_addr.sin_addr.s_addr = INADDR_ANY;

    if ( bind ( cmii_receiver_socket, (struct sockaddr *) &cmii_receiver_addr, 
           sizeof ( struct sockaddr)) == -1 ) {
        perror ( "bind" );
        exit ( 1 );
    }
*/
    memset ( &hints, 0, sizeof ( hints ) );
    hints.ai_family = PF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;

    debug_5 ( "calling getaddrinfo" );
    i = getaddrinfo ( NULL, cmii_port, &hints, &res0 );
    if ( i ) {
        die ( "getaddrinfo: %s", gai_strerror( i ) );
    }

    cmii_receiver_socket = -1;
    for (res = res0; res; res = res->ai_next) {
        memset ( (char *)&cmii_receiver_addr, '\0', sizeof(cmii_receiver_addr) );

        cmii_receiver_addr.sin_family = res->ai_family;
        cmii_receiver_addr.sin_port   = ((struct sockaddr_in *)res->ai_addr)->sin_port;
        cmii_receiver_addr.sin_addr.s_addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr;

        if ( capture_file != NULL ) {
            cmii_receiver_addr.sin_family = cmc_receiver_addr.sin_family;
            cmii_receiver_addr.sin_addr.s_addr = cmc_receiver_addr.sin_addr.s_addr;
            debug_5 ( "using cmii_receiver_addr %s:%d",
                inet_ntoa ( cmii_receiver_addr.sin_addr ), htons ( cmii_receiver_addr.sin_port ) );
        } else {
            debug_5 ( "trying cmii_receiver_addr %s:%d",
                inet_ntoa ( cmii_receiver_addr.sin_addr ), htons ( cmii_receiver_addr.sin_port ) );
        }

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

    debug_3 ( "setting SIGINT signal handler" );
    signal (SIGINT, signal_handler);

    fd_set sock_fds;
    int num_sock_fds;

    FD_ZERO( &sock_fds );
    FD_SET( cmii_receiver_socket, &sock_fds );
    debug_5 ( "opening cmii_capture_file" );
    cmii_fp = fopen ( cmii_capture_file , "w" );

    if (cmii_fp == NULL) {
        pdie ( "fopen" );
    }

    if ( capture_file != NULL ) {
        FD_SET( cmc_receiver_socket, &sock_fds );
        if ( cooked_format == 1 ) {
            debug_5 ( "calling pcap_open_dead" );
            pt =  pcap_open_dead ( DLT_LINUX_SLL,  10000 );
            debug_5 ( "calling pcap_set_datalink" );
            if ( pcap_set_datalink(pt, DLT_EN10MB) == -1 )
                die ( "pcap_set_datalink failure" );
        } else {
            debug_5 ( "calling pcap_open_dead" );
            pt =  pcap_open_dead ( DLT_EN10MB,  1024 );
        }

        debug_5 ( "calling pcap_dump_open" );
        pd =  pcap_dump_open( pt, capture_file );
        if (pd == NULL)
            pdie ( "pcap_dump_open" );
    }

    struct in_addr myaddr, myaddr2;

    debug_2 ( "entering receiver select loop" );
    len = sizeof ( struct sockaddr );
    while ( 1 ) {
        num_sock_fds = select( FD_SETSIZE, &sock_fds, (fd_set *) NULL, 
		  (fd_set *) NULL, NULL );
        if ( num_sock_fds < 0 ) {
            pdie ( "select " );
        } else if ( num_sock_fds == 0 ) {
            debug_5 ( "select returned with 0 descriptors ready" );
        } else {
            /* read data on sockets */
            if ( FD_ISSET( cmii_receiver_socket, &sock_fds )) {
                memset ( buf, '\0', 10000 );
                if ((n = recvfrom ( cmii_receiver_socket, buf, 10000, 0, 
                    (struct sockaddr*) &cmii_receiver_addr, &len)) == -1) {
                    pdie ( "recvfrom" );;
                } else {
                    debug_5 ( "cmii recvfrom returned %d bytes", n );
                } 
                
                cmiipkt = (CmII*) buf;
                CmIIh *cmiih;
                cmiih = (CmIIh*) &(cmiipkt->cmiih);
                myaddr.s_addr = ntohl(cmiipkt->pkt_header.srcIP);
                myaddr2.s_addr = ntohl(cmiipkt->pkt_header.dstIP);
                snprintf(ts, TS_LENGTH+1, "%s", cmiipkt->cmiih.ts);
                snprintf(contentID, MAX_CONTENT_ID_LENGTH+1, "%s", cmiipkt->cmiih.contentID);
                snprintf(caseID, MAX_CASE_ID_LENGTH+1, "%s", cmiipkt->cmiih.caseID);
                snprintf(IAPSystemID, MAX_IAP_SYSTEM_ID_LENGTH+1, "%s", cmiipkt->cmiih.IAPSystemID);

                debug_5 ( "writing to cmii_fp: %s, %s, %s, %s, %s, %s, %d, %d",
                        contentID, caseID, IAPSystemID, ts, inet_ntoa(myaddr), inet_ntoa(myaddr2),
                        ntohs(cmiipkt->pkt_header.srcPort), ntohs(cmiipkt->pkt_header.dstPort) );
                if ( fprintf ( cmii_fp, "%s, %s, %s, %s, %s, %s, %d, %d\n",
                        contentID, caseID, IAPSystemID, ts, inet_ntoa(myaddr), inet_ntoa(myaddr2),
                        ntohs(cmiipkt->pkt_header.srcPort), ntohs(cmiipkt->pkt_header.dstPort)
                             ) < 0 ) {
                    pdie ("fprintf");
                }
            }

            if ( capture_file != NULL ) {
                if ( FD_ISSET( cmc_receiver_socket, &sock_fds )) {
                    memset ( buf, '\0', 10000 );
                    if ((n = recvfrom ( cmc_receiver_socket, buf, 10000, 0, 
                        (struct sockaddr*) &cmc_receiver_addr, &len)) == -1) {
                        pdie ( "recvfrom" );;
                    } else {
                        debug_5 ( "cmc  recvfrom returned %d bytes", n );
                    } 
                    cmcpkt = (CmC*) buf;
                    sscanf ( cmcpkt->cmch.ts, 
                            "%d-%d-%dT%d:%d:%d.%ld", &(mytm.tm_year), 
                             &(mytm.tm_mon), &(mytm.tm_mday), &(mytm.tm_hour), 
                             &(mytm.tm_min), &(mytm.tm_sec), (long int *)&usec); 
                    mytm.tm_year -= 1900;
                    mytm.tm_mon -= 1;
                    usec = usec * 1000;
                    h.ts.tv_sec = timegm ( &mytm );
                    h.ts.tv_usec = usec;
                    h.caplen = n - sizeof ( CmCh );
                    h.len = n - sizeof ( CmCh );
                    debug_5 ( "pcap_dump'ing cmc packet to file" );
                    pcap_dump( (u_char*) pd ,  &h, (u_char*) cmcpkt->pkt);
                }
            }
       }
        
    } /* while */

    return 0;
}
