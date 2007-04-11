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
#include "tap.h"

#include <pcap.h> 
#include <net/ethernet.h>

char *prog_name = "tap";
int syslog_facility = DEF_SYSLOG_FACILITY;

char contentID[MAX_CONTENT_ID_LENGTH];
char caseID[MAX_CASE_ID_LENGTH];
char iapID[MAX_IAP_SYSTEM_ID_LENGTH];

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

void process_packet( u_char *args, const struct pcap_pkthdr *header,
	    const u_char *packet ) {
    struct ip *ip;
    struct udphdr *udp;
    struct tcphdr *tcp;
    CmC *cmcpkt;
    CmII *cmiipkt;
    int total_pkt_length;
    char calea_time[TS_LENGTH];

#ifdef DEBUG_PKTS
    char msg[ MAX_LOG_DEBUG_MSG_LEN ];

    memset ( msg, '\0', MAX_LOG_DEBUG_MSG_LEN );
#endif

    ip = ( struct ip* )( packet + ETHER_HDR_LEN );

    get_calea_time ( header->ts.tv_sec, 
                     header->ts.tv_usec, &calea_time[0] );

    if ( content_option == 1 ) {
        /* only send Communications Content CmC msg if requested*/
        CmCh cmch;
        memcpy( cmch.contentID, contentID, MAX_CONTENT_ID_LENGTH );
        memcpy( cmch.ts, calea_time, TS_LENGTH );

        total_pkt_length = header->len + sizeof( CmCh );
#ifdef DEBUG_PKTS
        debug_5 ( "building CmC packet" );
#endif
        cmcpkt = CmCPacketBuild ( &cmch, (char*) packet, header->len );
#ifdef DEBUG_PKTS
        debug_5 ( "sending CmC packet" );
#endif
        CmCPacketSend ( cmcpkt, total_pkt_length, &send_cmc_socket, 
                     &send_cmc_addr );
        CmCPacketFree ( cmcpkt ); 
    }
    /* next we send the Packet Data Header Report msg */

    CmIIh cmiih;
    HEADER payload;

    memcpy( cmiih.ts, calea_time, TS_LENGTH );
    memcpy( cmiih.contentID, contentID, MAX_CONTENT_ID_LENGTH );
    memcpy( cmiih.caseID, caseID, MAX_CASE_ID_LENGTH );
    memcpy( cmiih.IAPSystemID, iapID, MAX_IAP_SYSTEM_ID_LENGTH );
 
    payload.srcIP = htonl(ip->ip_src.s_addr); 
    payload.dstIP = htonl(ip->ip_dst.s_addr); 
    if ( ip->ip_p == IPPROTO_UDP ) {
        udp = ( struct udphdr* ) ( (u_char *)ip + (ip->ip_hl *4) );
        payload.srcPort = udp->uh_sport; 
        payload.dstPort = udp->uh_dport; 
    } else if ( ip->ip_p == IPPROTO_TCP ) {
        tcp = ( struct tcphdr* ) ( (u_char *)ip + (ip->ip_hl *4) );
        payload.srcPort = tcp->th_sport; 
        payload.dstPort = tcp->th_dport; 
    } else {
        payload.srcPort = 0; 
        payload.dstPort = 0; 
    }

#ifdef DEBUG_PKTS
    debug_5 ( "building CmII packet" );
#endif
    cmiipkt = CmIIPacketBuild ( &cmiih, (char*) &payload, sizeof( HEADER ) ); 
    total_pkt_length = sizeof( CmIIh ) + sizeof ( HEADER );
#ifdef DEBUG_PKTS
    debug_5 ( "sending CmII packet" );
#endif
    CmIIPacketSend ( cmiipkt, total_pkt_length, &send_cmii_socket, 
                     &send_cmii_addr );
    CmIIPacketFree ( cmiipkt ); 
}


void usage ( void ) {
    printf ( "Usage: tap -x content-id -y case-id" );
    printf ( " -z iap-system-id [-i interface]  [-d destination ] [-c]" );
    printf ( "[-u user] [-g group] " );
    printf ( " [-m cmc-port] [-n cmii-port]" );
    printf ( " [-v [...]] [-D debug-file]" );
    printf ( " [-l log-level ] [-L logfile]" );
    printf ( " [-f capture-filter]" );
    printf ( "\n" );
}

void print_help ( void ) {

    /* lets create a more informative help screen here */
    usage();
}
  

int main( int argc, char *argv[] ) {

    char errbuf[PCAP_ERRBUF_SIZE] = "";
    pcap_t *handle;
    struct bpf_program fp;
    bpf_u_int32 mask;		
    bpf_u_int32 net;		
    char *interface = NULL;
    char *filter = NULL;
    char *dest = NULL;
    struct addrinfo hints, *res, *res0;
    int i = 0;
    char *cmc_port = 0;
    char *cmii_port = 0;
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
    while (( i = getopt ( argc, argv, "i:cf:d:hm:n:x:y:z:u:g:vD:l:L:" )) != -1 ) {

        switch ( i ) {
            case 'i':   // interface
                if ( ( interface = strdup ( optarg ) ) == NULL )
                    pdie ( "strdup" );
                debug_5 ( "got opt %c: %s", i, optarg );
                break;
            case 'c':   // packet contents
                content_option = 1;
                debug_5 ( "got opt %c", i );
                break;
            case 'f':   // filter
                if ( ( filter = strdup ( optarg ) ) == NULL )
                    pdie ( "strdup" );
                debug_5 ( "got opt %c: %s", i, optarg );
                break; 
            case 'd':   // tunnel destination 
                if ( ( dest = strdup ( optarg ) ) == NULL )
                    pdie ( "strdup" );
                debug_5 ( "got opt %c: %s", i, optarg );
                break; 
            case 'u':   // username
                strncpy ( user, optarg, 31 );
                debug_5 ( "got opt %c: %s", i, optarg );
                change_user = 1;
                break;
            case 'g':   // group name
                strncpy ( group, optarg, 31 );
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
            case 'x':   // contentID 
                strncpy ( contentID , optarg, MAX_CONTENT_ID_LENGTH );
                debug_5 ( "got opt %c: %s", i, optarg );
                break; 
            case 'y':   // caseID 
                strncpy  ( caseID, optarg, MAX_CASE_ID_LENGTH );
                debug_5 ( "got opt %c: %s", i, optarg );
                break; 
            case 'z':   // iapID 
                strncpy  ( iapID, optarg, MAX_IAP_SYSTEM_ID_LENGTH );
                debug_5 ( "got opt %c: %s", i, optarg );
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
                debug_5 ( "got opt %c", i );
                print_help();
                exit ( 0 ); 
            default:
                debug_5 ( "got opt %c", i );
                usage ();
                exit ( 1 );
        }
    }

    if ( strcmp ( contentID, "\0" )  == 0 ) {
        usage ();
        die ( "Error: contentID must be specified" );
    }
    if ( strcmp ( caseID, "\0" )  == 0 ) {
        usage ();
        die ( "Error: caseID must be specified" );
    }
    if ( strcmp ( iapID, "\0" )  == 0 ) {
        usage ();
        die ( "Error: iapID must be specified" );
    }
    if ( interface == NULL ) {
        debug_4 ( "looking up pcap capable device" );
        interface = pcap_lookupdev( errbuf );
        if ( interface == NULL ) {
            die ( "pcap_lookupdev: %s\n", errbuf );
        }
        debug_2 ( "using default interface: %s", interface );
    } 
    /* getaddrinfo defaults to loopback, but we'll specify it anyways */
    if ( dest == NULL ) {
        if ( ( dest = strdup ( "127.0.0.1" ) ) == NULL )
            pdie ( "strdup" );
        debug_2 ( "using default dest (%s)", dest );
    }

    debug_4 ( "opening pcap handle" );
    handle = pcap_open_live( interface, 65535, 1, 1000, errbuf );
    if ( handle == NULL ) {
        die ( "Couldn't open device %s: %s\n", interface, errbuf );
    }

    /* drop privs if running as root or if told to do so */
    if ( change_user == 1) {
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
    if ( change_group == 1 ) {
        debug_3 ( "changing group id to: %s", group );
        errno = 0;
        if (! (grent = getgrnam(group)) ) {
            if (errno) {
                pdie ( "getgrnam" );
            } else {
                die ( "Group %s not found\n", group );
            }
        }
        if ( setgid(grent->gr_gid) < 0 )
            pdie ( "setgid" );
    }

    /* do as much as possible after dropping privs */
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

    if ( cmii_port == NULL ) {  
        if ( ! ( cmii_port = malloc ( 64 ) ) )
            perror ( "malloc" );
        snprintf ( cmii_port, 64, "%d", CmII_PORT );
        debug_5 ( "using default cmii port (%s)", cmii_port );
    }
    if ( content_option == 1 ) {
        if ( cmc_port == NULL ) {
            if ( ! ( cmc_port = malloc ( 64 ) ) )
                perror ( "malloc" );
            snprintf ( cmc_port, 64, "%d", CmC_PORT );
            debug_5 ( "using default cmc port (%s)", cmc_port );
        }
    }

    debug_5 ( "running pcap_lookupnet" );
    if ( pcap_lookupnet( interface, &net, &mask, errbuf ) == -1 ) {
        debug_3 ( "Can't get netmask for device %s", interface );
        log_3 ( "Can't get netmask for device %s", interface );
        net = 0;
        mask = 0;
    }
 
    debug_5 ( "running pcap_compile" );
    if ( pcap_compile( handle, &fp, filter, 0, net ) == -1 ) {
        die ( "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle) );
    }

    debug_5 ( "running pcap_setfilter" );
    if ( pcap_setfilter( handle, &fp ) == -1 ) {
        die ( "Couldn't install filter %s: %s\n", filter, pcap_geterr(handle) );
    }

    /* Open CmC socket only if CmC option is selected */
    if ( content_option == 1 ) {
        debug_5 ( "CmC option is set" );

        memset ( &hints, 0, sizeof ( hints ) );
        hints.ai_family = PF_INET;
        hints.ai_socktype = SOCK_DGRAM;

        debug_5 ( "calling getaddrinfo" );
        i = getaddrinfo ( dest, cmc_port, &hints, &res0 );
        if ( i ) {
            die ( "getaddrinfo: %s", gai_strerror( i ) );
        }

        send_cmc_socket = -1;
        for (res = res0; res; res = res->ai_next) {
            memset ( (char *)&send_cmc_addr, '\0', sizeof(send_cmc_addr) );

            send_cmc_addr.sin_family = res->ai_family;
            send_cmc_addr.sin_port   = ((struct sockaddr_in *)res->ai_addr)->sin_port;
            send_cmc_addr.sin_addr.s_addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr;

            debug_5 ( "trying send_cmc_addr %s:%d",
                inet_ntoa ( send_cmc_addr.sin_addr ), htons ( send_cmc_addr.sin_port ) );

            debug_5 ( "creating send_cmc_socket" );
            send_cmc_socket = socket( res->ai_family, res->ai_socktype, res->ai_protocol );
            if (send_cmc_socket < 0) {
                debug_5 ( "socket: %s", strerror ( errno ) );
                strncpy ( errbuf, "socket", PCAP_ERRBUF_SIZE );
                if ( res->ai_next )
                     debug_5 ( "socket failed, trying next ip addr" );
                continue;
            }

            debug_5 ( "connecting send_cmc_socket" );
            if ( connect ( send_cmc_socket, res->ai_addr, res->ai_addrlen ) < 0 ) {
                strncpy ( errbuf, "connect", PCAP_ERRBUF_SIZE );
                debug_5 ( "connect: %s", strerror ( errno ) );
                if ( close( send_cmc_socket ) == -1 )
                    pdie ( "close" );
                send_cmc_socket = -1;
                if ( res->ai_next )
                     debug_5 ( "connect failed, trying next ip addr" );
                continue;
            }

            debug_5 ( "connect succeeded" );
            break;
        }
        if ( send_cmc_socket < 0 ) {
            pdie ( errbuf );
        }

        freeaddrinfo(res0);
    } else {
        debug_5 ( "CmC option is not set" );
    }

    memset ( &hints, 0, sizeof ( hints ) );
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    debug_5 ( "calling getaddrinfo" );
    i = getaddrinfo ( dest, cmii_port, &hints, &res0 );
    if ( i ) {
        die ( "getaddrinfo: %s", gai_strerror( i ) );
    }

    send_cmii_socket = -1;
    for (res = res0; res; res = res->ai_next) {
        memset ( (char *)&send_cmii_addr, '\0', sizeof(send_cmii_addr) );

        send_cmii_addr.sin_family = res->ai_family;
        send_cmii_addr.sin_port   = ((struct sockaddr_in *)res->ai_addr)->sin_port;
        send_cmii_addr.sin_addr.s_addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr;

        if ( content_option ) {
            send_cmii_addr.sin_family = send_cmc_addr.sin_family;
            send_cmii_addr.sin_addr.s_addr = send_cmc_addr.sin_addr.s_addr;
            debug_5 ( "using send_cmii_addr %s:%d",
                inet_ntoa ( send_cmii_addr.sin_addr ), htons ( send_cmii_addr.sin_port ) );
        } else {
            debug_5 ( "trying send_cmii_addr %s:%d",
                inet_ntoa ( send_cmii_addr.sin_addr ), htons ( send_cmii_addr.sin_port ) );
        }

        debug_5 ( "creating send_cmii_socket" );
        send_cmii_socket = socket( res->ai_family, res->ai_socktype, res->ai_protocol );
        if (send_cmii_socket < 0) {
            debug_5 ( "socket: %s", strerror ( errno ) );
            strncpy ( errbuf, "socket", PCAP_ERRBUF_SIZE );
            if ( ! content_option ) {
                debug_5 ( "socket failed, trying next ip addr" );
                continue;
            } else {
                break;
            }
        }

        debug_5 ( "connecting send_cmii_socket" );
        if ( connect ( send_cmii_socket, (struct sockaddr *)&send_cmii_addr,
                sizeof(send_cmii_addr) ) < 0 ) {
            strncpy ( errbuf, "connect", PCAP_ERRBUF_SIZE );
            debug_5 ( "connect: %s", strerror ( errno ) );
            if ( close( send_cmii_socket ) == -1 )
                pdie ( "close" );
            send_cmii_socket = -1;
            if ( ! content_option ) {
                debug_5 ( "connect failed, trying next ip addr" );
                continue;
            } else {
                break;
            }
        }

        debug_5 ( "connect succeeded" );
        break;
    }
    if ( send_cmii_socket < 0 ) {
        pdie ( errbuf );
    }

    freeaddrinfo(res0);

    debug_4 ( "begining pcap_loop" );
    pcap_loop( handle, -1, process_packet, NULL );

    debug_4 ( "pcap_loop done, calling pcap_close" );
    pcap_close( handle );

    return( 0 );
}

