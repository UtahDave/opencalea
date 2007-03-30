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

char contentID[MAX_CONTENT_ID_LENGTH];
char caseID[MAX_CASE_ID_LENGTH];
char iapID[MAX_IAP_SYSTEM_ID_LENGTH];

void print_packet( const u_char *packet, u_short  size ) {
    int i = 0;
    printf ( " size: %d\n", size );
    for( i=0; i < size; i++ ) {
        printf ( "%02x ",  packet[i] );
    }
    printf ( "\n" );
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
 
	ip = ( struct ip* )( packet + ETHER_HDR_LEN );
        get_calea_time ( header->ts.tv_sec, 
                             header->ts.tv_usec, &calea_time[0] );

        if ( content_option == 1 ) {
            /* only send Communications Content CmC msg if requested*/
            CmCh cmch;
            memcpy( cmch.contentID, contentID, MAX_CONTENT_ID_LENGTH );
            memcpy( cmch.ts, calea_time, TS_LENGTH );

            total_pkt_length = header->len + sizeof( CmCh );
            cmcpkt = CmCPacketBuild ( &cmch, (char*) packet, header->len );
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
        cmiipkt = CmIIPacketBuild ( &cmiih, (char*) &payload, sizeof( HEADER ) ); 
        total_pkt_length = sizeof( CmIIh ) + sizeof ( HEADER );
        CmIIPacketSend ( cmiipkt, total_pkt_length, &send_cmii_socket, 
                         &send_cmii_addr );
        CmIIPacketFree ( cmiipkt ); 
}


void usage ( void ) {

    printf ( "Usage: tap -i interface -x content-id -y case-id" );
    printf ( " -z iap-system-id [-d dest-ip] [-c]" );
    printf ( " [-m cmc-port] [-n cmii-port]" );
    printf ( " [-f capture-filter]\n" );

}

void print_help ( void ) {

    /* lets create a more informative help screen here */
    usage();
}
  
int main( int argc, char *argv[] ) {

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    bpf_u_int32 mask;		
    bpf_u_int32 net;		
    char *interface = NULL;
    char *filter = NULL;
    char *dest_ip = NULL;
    int i = 0;
    int cmc_port = CmC_PORT;
    int cmii_port = CmII_PORT;
    int change_user = 0;
    int change_group = 0;
    struct passwd *pwent;
    struct group *grent;
    char user[32] = USER;
    char group[32] = GROUP;


    /* command line options processing */
    while (( i = getopt ( argc, argv, "i:cf:d:hm:n:x:y:z:u:g:" )) != -1 ) {

        switch ( i ) {
            case 'i':   // interface
                interface = strdup ( optarg );
                break;
            case 'c':   // packet contents
                content_option = 1;
                break;
            case 'f':   // filter
                filter = strdup ( optarg );
                break; 
            case 'd':   // tunnel destination 
                dest_ip = strdup ( optarg );
                break; 
            case 'u':   // username
                strncpy ( user, optarg, 31 );
                change_user = 1;
                break;
            case 'g':   // group name
                strncpy ( group, optarg, 31 );
                change_group = 1;
                break;
           case 'm':   // cmc port 
                errno = 0;
                cmc_port = (int)strtol(optarg, (char **)NULL, 0);
                if (cmc_port <= 0) {
                    if (errno)
                        perror("strtol(cmc_port)");
                    else
                        fprintf(stderr, "invalid cmc_port\n");
                    exit(-1);
                }
                break; 
            case 'n':   // cmii port 
                errno = 0;
                cmii_port = (int)strtol(optarg, (char **)NULL, 0);
                if (cmii_port <= 0) {
                    if (errno)
                        perror("strtol(cmii_port)");
                    else
                        fprintf(stderr, "invalid cmii_port\n");
                    exit(-1);
                }
                break; 
            case 'x':   // contentID 
                strncpy ( contentID , optarg, MAX_CONTENT_ID_LENGTH );
                break; 
            case 'y':   // caseID 
                strncpy  ( caseID, optarg, MAX_CASE_ID_LENGTH );
                break; 
            case 'z':   // iapID 
                strncpy  ( iapID, optarg, MAX_IAP_SYSTEM_ID_LENGTH );
                break; 
            case 'h':   // help
                print_help();
                exit (-1); 
            default:
                usage ();
                exit ( 1 );
        }
    }
    
    if ( interface == NULL ) {
        printf ( "interface must be specified...\n");
        usage ();
        exit ( -1 );
    } 
    if ( dest_ip == NULL ) {
        dest_ip = strdup( "127.0.0.1" );
    }
    if ( strcmp ( contentID, "\0" )  == 0 ) {
        printf ( "contentID must be specified...\n");
        usage ();
        exit ( -1 );
    }
    if ( strcmp ( caseID, "\0" )  == 0 ) {
        printf ( "caseID must be specified...\n");
        usage ();
        exit ( -1 );
    }
    if ( strcmp ( iapID, "\0" )  == 0 ) {
        printf ( "iapID must be specified...\n");
        usage ();
        exit ( -1 );
    }
    if (cmc_port <= 0) {
        fprintf(stderr, "invalid cmc_port\n");
        exit(-1);
    }
    if (cmii_port <= 0) {
        fprintf(stderr, "invalid cmii_port\n");
        exit(-1);
    }

    handle = pcap_open_live( interface, BUFSIZ, 1, 1000, errbuf );
    if ( handle == NULL ) {
        fprintf( stderr, "Couldn't open device %s: %s\n", interface, errbuf );
        return( 2 );
    }

    /* drop privs if running as root or if told to do so */
    if ( change_user == 1) {
        errno = 0;
        if (! (pwent = getpwnam(user)) ) {
            if (errno)
                perror("getpwnam");
            else
                fprintf(stderr,"User %s not found\n", user);
            exit(-1);
        }
        if (setuid(pwent->pw_uid) < 0) {
            perror("setuid");
            exit(-1);
        }
    }
    if ( change_group == 1 ) {
        errno = 0;
        if (! (grent = getgrnam(group)) ) {
            if (errno)
                perror("getgrnam");
            else
                fprintf(stderr,"Group %s not found\n", group);
            exit(-1);
        }
        if (setgid(grent->gr_gid) < 0) {
            perror("setgid");
            exit(-1);
        }
    }

    if ( pcap_lookupnet( interface, &net, &mask, errbuf ) == -1 ) {
        fprintf( stderr, "Can't get netmask for device %s\n", interface );
        net = 0;
        mask = 0;
    }
 
   if ( pcap_compile( handle, &fp, filter, 0, net ) == -1 ) {
        fprintf( stderr, "Couldn't parse filter %s: %s\n", 
                 filter, pcap_geterr(handle) );
        return( 2 );
    }

    if ( pcap_setfilter( handle, &fp ) == -1 ) {
        fprintf( stderr, "Couldn't install filter %s: %s\n", 
                 filter, pcap_geterr(handle) );
        return( 2 );
    }

    /* Open CmC socket only if CmC option is selected */
    if ( content_option == 1 ) {
        if (( send_cmc_socket = socket ( PF_INET, SOCK_DGRAM, 0 )) == -1 ) {
            perror( "socket" );
            exit ( 1 );
        }

        memset ( (char *)&send_cmc_addr, '\0', sizeof(send_cmc_addr) );

        send_cmc_addr.sin_family = AF_INET;
        send_cmc_addr.sin_port   = htons( cmc_port );
        send_cmc_addr.sin_addr.s_addr = inet_addr(dest_ip);

        if (( connect(send_cmc_socket, (struct sockaddr *)&send_cmc_addr,
                sizeof(send_cmc_addr))  ) == -1 ) {
            perror( "connect" );
            exit ( 1 );
        }
    }

    if (( send_cmii_socket = socket ( PF_INET, SOCK_DGRAM, 0 )) == -1 ) {
        perror( "socket" );
        exit ( 1 );
    }

    memset ( (char *)&send_cmii_addr, '\0', sizeof(send_cmii_addr) );

    send_cmii_addr.sin_family = AF_INET;
    send_cmii_addr.sin_port   = htons( cmii_port );
    send_cmii_addr.sin_addr.s_addr = inet_addr(dest_ip);

    if (( connect(send_cmii_socket, (struct sockaddr *)&send_cmii_addr,
            sizeof(send_cmii_addr))  ) == -1 ) {
        perror( "connect" );
        exit ( 1 );
    }

    if ( content_option == 1 ) {
        printf ( "cmc send socket: %d\n", send_cmc_socket); 
    }
    printf ( "cmii send socket: %d\n", send_cmii_socket); 

    pcap_loop( handle, -1, process_packet, NULL );

    pcap_close( handle );

    return( 0 );
}


