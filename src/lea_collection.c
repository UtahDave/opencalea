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
#include "lea_collection.h"

#include <pcap.h>
#include <net/ethernet.h>

FILE *cmii_fp = NULL;
struct pcap_dumper *pd = NULL;

void print_packet( const u_char *packet, u_short  size ) {
    int i = 0;
    printf ( " size: %d\n", size );
    for( i=0; i < size; i++ ) {
        printf ( "%02x ",  packet[i] );
    }
    printf ( "\n" );
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
    printf ( "[-f capture-file] " );
    printf ( "[-u user] [-g group] " );
    printf ( " [-m cmc-port] [-n cmii-port] [-x cooked-format]\n" );

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
    int i=0;
    int cmc_port = CmC_PORT;
    int cmii_port = CmII_PORT;
    int cooked_format = 0;
    int change_user = 0;
    int change_group = 0;
    struct passwd *pwent;
    struct group *grent;
    char user[32] = USER;
    char group[32] = GROUP;

    /* command line options processing */
    while (( i = getopt ( argc, argv, "t:f:hm:n:xu:g:" )) != -1 ) {

        switch ( i ) {
            case 'f':   // pcap capture file 
                capture_file = strdup ( optarg );
                break;
            case 't':   // cmii capture file
                cmii_capture_file = strdup ( optarg );
                break;
            case 'u':   // username
                strncpy ( (char *)user, optarg, 31 );
                change_user = 1;
                break;
            case 'g':   // group name
                strncpy ( &group[0], optarg, 31 );
                change_group = 1;
                break;
           case 'm':   // cmc port 
                cmc_port = atoi ( optarg );
                break; 
            case 'n':   // cmii port 
                cmii_port = atoi ( optarg );
                break; 
            case 'x':   // cmii port 
                cooked_format = 1;
                break; 
            case 'h':   // help
                usage();
                exit (-1); 
            default:
                usage ();
                exit ( 1 );
        }
    }

    if ( cmii_capture_file == NULL ) {
        printf ( "cmii capture file not specified...\n" );
        usage();
        exit(-1);
    }
    if ( capture_file == NULL ) {
        printf ( "warning!! pcap capture file not specified...\n" );
    }

    /* drop privs if running as root or told to do so */
    if ( ((uid_t)geteuid() == 0) || change_user ) {
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
    if ( ((uid_t)geteuid() == 0) || change_group ) {
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

    if ( capture_file != NULL ) {
        cmc_receiver_socket = socket ( PF_INET, SOCK_DGRAM, 0 );
        if ( cmc_receiver_socket == -1 ) {
            perror ( "socket" );
            exit ( 1 );
        }

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
    }

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


    signal (SIGINT, signal_handler);

    fd_set sock_fds;
    int num_sock_fds;

    FD_ZERO( &sock_fds );
    FD_SET( cmii_receiver_socket, &sock_fds );
    cmii_fp = fopen ( cmii_capture_file , "w" );

    if (cmii_fp == NULL) {
        perror ( "fopen" );
        exit ( 1 );
    }

    if ( capture_file != NULL ) {
        FD_SET( cmc_receiver_socket, &sock_fds );
        if ( cooked_format == 1 ) {
            pt =  pcap_open_dead ( DLT_LINUX_SLL,  10000 );
            pcap_set_datalink(pt, DLT_EN10MB);
        } else {
            pt =  pcap_open_dead ( DLT_EN10MB,  1024 );
        }

        pd =  pcap_dump_open( pt, capture_file );
        if (pd == NULL) {
            perror ( "pcap_dump_open" );
            exit ( 1 );
        }
    }

    len = sizeof ( struct sockaddr );
    while ( 1 ) {
        num_sock_fds = select( FD_SETSIZE, &sock_fds, (fd_set *) 0, 
		  (fd_set *) 0, NULL );
        if ( num_sock_fds < 0 ) {
            perror ( "select " );
        } else if ( num_sock_fds == 0 ) {
            /* no data */
        } else {
            /* read data on sockets */
            if ( FD_ISSET( cmii_receiver_socket, &sock_fds )) {
                memset ( buf, '\0', 10000 );
                if ((n = recvfrom ( cmii_receiver_socket, buf, 10000, 0, 
                    (struct sockaddr*) &cmii_receiver_addr, &len)) == -1) {
                    perror ( "recvfrom" );;
                } else {
                    //printf ( " Got %d bytes\n", n );
                } 
                
                cmiipkt = (CmII*) buf;
                CmIIh *cmiih;
                cmiih = (CmIIh*) &(cmiipkt->cmiih);
                struct in_addr myaddr, myaddr2;
                myaddr.s_addr = ntohl(cmiipkt->pkt_header.srcIP);
                myaddr2.s_addr = ntohl(cmiipkt->pkt_header.dstIP);
                snprintf(ts, TS_LENGTH+1, "%s", cmiipkt->cmiih.ts);
                snprintf(contentID, MAX_CONTENT_ID_LENGTH+1, "%s", cmiipkt->cmiih.contentID);
                snprintf(caseID, MAX_CASE_ID_LENGTH+1, "%s", cmiipkt->cmiih.caseID);
                snprintf(IAPSystemID, MAX_IAP_SYSTEM_ID_LENGTH+1, "%s", cmiipkt->cmiih.IAPSystemID);

                if ( (fprintf ( cmii_fp, "%s, ", contentID) < 0)
                  || (fprintf ( cmii_fp, "%s, ", caseID) < 0)
                  || (fprintf ( cmii_fp, "%s, ", IAPSystemID) < 0)
                  || (fprintf ( cmii_fp, "%s, ", ts) < 0)
                  || (fprintf ( cmii_fp, "%s, ", inet_ntoa(myaddr)) < 0)
                  || (fprintf ( cmii_fp, "%s, ", inet_ntoa(myaddr2)) < 0)
                  || (fprintf ( cmii_fp, "%d, ", ntohs(cmiipkt->pkt_header.srcPort)) < 0)
                  || (fprintf ( cmii_fp, "%d\n", ntohs(cmiipkt->pkt_header.dstPort)) < 0)
                   ) {
                    perror("fprintf");
                    exit( -1 );
                }
            }

            if ( capture_file != NULL ) {
                if ( FD_ISSET( cmc_receiver_socket, &sock_fds )) {
                    memset ( buf, '\0', 10000 );
                    if ((n = recvfrom ( cmc_receiver_socket, buf, 10000, 0, 
                        (struct sockaddr*) &cmc_receiver_addr, &len)) == -1) {
                        perror ( "recvfrom" );;
                    } else {
                        //printf ( " Got %d bytes\n", n );
                    } 
                    cmcpkt = (CmC*) buf;
                    sscanf ( cmcpkt->cmch.ts, 
                            "%d-%d-%dT%d:%d:%d.%ld", &(mytm.tm_year), 
                             &(mytm.tm_mon), &(mytm.tm_mday), &(mytm.tm_hour), 
                             &(mytm.tm_min), &(mytm.tm_sec), &usec); 
                    mytm.tm_year -= 1900;
                    mytm.tm_mon -= 1;
                    usec = usec * 1000;
                    h.ts.tv_sec = timegm ( &mytm );
                    h.ts.tv_usec = usec;
                    h.caplen = n - sizeof ( CmCh );
                    h.len = n - sizeof ( CmCh );
                    pcap_dump( (u_char*) pd ,  &h, (u_char*) cmcpkt->pkt);
                }
            }
       }
        
    } /* while */

    return 0;
}
