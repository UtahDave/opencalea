/* Copyright Merit Network Inc. 2007 */

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <string.h>
#include <sys/signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <time.h>
#include "lea_collection.h"
#include "calea.h"

struct pcap_dumper *pd;

void print_packet( const u_char *packet, u_short  size ) {
    int i = 0;
    printf ( " size: %d\n", size );
    for( i=0; i < size; i++ ) {
        printf ( "%02x ",  packet[i] );
    }
    printf ( "\n" );
}

void signal_handler ( int sigval ) {

    fclose ( cmii_fp );
    pcap_dump_close ( pd );
    exit ( 1 );
}

void usage ( void ) {

    printf ( "Usage: lea_collector -t <cmii-capture-file> " );
    printf ( "[-f <capture-file>] " );
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
    char ts[24];
    char *capture_file = NULL;
    char *cmii_capture_file = NULL;
    int i=0;
    int cmc_port = CmC_PORT;
    int cmii_port = CmII_PORT;
    int cooked_format = 0;

    /* command line options processing */
    while (( i = getopt ( argc, argv, "t:f:hm:n:x" )) != -1 ) {

        switch ( i ) {
            case 'f':   // pcap capture file 
                capture_file = strdup ( optarg );
                break;
            case 't':   // cmii capture file
                cmii_capture_file = strdup ( optarg );
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

    if ( capture_file != NULL ) {
        cmc_receiver_socket = socket ( PF_INET, SOCK_DGRAM, 0 );
        if ( cmc_receiver_socket == -1 ) {
            perror ( "socket" );
            exit ( 1 );
        }

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

    if ( capture_file != NULL ) {
        FD_SET( cmc_receiver_socket, &sock_fds );
        if ( cooked_format == 1 ) {
            pt =  pcap_open_dead ( DLT_LINUX_SLL,  10000 );
            pcap_set_datalink(pt, DLT_EN10MB);
        } else {
            pt =  pcap_open_dead ( DLT_EN10MB,  1024 );
        }

        pd =  pcap_dump_open( pt, capture_file ); 
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
                snprintf ( ts, 24, "%s", cmiipkt->cmiih.ts);

                fprintf ( cmii_fp, "%s, ", cmiipkt->cmiih.contentID);
                fprintf ( cmii_fp, "%s, ", cmiipkt->cmiih.caseID);
                fprintf ( cmii_fp, "%s, ", cmiipkt->cmiih.IAPSystemID);
                fprintf ( cmii_fp, "%s, ", ts);
                fprintf ( cmii_fp, "%s, ", inet_ntoa(myaddr));
                fprintf ( cmii_fp, "%s, ", inet_ntoa(myaddr2));
                fprintf ( cmii_fp, "%d, ", ntohs(cmiipkt->pkt_header.srcPort));
                fprintf ( cmii_fp, "%d\n", ntohs(cmiipkt->pkt_header.dstPort));
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
