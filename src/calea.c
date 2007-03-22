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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <string.h>
#include <search.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>
#include "calea.h"

/* generate an correctly formated timestamp
   based on seconds and milliseconds UTC
*/
void get_calea_time ( time_t sec, time_t usec, char *buf ) {

    struct tm *mytm;
   
    mytm = gmtime ( &sec ); 
    sprintf ( buf, "%.4d-%.2d-%.2dT%.2d:%.2d:%.2d.%.3dZ",
                    mytm->tm_year + 1900,
                    mytm->tm_mon + 1,
                    mytm->tm_mday, mytm->tm_hour, mytm->tm_min,
                    mytm->tm_sec, (int) usec/1000 );
}


/* send a Communications Content packet to lea 
   collection function
*/
int CmCPacketSend ( CmC *packet, int length, int *send_socket, 
                    struct sockaddr_in *send_addr ) {

    int bytes_sent;

    if ( (bytes_sent = send ( *send_socket, packet, length, 0)) == -1 ) {
        perror("send");
        if (! (errno == EHOSTUNREACH || 
               errno == EHOSTDOWN || 
               errno == ENETDOWN)) {
            exit ( -1 );
        }
        return -1;
     }

    return bytes_sent;
}

/* send a Packet Data Header Report msg to lea 
   collection function
*/
int CmIIPacketSend ( CmII *packet, int length, int *cmii_send_socket, 
                    struct sockaddr_in *cmii_send_addr ) {

    int bytes_sent;

    if ( (bytes_sent = send ( *cmii_send_socket, packet, length, 0)) == -1 ) {
        perror("send");
        if (! (errno == EHOSTUNREACH || 
               errno == EHOSTDOWN || 
               errno == ENETDOWN) ) {
            exit ( -1 );
        }
        return -1;
    }
 
    return bytes_sent;
}

CmC* CmCPacketBuild ( CmCh *header, char *buf, int len ) {

    CmC *cmc_pkt;

    cmc_pkt = (CmC*) malloc ( sizeof( CmC ) );
   
    memcpy ( &(cmc_pkt->cmch), header, sizeof( CmCh ) ); 
    memcpy ( cmc_pkt->pkt, buf, len );

    return cmc_pkt;
}

void CmCPacketFree ( CmC *cmc_pkt ) {

    free ( cmc_pkt );
}

CmII* CmIIPacketBuild ( CmIIh *header, char *buf, int len ) {

    CmII *cmii_pkt;

    cmii_pkt = (CmII*) malloc ( sizeof( CmII ) );
   
    memcpy ( &(cmii_pkt->cmiih), header, sizeof( CmII ) ); 
    memcpy ( &(cmii_pkt->pkt_header), buf, len );

    return cmii_pkt;
}

void CmIIPacketFree ( CmII *cmii_pkt ) {

    free ( cmii_pkt );
}

