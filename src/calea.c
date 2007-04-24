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

/* generate a correctly formated timestamp
   based on seconds and milliseconds UTC
*/
void get_calea_time ( time_t sec, time_t usec, char *buf ) {

    struct tm *mytm;
   
    mytm = gmtime ( &sec ); 
    sprintf ( buf, "%.4d-%.2d-%.2dT%.2d:%.2d:%.2d.%.3d",
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
        pdie ( "send" );
        switch ( errno ) {
        case EHOSTUNREACH:
        case EHOSTDOWN:
        case ENETDOWN:
            return -1;
            break;
        case ENOBUFS:
            log_1 ( "%s%s%s", "Whoah, slow down there!  You're sending packets too fast.\n",
                "Check your filter (eg. you're not capturing the very packets your sending out),\n",
                "and make sure you're capturing on the right interface." );
            break;
        default:
            exit ( -1 );
            break;
         }
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
        pdie ( "send" );
        switch ( errno ) {
        case EHOSTUNREACH:
        case EHOSTDOWN:
        case ENETDOWN:
            return -1;
            break;
        case ENOBUFS:
            log_1 ( "%s%s%s", "Whoah, slow down there!  You're sending packets too fast.\n",
                "Check your filter (eg. you're not capturing the very packets your sending out),\n",
                "and make sure you're capturing on the right interface." );
            break;
        default:
            exit ( -1 );
            break;
         }
    }
 
    return bytes_sent;
}

CmC* CmCPacketBuild ( CmCh *header, char *buf, int len ) {

    CmC *cmc_pkt;

    //cmc_pkt = (CmC*) malloc ( sizeof( CmC ) );
    if (! ( cmc_pkt = (CmC*) malloc ( sizeof( CmC ) ) ) ) {
        perror("malloc");
        exit ( -1 );
    }
   
    memcpy ( &(cmc_pkt->cmch), header, sizeof( CmCh ) ); 
    memcpy ( cmc_pkt->pkt, buf, len );

    return cmc_pkt;
}

void CmCPacketFree ( CmC *cmc_pkt ) {

    free ( cmc_pkt );
}

CmII* CmIIPacketBuild ( CmIIh *header, char *buf, int len ) {

    CmII *cmii_pkt;

    if (! ( cmii_pkt = (CmII*) malloc ( sizeof( CmII ) ) ) ) {
        perror("malloc");
        exit ( -1 );
    }
   
    memcpy ( &(cmii_pkt->cmiih), header, sizeof( CmIIh ) ); 
    memcpy ( &(cmii_pkt->pkt), buf, len );

    return cmii_pkt;
}

void CmIIPacketFree ( CmII *cmii_pkt ) {

    free ( cmii_pkt );
}

/* Helper Routines */

void *Calloc(size_t size) {
  char *ptr;
  ptr = calloc(1, size);
  if(!ptr) {
    perror("calloc() failed");
    exit(-1);
  }
  return ptr;
}

/*-------------------------------------------------------------------------------------*/
/* Print hex data                                                                      */
/*                                                                                     */
/*   Offset                                                                            */
/* Dec   Hex     Hex Data                                            ASCII Data        */
/* 00000 (00000) 4E 4F 54 49 46 59 20 73  69 70 3A 6F 70 65 6E 73    NOTIFY s ip:opens */
/*                                                                                     */
/*-------------------------------------------------------------------------------------*/
void print_hex(const u_char *payload, size_t payload_size) {

  size_t i, j, k, index = 0;
  char line[80];

  for (index=0; index < payload_size; index+=16) {
    bzero(line, 80);

    /* Print the base address. */
    sprintf(line, "%05Zu (%05lX)  ", index, (long unsigned)index);

    /* Print full row */
    if ( (k=payload_size-index) > 15 )  {
      /* Print full row */
      for ( i = 0; i < 16; i++ ) {
        if (i == 8) sprintf(line, "%s ", line);
        sprintf(line, "%s%02X ", line, payload[index+i]);
      }
      sprintf(line, "%s  ", line);
      for ( j = 0; j < 16; j++ ) {
        if (j == 8) sprintf(line, "%s ", line);
        sprintf(line, "%s%c", line, isprint(payload[index+j]) ? payload[index+j] : '.');
      }
      debug_5(line);
    } else {
    /* Print partial row */
      for ( i = 0; i < 16; i++ ) {
        if (i == 8) sprintf(line, "%s ", line);
        if (i < k) {
          sprintf(line, "%s%02X ", line, payload[index+i]);
        } else {
          sprintf(line, "%s   ", line);
        }
      }
      sprintf(line, "%s  ", line);
      for ( j = 0; j < 16; j++ ) {
        if (j == 8) sprintf(line, "%s ", line);
        if (j < k) {
          sprintf(line, "%s%c", line, isprint(payload[index+j]) ? payload[index+j] : '.');
        } else {
          sprintf(line, "%s ", line);
        }
      }
      debug_5(line);
    }
  }

}

