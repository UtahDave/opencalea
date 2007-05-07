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
#include "msg.h"
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
int CmCPacketSend (Msg *packet, int length, int *cmc_send_socket) {

    int bytes_sent;

    if ( (bytes_sent = send ( *cmc_send_socket, packet, length, 0)) == -1 ) {
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
int CmIIPacketSend (Msg *packet, int length, int *cmii_send_socket) { 

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

Msg *CmCPacketBuild (HEADER *dfheader) {

    Msg *msg;
    size_t msg_len;

    msg_len = sizeof(Msg);
    if (! ( msg = (Msg *) malloc ( msg_len + dfheader->encoded_size ) ) ) {
        perror("malloc");
        exit ( -1 );
    }

    msg->msgh.msgtype = MSGTYPE_CMC;
    msg->msgh.format  = MSGFMT_BER;
    msg->msgh.routeid = htons(dfheader->cmc_routeid);
    msg->msgh.msglen  = dfheader->encoded_size;

    memcpy ( ((char *)msg + msg_len), dfheader->encoded, dfheader->encoded_size);
    return msg;
}

Msg *CmIIPacketBuild (HEADER *dfheader) {

    Msg *msg;

    if (! ( msg = (Msg *) malloc ( sizeof(Msg) + dfheader->encoded_size ) ) ) {
        perror("malloc");
        exit ( -1 );
    }

    msg->msgh.msgtype = MSGTYPE_CMII;
    msg->msgh.format  = MSGFMT_BER;
    msg->msgh.routeid = htons(dfheader->cmii_routeid);
    msg->msgh.msglen  = dfheader->encoded_size;

    memcpy ( ((char *)msg + sizeof(Msg)), dfheader->encoded, dfheader->encoded_size);
    return msg;
}

void PacketFree ( Msg *msg ) {

    free ( msg );
}

Msg *CtrlMsgBuild (HEADER *dfheader) {

    Msg *msg;
    CtrlMsg *ctrlmsg;

    if ( !(msg = (Msg *)malloc(sizeof(Msg) + sizeof(CtrlMsg) ) ) ) {
        perror("CtrlMsgBuild: malloc");
        exit(-1);
    }

    ctrlmsg = (CtrlMsg *)((char *)msg + sizeof(Msg));

    msg->msgh.msgtype = MSGTYPE_CONTROL;
    msg->msgh.format  = MSGFMT_NONE;
    msg->msgh.routeid = htons(-1);
    msg->msgh.msglen  = sizeof(CtrlMsg);

    ctrlmsg->ctrlh.cmd = CTRLCMD_ROUTE_ADD;

    strcpy((char *)ctrlmsg->ctrlh.agent.IAPSystemID, dfheader->iAPSystemId);
    ctrlmsg->ctrlh.agent.type = AGENTTYPE_CONTROL;
    ctrlmsg->ctrlh.agent.subtype = AGENTSUBTYPE_IASTAP;

    strcpy((char *)ctrlmsg->ctrlh.intercept.CaseID, dfheader->caseId);
    strcpy((char *)ctrlmsg->ctrlh.intercept.SubjectID, dfheader->correlationID);

    strcpy((char *)ctrlmsg->ctrlh.dfhost.protocol, "udp");
    strcpy((char *)ctrlmsg->ctrlh.dfhost.host, "jabber.goes.com");

    return msg;
}

int PacketSend (char *packet, int length, int *send_socket) {

    int bytes_sent;

    if ( (bytes_sent = send ( *send_socket, packet, length, 0)) == -1 ) {
        pdie ( "PacketSend:" );
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

/* */
