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

#ifndef _CALEA_H
#define _CALEA_H

typedef struct {
    char contentID[MAX_CONTENT_ID_LENGTH];
    char ts[TS_LENGTH];
} cmc_header_t; 
#define CmCh cmc_header_t

/* Definition of a Communications Content packet according to the std */
typedef struct {
    CmCh cmch;
    u_char pkt[9000];
} cmc_pkt_t;
#define CmC cmc_pkt_t

/* Definition of a Header Set according to the std */
typedef struct {
    uint32_t streamID;
    uint32_t srcIP;
    uint32_t dstIP;
    uint16_t srcPort;
    uint16_t dstPort;

    /* temporarily added nb */
    char *contentId;
    char *caseId;
    char *iAPSystemId;
    char *start_time;
    const char *payload;
    size_t payload_size;
    char *correlationID;
    long sequenceNumber;
    time_t sec;
    time_t usec;
    char *encoded;
    size_t encoded_size;
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    int cmc_routeid;
    int cmii_routeid;
} header_t;
#define HEADER header_t

typedef struct {
    char caseID[MAX_CASE_ID_LENGTH];
    char IAPSystemID[MAX_IAP_SYSTEM_ID_LENGTH];
    char ts[TS_LENGTH];
    char contentID[MAX_CONTENT_ID_LENGTH];
} cmii_header_t; 
#define CmIIh cmii_header_t

/* the Packet Data Header Report Msg Format from the std */
typedef struct {
    CmIIh cmiih;
    HEADER pkt_header;
    u_char pkt[9000];
} cmii_pkt_t;
#define CmII cmii_pkt_t

#endif
