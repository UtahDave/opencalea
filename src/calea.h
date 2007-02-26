/* Copyright Merit Network Inc. 2007 */

#ifndef _CALEA_H
#define _CALEA_H

#define CmC_PORT 6666
#define CmII_PORT 6667

#define MAX_CONTENT_ID_LENGTH 128
#define MAX_CASE_ID_LENGTH 128
#define MAX_IAP_SYSTEM_ID_LENGTH 128

typedef struct {
    char contentID[MAX_CONTENT_ID_LENGTH];
    char ts[24]; //time in ascii "YYYY-MM-DDThh:mm:ss.sssZ"
} cmc_header_t; 
#define CmCh cmc_header_t

/* Defination of a Communications Content packet according to the std */
typedef struct {
    CmCh cmch;
    u_char pkt[9000];
} cmc_pkt_t;
#define CmC cmc_pkt_t

/* Defination of a Header Set according to the std */
typedef struct {
    uint32_t streamID;
    uint32_t srcIP;
    uint32_t dstIP;
    uint16_t srcPort;
    uint16_t dstPort;
} header_t;
#define HEADER header_t

typedef struct {
    char caseID[MAX_CASE_ID_LENGTH];
    char IAPSystemID[MAX_IAP_SYSTEM_ID_LENGTH];
    char ts[24]; //time in ascii "YYYY-MM-DDThh:mm:ss.sssZ"
    char contentID[MAX_CONTENT_ID_LENGTH];
} cmii_header_t; 
#define CmIIh cmii_header_t

/* the Packet Data Header Report Msg Format from the std */
typedef struct {
    CmIIh cmiih;
    HEADER pkt_header;
} cmii_pkt_t;
#define CmII cmii_pkt_t

int CmCPacketSend ( CmC *packet, int length, int *send_sock, 
                    struct sockaddr_in *send_addr );
int CmIIPacketSend ( CmII *packet, int length, int *send_sock, 
                     struct sockaddr_in *send_addr );

void get_calea_time ( time_t sec, time_t usec, char *buf );

CmC* CmCPacketBuild ( CmCh *header, char *buf, int len );
CmII* CmIIPacketBuild ( CmIIh *header, char *buf, int len );
void CmCPacketFree ( CmC *cmc_pkt );
void CmIIPacketFree ( CmII *cmii_pkt );

#endif
