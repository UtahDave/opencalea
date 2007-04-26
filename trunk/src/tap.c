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

char *ias_cc_apdu(HEADER *dfheader);
char *packet_data_header_report(HEADER *dfheader);


/*
 * Config settings are set as follows (each step
 *     overwrites settings from an earlier step):
 *
 *   - Use compile time defaults
 *   - read alternate config file from "-f"
 *   - if no "-f" given, read DEF_OPENCALEA_CONF,
 *     then re-read DEF_TAP_CONF
 *   - read command-line options
 */

#ifndef DEF_TAP_CONF
#define DEF_TAP_CONF "/etc/opencalea/tap.conf"
#endif


/* Config Item: Program_Name */
char *prog_name = "tap";
/* Config Item: Syslog_Facility */
int syslog_facility = DEF_SYSLOG_FACILITY;

/* Config Item: ContentID */
char contentID[MAX_CONTENT_ID_LENGTH];
/* Config Item: CaseID */
char caseID[MAX_CASE_ID_LENGTH];
/* Config Item: IAPSystemID */
char iapID[MAX_IAP_SYSTEM_ID_LENGTH];

void process_packet( u_char *args, const struct pcap_pkthdr *header, const u_char *packet ) {

    struct ether_header *ethernet;
    struct ip *ip;
    struct udphdr *udp;
    struct tcphdr *tcp;
    CmCh cmch;
    CmC *cmcpkt;
    CmIIh cmiih;
    CmII *cmiipkt;
    int total_pkt_length;
    int ip_size;
    int tcp_size;
    int udp_size;
    int payload_size;
    int ip_size_total;
    const char *payload;      /* Packet Payload */
    HEADER *dfheader;
    char calea_time[TS_LENGTH];

    dfheader = (HEADER *)args;
    debug_4("ContentID: %s", dfheader->contentId);
    debug_4("CaseID: %s", dfheader->caseId);
    debug_4("iAPSystemId: %s", dfheader->iAPSystemId);

#ifdef DEBUG_PKTS
    char msg[ MAX_LOG_DEBUG_MSG_LEN ];
    memset ( msg, '\0', MAX_LOG_DEBUG_MSG_LEN );
#endif

    get_calea_time ( header->ts.tv_sec, header->ts.tv_usec, &calea_time[0] ); 

    dfheader->sec = header->ts.tv_sec;
    dfheader->usec = header->ts.tv_usec/100;

    /* Send the Packet Data Header Report msg */

    memcpy( cmiih.ts, calea_time, TS_LENGTH );
    memcpy( cmiih.contentID, contentID, MAX_CONTENT_ID_LENGTH );
    memcpy( cmiih.caseID, caseID, MAX_CASE_ID_LENGTH );
    memcpy( cmiih.IAPSystemID, iapID, MAX_IAP_SYSTEM_ID_LENGTH );

    /* Ethernet Packet */
    ethernet = (struct ether_header *)(packet);

    /* IP Header Offset */
    ip = ( struct ip* )( (char *)ethernet + ETHER_HDR_LEN );
    ip_size_total = (int)ntohs(ip->ip_len);
    ip_size = ip->ip_hl * 4;
    if (ip_size < 20) {
      log_5("Packet has invalid IP header length: %u bytes", ip_size);
      debug_3("Packet has invalid IP header length: %u bytes", ip_size);
      return;
    }
 
    dfheader->srcIP = htonl(ip->ip_src.s_addr); 
    dfheader->dstIP = htonl(ip->ip_dst.s_addr); 

    inet_ntop(AF_INET, &ip->ip_src.s_addr, dfheader->src_ip, sizeof(dfheader->src_ip));
    inet_ntop(AF_INET, &ip->ip_dst.s_addr, dfheader->dst_ip, sizeof(dfheader->dst_ip));

    if ( ip->ip_p == IPPROTO_UDP ) {
        /* UDP Header */
        udp = ( struct udphdr* ) ( (u_char *)ip + ip_size );

        udp_size = sizeof(struct udphdr);
        if (ntohs(udp->uh_ulen) <= 12) {
          log_5("Packet has invalid UDP header length: %u bytes", udp_size);
          debug_3("Packet has invalid UDP header length: %u bytes", udp_size);
          return;
        }

        /* UDP Payload */
        payload = (char *)((u_char *)udp + udp_size);

        /* UDP Payload size */
        payload_size = ntohs(udp->uh_ulen) - udp_size;

        //if (payload_size > 0) {
        //  debug_5("Payload (%d bytes):", payload_size);
        //  print_hex(payload, payload_size);
        //}

        //format_vop_payload(dfheader);

        dfheader->srcPort = ntohs(udp->uh_sport);
        dfheader->dstPort = ntohs(udp->uh_dport);

    } else if ( ip->ip_p == IPPROTO_TCP ) {

        /* TCP Header */
        tcp = ( struct tcphdr* ) ( (u_char *)ip + ip_size);

        tcp_size = tcp->th_off * 4;
        if (tcp_size < 20) {
          log_5("Packet has invalid TCP header length: %u bytes", tcp_size);
          debug_3("Packet has invalid TCP header length: %u bytes", tcp_size);
          return;
        }

        /* TCP Payload */
        payload = (char *)((u_char *)tcp + tcp_size);

        /* TCP Payload size */
        payload_size = ntohs(ip->ip_len) - (ip_size + tcp_size);

        //format_ias_payload(dfheader, payload, payload_size, 1);
        //format_vop_payload(dfheader, payload, payload_size, 1);

        dfheader->srcPort = ntohs(tcp->th_sport);
        dfheader->dstPort = ntohs(tcp->th_dport);

    } else {
        debug_4("Packet is neither UDP or TCP");
        dfheader->srcPort = 0;
        dfheader->dstPort = 0;
    }

    /*------------------------------------------------------------------------*/
    /* only send Communications Content CmC msg if requested                  */
    /*------------------------------------------------------------------------*/
    if ( content_option == 1 ) {

      debug_5("IP (%d bytes):", ip_size_total);
      print_hex((const u_char *)ip, (size_t)ip_size_total);

      dfheader->sequenceNumber++;
      dfheader->payload = (const char *)ip;
      dfheader->payload_size = (size_t)ip_size_total;
      /*------------------------------------------------------------------------*/
      /* WARNING: ias_cc_apdu will allocate space for the BER encoded message.  */
      /*          This space MUST be freed when it is no longer needed or a     */
      /*          memory leak will occur.                                       */
      /*                                                                        */
      /*          The address of the allocated memory is dfheader->encoded.     */
      /*          The size of the allocated memory is dfheader->encoded_size.   */
      /*          If ias_cc_apdu does not return 0, no deallocation is needed.  */
      /*------------------------------------------------------------------------*/
      if ( ias_cc_apdu(dfheader) == 0) {
        debug_5("Encoded size: %Zd", dfheader->encoded_size);
        debug_5("Encoded addr: %p", dfheader->encoded);
      } else {
        return;
      }

      memcpy( cmch.contentID, contentID, MAX_CONTENT_ID_LENGTH );
      memcpy( cmch.ts, calea_time, TS_LENGTH );

      total_pkt_length = header->len + sizeof( CmCh );
      debug_5 ( "building CmC packet size: %d", total_pkt_length );
      cmcpkt = CmCPacketBuild ( &cmch, dfheader->encoded, dfheader->encoded_size );
      debug_5 ( "sending CmC packet size: %d", total_pkt_length );
      CmCPacketSend ( cmcpkt, total_pkt_length, &send_cmc_socket, &send_cmc_addr );
      CmCPacketFree ( cmcpkt );

      free(dfheader->encoded);

    }

    if (packet_data_header_report(dfheader) == 0) {
      debug_5("Packet_Data_Header_Report encoded size: %Zd", dfheader->encoded_size);
      debug_5("Packet_Data_Header_Report encoded addr: %p", dfheader->encoded);
      print_hex((const u_char *)dfheader->encoded, (size_t)dfheader->encoded_size);
    } else {
      return;
    }

    total_pkt_length = sizeof( CmIIh );
    debug_5 ( "building CmII packet size: %d", total_pkt_length);
    cmiipkt = CmIIPacketBuild ( &cmiih, dfheader->encoded, dfheader->encoded_size); 
    debug_5 ( "sending CmII packet size: %d", total_pkt_length );
    CmIIPacketSend ( cmiipkt, total_pkt_length, &send_cmii_socket, &send_cmii_addr ); 
    CmIIPacketFree ( cmiipkt ); 

    free(dfheader->encoded);

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
    GKeyFile*   tap_conf_file;
    char *conf_temp = NULL;

    HEADER *dfheader;

    setdebug( DEF_DEBUG_LEVEL, "syslog", 1 );
    setlog( DEF_LOG_LEVEL, "syslog", 1 );

    /* loading parameters from conf file */
    tap_conf_file = g_key_file_new ( );
    if ( !g_key_file_load_from_file ( tap_conf_file, "tap.conf", 
           G_KEY_FILE_KEEP_COMMENTS, NULL)) {
        error ( "unable to parse tap.conf file" );
    } else {

        if ( (conf_temp = g_key_file_get_string ( tap_conf_file, 
                    "PREFERENCES", "Interface", NULL)) != NULL) {
            interface = Strdup ( conf_temp );
            debug_3 ( "Using config item Interface: %s", interface );
        } else {
            debug_4 ( "Not set in config file: Interface" );
        }

        if ( (conf_temp = g_key_file_get_string ( tap_conf_file, 
                    "PREFERENCES", "IAPSystemID", NULL)) != NULL) {
            strncpy ( iapID, conf_temp, MAX_IAP_SYSTEM_ID_LENGTH);
            debug_3 ( "Using config item IAPSystemID: %s", iapID );
        } else {
            debug_4 ( "Not set in config file: IAPSystemID" );
        }
     
        /* we are done loading from conf file */
        g_key_file_free ( tap_conf_file );
    }

    /* command line options processing */
    while (( i = getopt ( argc, argv, "i:cf:d:hm:n:x:y:z:u:g:vD:l:L:" )) != -1 ) {

        switch ( i ) {
            case 'i':   // interface
                interface = Strdup ( optarg );
                debug_4 ( "got opt %c: %s", i, optarg );
                break;
            case 'c':   // packet contents
                content_option = 1;
                debug_4 ( "got opt %c", i );
                break;
            case 'f':   // filter
                filter = Strdup ( optarg );
                debug_4 ( "got opt %c: %s", i, optarg );
                break; 
            case 'd':   // tunnel destination 
                dest = Strdup ( optarg );
                debug_4 ( "got opt %c: %s", i, optarg );
                break; 
            case 'u':   // username
                strncpy ( user, optarg, 31 );
                debug_4 ( "got opt %c: %s", i, optarg );
                change_user = 1;
                break;
            case 'g':   // group name
                strncpy ( group, optarg, 31 );
                debug_4 ( "got opt %c: %s", i, optarg );
                change_group = 1;
                break;
           case 'm':   // cmc port 
                cmc_port = Strdup ( optarg );
                debug_4 ( "got opt %c: %s", i, optarg );
                break; 
            case 'n':   // cmii port 
                cmii_port = Strdup ( optarg );
                debug_4 ( "got opt %c: %s", i, optarg );
                break; 
            case 'x':   // contentID 
                strncpy ( contentID , optarg, MAX_CONTENT_ID_LENGTH );
                debug_4 ( "got opt %c: %s", i, optarg );
                break; 
            case 'y':   // caseID 
                strncpy  ( caseID, optarg, MAX_CASE_ID_LENGTH );
                debug_4 ( "got opt %c: %s", i, optarg );
                break; 
            case 'z':   // iapID 
                strncpy  ( iapID, optarg, MAX_IAP_SYSTEM_ID_LENGTH );
                debug_4 ( "got opt %c: %s", i, optarg );
                break; 
            case 'v':   // debug ('d' was taken)
                debug_level_set++;
                debug_4 ( "got opt %c, debug level now %d",
                    i, debug_level_set );
                break;
            case 'D':   // debug file
                debug_file = Strdup ( optarg );
                debug_4 ( "got opt %c: %s", i, optarg );
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
                debug_4 ( "got opt %c: %d", i, log_level_set );
                break; 
            case 'L':   // logfile
                log_file = Strdup ( optarg );
                debug_4 ( "got opt %c: %s", i, optarg );
                break; 
            case 'h':   // help
                debug_4 ( "got opt %c", i );
                print_help();
                exit ( 0 ); 
            default:
                debug_4 ( "got opt %c", i );
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
        dest = Strdup ( "127.0.0.1" );
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
        debug_3 ( "resetting debug level (%d) and destination (%s)",
            debug_level_set, debug_file );
        setdebug( debug_level_set, debug_file, 1 );
    } else {
        debug_3 ( "resetting debug level (%d)", debug_level_set );
        setdebug( debug_level_set, "syslog", 1 );
    }
    if ( log_file && strlen ( log_file ) ) {
        log_level_set = ( log_level_set ) ? log_level_set : DEF_LOG_LEVEL;
        debug_3 ( "resetting log level (%d) and destination (%s)",
            log_level_set, log_file );
        setlog( log_level_set, log_file, 1 );
    } else {
        debug_3 ( "resetting log level (%d)", log_level_set );
        setlog( log_level_set, "syslog", 1 );
    }

    if ( cmii_port == NULL ) {  
        cmii_port = Calloc ( 64 );
        snprintf ( cmii_port, 64, "%d", CmII_PORT );
        debug_4 ( "using default cmii port (%s)", cmii_port );
    }
    if ( content_option == 1 ) {
        if ( cmc_port == NULL ) {
            cmc_port = Calloc ( 64 );
            snprintf ( cmc_port, 64, "%d", CmC_PORT );
            debug_4 ( "using default cmc port (%s)", cmc_port );
        }
    }

    debug_4 ( "running pcap_lookupnet" );
    if ( pcap_lookupnet( interface, &net, &mask, errbuf ) == -1 ) {
        debug_3 ( "Can't get netmask for device %s", interface );
        log_3 ( "Can't get netmask for device %s", interface );
        net = 0;
        mask = 0;
    }
 
    debug_4 ( "running pcap_compile" );
    if ( pcap_compile( handle, &fp, filter, 0, net ) == -1 ) {
        die ( "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle) );
    }

    debug_4 ( "running pcap_setfilter" );
    if ( pcap_setfilter( handle, &fp ) == -1 ) {
        die ( "Couldn't install filter %s: %s\n", filter, pcap_geterr(handle) );
    }

    /* Open CmC socket only if CmC option is selected */
    if ( content_option == 1 ) {
        debug_4 ( "CmC option is set" );

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

            debug_4 ( "trying send_cmc_addr %s:%d",
                inet_ntoa ( send_cmc_addr.sin_addr ), htons ( send_cmc_addr.sin_port ) );

            debug_4 ( "creating send_cmc_socket" );
            send_cmc_socket = socket( res->ai_family, res->ai_socktype, res->ai_protocol );
            if (send_cmc_socket < 0) {
                debug_4 ( "socket: %s", strerror ( errno ) );
                strncpy ( errbuf, "socket", PCAP_ERRBUF_SIZE );
                if ( res->ai_next )
                     debug_4 ( "socket failed, trying next ip addr" );
                continue;
            }

            debug_4 ( "connecting send_cmc_socket" );
            if ( connect ( send_cmc_socket, res->ai_addr, res->ai_addrlen ) < 0 ) {
                strncpy ( errbuf, "connect", PCAP_ERRBUF_SIZE );
                debug_4 ( "connect: %s", strerror ( errno ) );
                if ( close( send_cmc_socket ) == -1 )
                    pdie ( "close" );
                send_cmc_socket = -1;
                if ( res->ai_next )
                     debug_4 ( "connect failed, trying next ip addr" );
                continue;
            }

            debug_4 ( "connect succeeded" );
            break;
        }
        if ( send_cmc_socket < 0 ) {
            pdie ( errbuf );
        }

        freeaddrinfo(res0);
    } else {
        debug_4 ( "CmC option is not set" );
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
            debug_4 ( "using send_cmii_addr %s:%d",
                inet_ntoa ( send_cmii_addr.sin_addr ), htons ( send_cmii_addr.sin_port ) );
        } else {
            debug_4 ( "trying send_cmii_addr %s:%d",
                inet_ntoa ( send_cmii_addr.sin_addr ), htons ( send_cmii_addr.sin_port ) );
        }

        debug_4 ( "creating send_cmii_socket" );
        send_cmii_socket = socket( res->ai_family, res->ai_socktype, res->ai_protocol );
        if (send_cmii_socket < 0) {
            debug_4 ( "socket: %s", strerror ( errno ) );
            strncpy ( errbuf, "socket", PCAP_ERRBUF_SIZE );
            if ( ! content_option ) {
                debug_4 ( "socket failed, trying next ip addr" );
                continue;
            } else {
                break;
            }
        }

        debug_5 ( "connecting send_cmii_socket" );
        if ( connect ( send_cmii_socket, (struct sockaddr *)&send_cmii_addr,
                sizeof(send_cmii_addr) ) < 0 ) {
            strncpy ( errbuf, "connect", PCAP_ERRBUF_SIZE );
            debug_4 ( "connect: %s", strerror ( errno ) );
            if ( close( send_cmii_socket ) == -1 )
                pdie ( "close" );
            send_cmii_socket = -1;
            if ( ! content_option ) {
                debug_4 ( "connect failed, trying next ip addr" );
                continue;
            } else {
                break;
            }
        }

        debug_4 ( "connect succeeded" );
        break;
    }
    if ( send_cmii_socket < 0 ) {
        pdie ( errbuf );
    }

    freeaddrinfo(res0);

    /* allocate space for the df header */
    dfheader = Calloc(sizeof(HEADER));

    dfheader->correlationID = contentID;
    dfheader->contentId = contentID;
    dfheader->caseId = caseID;
    dfheader->iAPSystemId = iapID;
    dfheader->sequenceNumber = 0;

    debug_4 ( "begining pcap_loop" );
    pcap_loop( handle, -1, process_packet, (u_char *)dfheader );

    debug_4 ( "pcap_loop done, calling pcap_close" );
    pcap_close( handle );

    return( 0 );
}

