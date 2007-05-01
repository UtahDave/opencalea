/*
 * Copyright (c) 2007 Norman Brandinger <norm@goes.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "common.h"
#include "msg.h"
#include "calea.h"

ssize_t tcp_read(int fd, void *buf, size_t tot_len);
void usage (void);

char *prog_name       = "df_collector";
int   syslog_facility = DEF_SYSLOG_FACILITY;

FILE *CmII_fp = NULL;
FILE *CmC_fp  = NULL;
char *cmc_file = NULL;
char *cmii_file = NULL;
int   cmc_port  = 0;
int   cmii_port = 0;

char *bindaddr = NULL;

int change_user = 0;
int change_group = 0;
struct passwd *pwent;
struct group *grent;
char user[32] = DEF_USER;
char group[32] = DEF_GROUP;

int log_level_set = 0;
int debug_level_set = 0;
char *debug_file_name = NULL;
char *log_file_name = NULL;

void parse_commandline(int argc, char *argv[]) {

    int i=0;

    /* command line options processing */
    while (( i = getopt ( argc, argv, "t:f:b:hm:n:u:g:vD:l:L:" )) != -1 ) {

        switch ( i ) {
            case 'f':   // CmC file
                if ( ( cmc_file = strdup ( optarg ) ) == NULL )
                    pdie ( "strdup" );
                debug_5 ( "got opt %c: %s", i, optarg );
                break;
            case 't':   // CmII file
                if ( ( cmii_file = strdup ( optarg ) ) == NULL )
                    pdie ( "strdup" );
                debug_5 ( "got opt %c: %s", i, optarg );
                break;
            case 'b':   // address to bind sure
                if ( ( bindaddr = strdup ( optarg ) ) == NULL )
                    pdie ( "strdup" );
                debug_5 ( "got opt %c: %s", i, optarg );
                break;
            case 'u':   // username
                strncpy ( (char *)user, optarg, 31 );
                debug_5 ( "got opt %c: %s", i, optarg );
                change_user = 1;
                break;
            case 'g':   // group name
                strncpy ( &group[0], optarg, 31 );
                debug_5 ( "got opt %c: %s", i, optarg );
                change_group = 1;
                break;
           case 'm':   // cmc port
                cmc_port = atoi ( optarg );
                debug_5 ( "got opt %c: %s", i, optarg );
                break;
            case 'n':   // cmii port
                 cmii_port = atoi ( optarg );
                debug_5 ( "got opt %c: %s", i, optarg );
                break;
            case 'v':   // debug ('d' was taken)
                debug_level_set++;
                debug_5 ( "got opt %c, debug level now %d",
                    i, debug_level_set );
                break;
            case 'D':   // debug file
                if ( ( debug_file_name = strdup ( optarg ) ) == NULL )
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
                if ( ( log_file_name = strdup ( optarg ) ) == NULL )
                    pdie ( "strdup" );
                debug_5 ( "got opt %c: %s", i, optarg );
                break;
            case 'h':   // help
                usage();
                exit ( 0 );
            default:
                usage ();
                exit ( 1 );
        }
    }

    if ( cmii_file == NULL ) {
        usage();
        die ( "CmII file not specified (need -f)." );
    }

    /* drop privs if running as root or told to do so */
    if ( ((uid_t)geteuid() == 0) || change_user ) {
        debug_5 ( "changing userid to: %s", user );
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
    if ( ((uid_t)geteuid() == 0) || change_group ) {
        debug_5 ( "changing group id to: %s", group );
        errno = 0;
        if (! (grent = getgrnam(group)) ) {
            if (errno) {
                pdie ( "getgrnam" );
            } else {
                die ( "Group %s not found\n", group );
            }
        }
        if (setgid(grent->gr_gid) < 0)
            pdie ( "setgid" );
    }

    if ( cmii_port == 0 ) {
        cmii_port = CmII_PORT;
        debug_5 ( "df_collector: Using default CmII listener port (%d)", cmii_port );
    }

    if ( cmc_port == 0 ) {
        cmc_port = CmC_PORT;
        debug_5 ( "df_collector: Using default CmC listener port (%d)", cmc_port );
    }


    return;

}

void df_process_msg(Msg *msg, int n) {
	size_t msg_len;
	size_t ret;
	msg_len = sizeof(Msg);

	debug_5("Message Size: %d", n);
        print_hex((const u_char *)msg, msg_len);
        print_hex((const u_char *)((char *)msg + msg_len), msg->msgh.msglen);

        switch(msg->msgh.msgtype) {
        	case MSGTYPE_NONE:
                	debug_5("df_collector: MSGTYPE_NONE uninitialized or not present");
                        break;
                case MSGTYPE_CONTROL:
                        debug_5("df_collector: MSGTYPE_CONTROL OpenCALEA Control message");
                        break;
                case MSGTYPE_LOG:
                        debug_5("df_collector: MSGTYPE_LOG Surveillance Log message");
                        break;
                case MSGTYPE_CMII:
                        debug_5("df_collector: MSGTYPE_CMII Communications Identifying Information message");
			ret = fwrite(((char *)msg + msg_len),  msg->msgh.msglen, 1, CmII_fp);
			if (ret != 1) {
                          debug_5("df_collector: error writing to CmII file");
			}
                        break;
                case MSGTYPE_CII:
                        debug_5("df_collector: MSGTYPE_CII Call Identifying Information message");
                        break;
                case MSGTYPE_CMC:
                        debug_5("df_collector: MSGTYPE_CMC Communications Content message");
			if (cmc_file == NULL) {
                        	debug_5("df_collector: Warning CmC capture file not available");
			} else {
				ret = fwrite(((char *)msg + msg_len),  msg->msgh.msglen, 1, CmC_fp);
				if (ret != 1) {
                          	debug_5("df_collector: error writing to CmC file");
				}
			}
                        break;
                case MSGTYPE_CC:
                        debug_5("df_collector: MSGTYPE_CC Call Content message");
                        break;
                default:
                        debug_5("df_collector: Unknown MSGTYPE detected");
                        break;
                }

        switch(msg->msgh.format) {
		case MSGFMT_NONE:
                	debug_5("df_collector: MSGFMT_NONE uninitialized or not present");
                        break;
		case MSGFMT_C:
                	debug_5("df_collector: MSGFMT_C C structure");
                        break;
		case MSGFMT_XML:
                	debug_5("df_collector: MSGFMT_XML eXtensible Markup Language");
                        break;
		case MSGFMT_BER:
                	debug_5("df_collector: MSGFMT_BER Basic Encoding Rules");
                        break;
		case MSGFMT_TXT:
                	debug_5("df_collector: MSGFMT_TXT Plain Text");
                        break;
		case MSGFMT_CSV:
                	debug_5("df_collector: MSGFMT_CSV Comma Seperated Values");
                        break;
		case MSGFMT_IAS_D31:
                	debug_5("df_collector: MSGFMT_IAS_D31 IAS section D.3.1 CmC in UDP Encapsulation");
                        break;
		case MSGFMT_IAS_D32:
                	debug_5("df_collector: MSGFMT_IAS_D32 IAS section D.3.2 CmC in IC-APDU's");
                        break;
		default:
                	debug_5("df_collector: Unknown MSGFMT detected");
                        break;
		}
	
	return;
}

void usage ( void ) {

    printf ( "Usage: df_collector -t cmii-capture-file " );
    printf ( "[-f cmc-capture-file] " );
    printf ( "[-b bind-addr] " );
    printf ( "[-u user] [-g group] " );
    printf ( " [-m cmc-port] [-n cmii-port] [-x]" );
    printf ( " [-v [...]] [-D debug-file]" );
    printf ( " [-l log-level ] [-L logfile]" );
    printf ( "\n" );


}

int main ( int argc, char *argv[] ) {

	int	i, maxi, maxfd, connfd, sockfd;
	int	CmII_tcpfd, CmC_tcpfd;
	int	CmII_udpfd, CmC_udpfd;
	int	controlfd;
	int	nready, client[FD_SETSIZE];
	ssize_t n;
	fd_set	rset, allset;

	char buf[MAX_MSGSIZE];
	const int on = 1;
	socklen_t	len, clilen;
	struct sockaddr_in cliaddr, servaddr;

	setdebug( 5, "stdout", 1 );

	parse_commandline(argc, argv);

	/************************************/
	/* Open the CmII file pointer       */
	/************************************/
	if (cmii_file) {
		if (!(CmII_fp = fopen(cmii_file , "wb"))) {
			debug_5("df_collector: CmII_fp open failed for %s", cmii_file);
			pdie("df_collector: CmII_fp fopen");
		}
	}

	/************************************/
	/* Open the CmC file pointer        */
	/************************************/
	if (cmc_file) {
		if (!(CmC_fp = fopen(cmc_file , "wb"))) {
			debug_5("df_collector: CmC_fp open failed for %s", cmc_file);
			pdie("df_collector: CmC_fp fopen");
		}
	}

	/************************************/
	/* Create CmII TCP listening socket */
	/************************************/

	CmII_tcpfd = socket(AF_INET, SOCK_STREAM, 0);
	
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(cmii_port);

	setsockopt(CmII_tcpfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	bind(CmII_tcpfd, (struct sockaddr *) &servaddr, sizeof(servaddr));

	listen(CmII_tcpfd, 10);

	/***********************************/
	/* Create CmC TCP listening socket */
	/***********************************/

	CmC_tcpfd = socket(AF_INET, SOCK_STREAM, 0);
	
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(cmc_port);

	setsockopt(CmC_tcpfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	bind(CmC_tcpfd, (struct sockaddr *) &servaddr, sizeof(servaddr));

	listen(CmC_tcpfd, 10);

        /*****************************/
        /* Create control UDP socket */
        /*****************************/

        controlfd = socket(AF_INET, SOCK_DGRAM, 0);

        bzero(&servaddr, sizeof(servaddr));
        servaddr.sin_family = AF_INET;
        servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
        servaddr.sin_port = htons(DF_CONTROL_PORT);

        bind(controlfd, (struct sockaddr *) &servaddr, sizeof(servaddr));
	
	/**************************/
	/* Create CmII UDP socket */
	/**************************/

	CmII_udpfd = socket(AF_INET, SOCK_DGRAM, 0);

	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(cmii_port);

	bind(CmII_udpfd, (struct sockaddr *) &servaddr, sizeof(servaddr));
	
	/*************************/
	/* Create CmC UDP socket */
	/*************************/

	CmC_udpfd = socket(AF_INET, SOCK_DGRAM, 0);

	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(cmc_port);

	bind(CmC_udpfd, (struct sockaddr *) &servaddr, sizeof(servaddr));

	/********************************************************************/

	maxi = -1;		/* index into client[] array */
	for (i=0; i<FD_SETSIZE; i++) {
		client[i] = -1;	/* -1 indicates and empty slot in the client[] array */
	}

	FD_ZERO(&allset);

	FD_SET(CmII_tcpfd, &allset);
	FD_SET(CmII_udpfd, &allset);
	FD_SET(CmC_tcpfd,  &allset);
	FD_SET(CmC_udpfd,  &allset);
	FD_SET(controlfd,  &allset);

	/* initialize the maximum file desctiptor for the select() */
	maxfd = max(CmII_tcpfd, CmII_udpfd);
	maxfd = max(maxfd, CmC_udpfd);		
	maxfd = max(maxfd, CmC_tcpfd);		

	for (;;) {
		rset = allset;	/* initialize */
		if ( (nready = select(maxfd+1, &rset, NULL, NULL, NULL)) < 0) {
			if (errno == EINTR)
				continue;
			else {
				debug_5("df_collector: select error", 1);
				return -1;
			}
		}

		/* CmII TCP socket ready to receive data */
		if (FD_ISSET(CmII_tcpfd, &rset)) {	/* new client connection */

			clilen = sizeof(cliaddr);
			connfd = accept(CmII_tcpfd, (struct sockaddr *) &cliaddr, &clilen);

			for (i=0; i<FD_SETSIZE; i++) { 
				if (client[i] < 0) {
					client[i] = connfd;	/* save descriptor */
					break;
				}
			}

			if (i == FD_SETSIZE) {
				debug_5("Too many clients", 1);
			}

			FD_SET(connfd, &allset);		/* add new descriptor to the set */

			if (connfd > maxfd)
				maxfd = connfd;

			if (i > maxi)
				maxi = i;			/* max index in client[] array */

			if (--nready <= 0)
				continue;			/* no more readable descriptors */

		}			

		/* check control UDP socket for data */	
		if (FD_ISSET(controlfd, &rset)) {
			len = sizeof(cliaddr);
			n = recvfrom(controlfd, buf, MAX_MSGSIZE, 0, (struct sockaddr *) &cliaddr, &len);
			df_process_msg((Msg *)buf, n);
		}

		/* check CmII UDP socket for data */	
		if (FD_ISSET(CmII_udpfd, &rset)) {
			len = sizeof(cliaddr);
			n = recvfrom(CmII_udpfd, buf, MAX_MSGSIZE, 0, (struct sockaddr *) &cliaddr, &len);
			df_process_msg((Msg *)buf, n);
		}

		/* check CmC UDP socket for data */	
		if (FD_ISSET(CmC_udpfd, &rset)) {
			len = sizeof(cliaddr);
			n = recvfrom(CmC_udpfd, buf, MAX_MSGSIZE, 0, (struct sockaddr *) &cliaddr, &len);
			df_process_msg((Msg *)buf, n);
		}

		/* check TCP clients for data */
		for (i=0; i<= maxi; i++) {
			if ((sockfd = client[i]) < 0)
				continue;
			if (FD_ISSET(sockfd, &rset)) {

				if ((n=tcp_read(sockfd, buf, MAX_MSGSIZE)) == 0) {
					/* conneciton closed by client */
					close(sockfd);
					FD_CLR(sockfd, &allset);
					client[i] = -1;
				} else {
					df_process_msg((Msg *)buf, n);
				}

				if (--nready <= 0)
					break;			/* no more readable descriptors */
			}
		}

	}
	return 0;
}
