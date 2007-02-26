/* Copyright Merit Network Inc. 2007 */

#ifndef _RECEIVER_H
#define _RECEIVER_H


int cmc_receiver_socket;
struct sockaddr_in cmc_receiver_addr;
int cmii_receiver_socket;
struct sockaddr_in cmii_receiver_addr;

FILE *cmii_fp;

#endif
