/* Copyright Merit Network Inc. 2007 */

#ifndef _TAP_H
#define _TAP_H

#include <time.h>

int send_cmc_socket;
struct sockaddr_in send_cmc_addr;

int send_cmii_socket;
struct sockaddr_in send_cmii_addr;

int content_option = 0;

#endif
