#ifndef _CALEA_COMMON_H
#define _CALEA_COMMON_H

#include <syslog.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#define TAP "./tap"
#define CAPTURE_IF "en1"


/* valid command codes */
#define TAP_START              1
#define TAP_STOP               2 
#define SHOW_PROCESS_REGISTRY  3 
#define CLOSE_SESSION          4 
#define CONNECT                5
#define ACK "0"
#define QUIT "1"

#endif
