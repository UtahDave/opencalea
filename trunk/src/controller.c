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

#include <fcntl.h>

#define MAX_CONNECTIONS 10
#define MAX_MSGSIZE 1024 

#define PROMPT "CALEA-CTRL> "

int controller_socket = 0;
struct sockaddr_in collector_addr;

int connected_flag = 0;
int batch_mode = 0;

void print_help_msg (void) {
        printf ( " Valid commands are: \n" );
        printf ( " batch-start <ip-list> <filter>\tStart a new collection process\n" );
        printf ( " batch-stop <ip-list> <batch-id>\tStop a collection process\n" );
        printf ( " connect <ip-addr>\t\tConnect to a collector\n" );
        printf ( " start <filter>\t\t\tStart a new collection process\n" );
        printf ( " status\t\t\t\tShow currently running collection processes\n" );
        printf ( " stop <pid>\t\t\tStop a collection process\n" );
        printf ( " quit\t\t\t\tQuit this session\n" );
        printf ( " help\t\t\t\tThis Message\n" );
        printf ( " \n" );
        printf ( " Examples: \n" );
        printf ( " start \"-n host 1.1.1.1\" \n");
        printf ( " batch-start \"1.1.1.1 2.2.2.2\" \"-x x -y y -z z\"\n");
        printf ( " stop 9999 \n");
}

int process_response ( char* recv_buf ) {
    int response_code = -1;

    sscanf ( recv_buf, "%d", &response_code );
    return response_code;
}

int process_user_cmd ( char* user_input, char* msgbuf ) {

    char cmd[64];
    int retval;
 
    if ( strcmp ( user_input, "\n" ) == 0 ) {
        return 0;
    }
    sscanf ( user_input, "%s", cmd );

    if ( strcmp ( cmd, "batch-start" ) == 0 ) {
        if ( controller_socket != 0 ) {
            close ( controller_socket );
        }
        batch_mode = 1;
        return 1;
    } 
    if ( strcmp ( cmd, "batch-stop" ) == 0 ) {
        if ( controller_socket != 0 ) {
            close ( controller_socket );
        }
        batch_mode = 2;
        return 1;
    } 

    if ( (strcmp ( cmd, "connect" ) != 0) && ( !connected_flag ) ) {
        printf ("you must be connected first before issuing this command...\n");
        return 0;
    }

    if ( strcmp ( cmd, "connect" ) == 0 ) {
        char *collector_ipaddr;
        collector_ipaddr = user_input + strlen ( cmd ) + 1;

        controller_socket = socket ( AF_INET, SOCK_STREAM, 0 );
        if ( controller_socket == -1 ) {
            printf ( "Error while creating server socket\n" );
            exit ( -1 );
        }
        fcntl ( controller_socket, F_SETFL, O_NONBLOCK );        

        collector_addr.sin_family = AF_INET;    
        collector_addr.sin_port = htons ( 5555 ) ;
        collector_addr.sin_addr.s_addr = inet_addr( collector_ipaddr );
 
        int i = 0;
        printf ( "Connecting." );
        fflush ( stdout );
        for ( i = 0; i < 5 ; i++ ) {
            connect ( controller_socket, 
                           (struct sockaddr*) &collector_addr, 
                           sizeof(struct sockaddr_in) );
            sleep ( 1 );
            if ( errno == EISCONN ) {
                break;
            }
            printf ( "." );
            fflush ( stdout );
        }
        printf ( "\n" );
        retval = fcntl ( controller_socket, F_SETFL, 2 );        
       
        /* if socket is already connected */
        if ( errno == EISCONN ) {
            if ( batch_mode == 0 ) {
                connected_flag = 1;
            }
            snprintf ( msgbuf, 64, "%d", CONNECT ); 
        } else {
            printf ( "connect failed...\n" );
        }
        return 1;
    } 
    if ( strcmp ( cmd, "start" ) == 0 ) {
        char *filter;
        int batch_id = 0;

        filter = user_input + strlen ( cmd ) + 1;
        snprintf ( msgbuf, 2048, "%d %d %s", TAP_START, batch_id, filter ); 
        return 1;
    } 
    if ( strcmp ( cmd, "stop" ) == 0 ) {
        int target_pid = 0;
        sscanf ( user_input, "%s %d", cmd, &target_pid );
        snprintf ( msgbuf, 64, "%d %d %d", TAP_STOP, 0, target_pid ); 
        return 1;
    } 
    if ( strcmp ( cmd, "status" ) == 0 ) {
        snprintf ( msgbuf, 64, "%d", SHOW_PROCESS_REGISTRY ); 
        return 1;
    } 
    if ( strcmp ( cmd, "quit" ) == 0 ) {
        snprintf ( msgbuf, 64, "%d", CLOSE_SESSION ); 
        return 1;
    } 
    if ( strcmp ( cmd, "exit" ) == 0 ) {
        snprintf ( msgbuf, 64, "%d", CLOSE_SESSION ); 
        return 1;
    } 
    if ( strcmp ( cmd, "help" ) == 0 ) {
        print_help_msg ( );
        return 0;
    } 
    
    return -1;
}

int main ( void ) {

    char* msgbuf;
    char* return_buf;
    char* user_input;

    printf ( "Starting client...\n" );
    srand (getpid());

    msgbuf = (char*) malloc ( 8 * MAX_MSGSIZE );
    user_input = (char*) malloc ( 8 * MAX_MSGSIZE );
    return_buf = (char*) malloc ( 2048 * 8 );
    int send_len = 0;
    int recv_len = 0;
    int retval = 0;

    /* process user commands till we exit */
    while ( 1 ) {
        printf ( "%s ", PROMPT );
        memset ( user_input, '\0', 8 * MAX_MSGSIZE );
        memset ( msgbuf, '\0', 8 * MAX_MSGSIZE );
        fgets ( user_input, 100, stdin );

        retval = process_user_cmd ( user_input, msgbuf );

        if ( batch_mode == 0 ) {
            if ( retval == 1) {
                send_len = send ( controller_socket, msgbuf, MAX_MSGSIZE, 0 );
                memset ( return_buf, '\0', 2048 );
                recv_len = recv ( controller_socket, return_buf, 2048, 0 ); 
                if ( recv_len  >  0 ) {
                    int resp_code;
                    resp_code = process_response ( return_buf );
                    if ( resp_code == atoi(QUIT) ) {
                        /* collector ACKed our request to quit */
                        break;
                    } else if ( resp_code == atoi(ACK) ) {
                        /* collector ACKed our request */
    
                    } else {
                        printf ( "%s\n", return_buf );
                    }
                }
            } else {
                /* command was not valid */
                if ( retval == -1 ) {
                    printf ( "%s ", "Invalid command\n" );
                    print_help_msg ( );
                }
            }

        } else if ( batch_mode >= 1 ) {

            char *batch_cmd;
            char *filter = NULL;
            char *f;
            char *start = NULL;
            char *str_end;
            char *tok;
            int end;
            char cmd[64];
            char my_input[2048];
            int batch_id = rand();

            sscanf ( user_input, "%s", cmd );
            batch_cmd = user_input + strlen ( cmd ) + 1;

            if ( batch_mode == 1 ) {
                /* extract the filter */
                f = strstr ( batch_cmd, " \"" );
                filter = strdup (f);
                /* shorten the string to only have the ip address list */
                f[0] = '\0';
                /* get rid of starting and ending quote characters */
                start = batch_cmd + 1;
                end = strlen ( batch_cmd ) - 1;
                batch_cmd[end] = '\0';
            } else if ( batch_mode == 2 ) {
                /* extract the batch_id */
                f = strstr ( batch_cmd, "\" " );
                f = f + 2;
                batch_id = atoi ( f );
                f[0] = '\0';
                printf ( "batch_id is: %d\n", batch_id );
                printf ( "ip list is: %s\n", batch_cmd );
                /* get rid of starting and ending quote characters */
                start = batch_cmd + 1;
                end = strlen ( batch_cmd ) - 2;
                batch_cmd[end] = '\0';
            }
   
            str_end = start + strlen ( batch_cmd );

            while (start < str_end) {
                tok = strtok ( start, " " );
                printf ("tok: %s\n", tok);
                snprintf ( my_input, 2048, "connect %s", tok );
                retval = process_user_cmd ( my_input, msgbuf );
                if ( batch_mode == 1 ) {
                    snprintf ( msgbuf, 2048, "%d %d %s", 
                               TAP_START, batch_id, filter ); 
                } else if ( batch_mode == 2 ) {
                    snprintf ( msgbuf, 2048, "%d %d %d", TAP_STOP, batch_id, 0 ); 
                }
                send_len = send ( controller_socket, msgbuf, MAX_MSGSIZE, 0 );
                snprintf ( msgbuf, 64, "%d", CLOSE_SESSION ); 
                send_len = send ( controller_socket, msgbuf, MAX_MSGSIZE, 0 );

                start = start + strlen ( tok ) + 1;
                memset ( msgbuf, '\0', 8 * MAX_MSGSIZE);
            }
            batch_mode = 0;
            connected_flag = 0;
        } 
        memset ( msgbuf, '\0', 8 * MAX_MSGSIZE);
    }

    free ( return_buf );
    free ( user_input );
    free ( msgbuf );

    close( controller_socket );

    return 0;
}

