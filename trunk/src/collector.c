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
#include "process_registry.h"

#include <signal.h>
#include <sys/wait.h>
#include <pthread.h>
#include <glob.h>

#define MAX_CONNECTIONS 10

extern char **environ;

int get_command ( char* msgbuf ) {
    int msg_id;
    sscanf ( msgbuf, "%d", &msg_id );
    return msg_id ;
}

int get_target_pid ( char* msgbuf ) {
    int msg_id, target_pid, batch_id;
    sscanf ( msgbuf, "%d %d %d", &msg_id, &batch_id, &target_pid );
    return target_pid;
}

int get_batch_id ( char* msgbuf ) {
    int msg_id, target_pid, batch_id;
    sscanf ( msgbuf, "%d %d %d", &msg_id, &batch_id, &target_pid );
    return batch_id;
}

void* reply ( void* args, uint reply_code ) {
    int *handler_socket;
    char* buf;

    if (! ( buf = (char*) malloc ( 128 ) ) ) {
       perror("malloc");
       exit ( -1 );
    }
    memset ( buf, '\0', 128 );
    snprintf ( buf, 128, "%u", reply_code );
    printf( "about to send: %s\n", buf);

    handler_socket = ( int* ) args;
    if ( (send( *handler_socket, buf, strlen( buf ), 0 )) == -1 ) {
        perror("send");
        exit (-1);
    }

    free ( buf );
    return ( NULL );
}

void* controller_thread ( void* args ) {
    int recv_len;
    char *msg_buf;
    int *handler_socket;
    int msg_id = 0;
    int pid = 0;
    int target_pid = 0;

    handler_socket = ( int* ) args;
    char* return_buf;
    int send_len = 0;
    if (! ( return_buf = (char*) malloc ( MAX_MSGSIZE ) ) ) {
       perror("malloc");
        exit ( -1 );
    }
    if (! ( msg_buf = (char*) malloc ( MAX_MSGSIZE ) ) ) {
       perror("malloc");
        exit ( -1 );
    }

    while ( 1 ) {

        memset ( msg_buf, '\0', MAX_MSGSIZE );
        memset ( return_buf, '\0', MAX_MSGSIZE );

        if ( (recv_len = recv ( *handler_socket, msg_buf, MAX_MSGSIZE - 1, 0 )) == -1 )
            if ( errno != EAGAIN ) {
                perror("recv");
                exit (-1);
            }

        if ( recv_len > 0 ) {

            msg_id = get_command ( msg_buf );
            switch ( msg_id ) {
                case TAP_START:
                    printf ( "start...\n" );
                    char *f;

                    /* send an ACK for the start command */
                    reply ( handler_socket, ACK );

                    /* extract the batch-id  */ 
                    int batch_id = 0;
                    batch_id = get_batch_id ( msg_buf );

                    /* extract the filter from the start command */
                    char *filter;
                    int len = 0;
                    printf ( "the msg is: %s\n", msg_buf );
                    if ( (f = strstr ( msg_buf, " \"" )) == NULL ) {
                        printf ( "syntax error: filter not found\n" );
                        break;
                    }
                    if (! ( filter = (char*) malloc ( MAX_MSGSIZE ) ) ) {
                       perror("malloc");
                        exit ( -1 );
                    }
                    memset ( filter, '\0', MAX_MSGSIZE );
                    memcpy ( filter, f+2, MAX_MSGSIZE - (f+2 - msg_buf) );

                    len = strlen ( filter );
                    filter[len-2] = '\0'; 
                    printf ( "the filter is: %s\n", filter );

                    /* ignore signals temporarily before we fork 
                       we re-enable them on the child process only */
 
                    signal ( SIGCHLD, SIG_IGN );
                    signal ( SIGUSR1, SIG_IGN );

                    pid = fork( );

                    if ( pid == 0 ) {

                        /* this is the child process re-enable signals */
                        signal ( SIGUSR1, SIG_DFL );

                        /* get the arguments with which to run the tap */
                        char* argv[32];
                        char item[64];
                        char filter_item[1024];
                        int filter_start = 0 ;
                        pid = getpid ( );
                        argv[0] = strdup ( "tap" );
                        argv[1] = strdup ( "-i" );
                        argv[2] = strdup ( CAPTURE_IF );
                        int n = 2;
                        char* iter = filter;
                        while ( iter < filter + strlen ( filter ) ) {
                            n++;
                            sscanf ( iter, "%s", item );
                            if ( strncmp ( item , "\"", 1 ) == 0 ) {
                                if ( filter_start == 0 ) {
                                    n--;
                                    filter_start = 1;
                                } else {
                                    /* end of filter */
                                    printf ( "filter_item: %s\n", filter_item );
                                    argv[n] = strdup ( filter_item );
                                    memset ( filter_item , '\0', 1024 );
                                }
                            } else {
                                if ( filter_start == 0 ) {
                                    argv[n] = strdup ( item );
                                } else {
                                    n--;
                                    strcat ( filter_item, " " ); 
                                    strcat ( filter_item, item ); 
                                }
                            }
                            iter = iter + strlen ( item ) + 1;
                        }
                        argv[n+1] = NULL;
                        free ( filter );
                         
                        /* run the tap program with the correct args */
                        printf ( "attempting to run tap...\n" );
                        execv ( TAP, argv );

                        exit( 0 );

                    } else {
                        /* if this is the parent process we register 
                           the child 
                           attempt to validate whether the process 
                           actually started correctly first
                        */
                        int retval = 0;
                        sleep ( 1 );
                        retval = kill ( pid, 0 );
                        if ( retval == 0 ) {
                            /* process exists */
                            char cmd[1024];
                            sprintf ( cmd, "%s %s %s %s", TAP, "-i", 
                                      CAPTURE_IF, filter );
                            free ( filter );
                            pid_registry_add ( batch_id, pid, cmd );
                            syslog ( LOG_ALERT, 
                                "starting monitoring session with pid: %d and filter: %s", pid, filter ); 
                        } else {
                            syslog ( LOG_ALERT, 
                                "tap process did not start correctly...\n");
                        }
                    }                    
                    break;
                case TAP_STOP:
                    printf ( "stop...\n" );
                  
                    /* send an ACK for the stop command */
                    reply ( handler_socket, ACK );

                    /* get batch_id */
                    batch_id = get_batch_id ( msg_buf );
                    
                    if ( batch_id == 0 ) {
                        /* this is a stop command */
                        /* extract the pid which we want to stop */
                        target_pid = get_target_pid ( msg_buf );
                        if ( pid_validate ( target_pid ) == 0 ) {
                            /* pid was not in our process registry */
                            break;
                        }
                        int retval = 0;

                        /* send kill signal to the tap pid and make
                           sure it actually died */

                        if ( target_pid != 0 ) {
                            syslog ( LOG_ALERT, 
                                 "stoping monitoring session %d", target_pid ); 
                            retval = kill ( target_pid, SIGUSR1 ); 
                            if ( retval == 0 ) {
                                /* the kill worked */
                                pid_registry_del ( target_pid );
                            } else {
                                /* unable to kill the process */
                            }
                        } else {
                            /* killing with pid zero will kill all processes 
                               in the same process group so dont do it */
                        }

                    } else {
                        /* batch stop: we lookup all pid for this batch id 
                           and stop them all */
                        int pid_list[128];
                        int i = 0;
                        int retval = 0;
                        printf ( "looking up pids...\n");
                        pid_batch_id_lookup ( batch_id, (int*) &pid_list );
                        for ( i = 0; i <= 128; i++ ) { 
                            printf ( "killing pids... %d\n", pid_list[i]);
                            syslog ( LOG_ALERT, 
                                 "stoping monitoring session %d", target_pid ); 
                            if ( pid_list[i] != 0 ) {
                                retval = kill ( pid_list[i], SIGUSR1 );
                                if ( retval == 0 ) {
                                    /* the kill worked */
                                    pid_registry_del ( pid_list[i] );
                                } else {
                                    /* unable to kill the process */
                                }
                            }
                        } 
                      
                    }
                    break;
                case SHOW_PROCESS_REGISTRY:
                    printf ( "show...\n" );
                    memset ( return_buf, '\0', MAX_MSGSIZE );
                    pid_registry_show ( return_buf );
                    send_len = send ( *handler_socket, return_buf, 
                                      strlen ( return_buf ), 0 );
                    break;
                case CLOSE_SESSION:
                    printf ( "close...\n" );
                    reply ( handler_socket, QUIT );
                    close ( *handler_socket );
                    pthread_exit( NULL );
                    exit(-1);
                    break;
                case CONNECT:
                    printf ( "connect...\n" );
                    memset ( return_buf, '\0', MAX_MSGSIZE );
                    reply ( handler_socket, ACK );
                    break;
                case PING:
                    printf ( "ping...\n" );
                    reply ( handler_socket, ACK );
                    break;
                case NOP:
                    printf ( "nop ...\n" );
                    reply ( handler_socket, ACK );
                    break;
                default:
                    printf ( "command code not valid\n" ); 
                    reply ( handler_socket, ACK );
                    break;
            }
        }

    }
    free ( msg_buf );
    free ( return_buf );
    return ( NULL );
}


int main ( void ) {

    int s;
    int handler_socket;;
    struct sockaddr_in myaddr;
    socklen_t myaddrlen;
    int retval = 0;
    int errno;

    printf ( "Starting server...\n" );
 
    s = socket ( AF_INET, SOCK_STREAM, 0 );

    if ( s == -1 ) {
        printf ( "Error while creating server socket\n" );
        exit ( -1 );
    }

    memset ( (char *) &myaddr, 0, sizeof(myaddr) );
    myaddr.sin_family = AF_INET;
    myaddr.sin_port = htons( Collector_PORT );
    myaddr.sin_addr.s_addr = htonl ( INADDR_ANY );

    myaddrlen = sizeof( struct sockaddr_in );
    retval = bind ( s, (struct sockaddr*) &myaddr, sizeof(myaddr) );
    if ( retval == -1 ) {
        perror ( "Error while binding socket" );
        exit ( -1 );
    }

    syslog ( LOG_ALERT, "Starting CALEA Collector...\n" );
    listen ( s, MAX_CONNECTIONS );

    myaddrlen = sizeof( struct sockaddr_in );

    while ( 1 ) {
        handler_socket = accept( s, (struct sockaddr*) &myaddr, &myaddrlen );
        if ( handler_socket == -1 ) {
            printf ( "Error while accepting client connection\n" );
            exit ( -1 );
        }
        pthread_t ctrl_thread;
        pthread_create ( &ctrl_thread, NULL, controller_thread, &handler_socket );
    }
    return 0;
}
