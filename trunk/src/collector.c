#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <pthread.h>
#include <glob.h>

#include "process_registry.h"
#include "common.h"

#define MAX_CONNECTIONS 10
#define MAX_MSGSIZE 1024 

extern char **environ;

int get_command ( char* msgbuf ) {
    int msg_id;
    sscanf ( msgbuf, "%d", &msg_id );
    return msg_id;
}

int get_target_pid ( char* msgbuf ) {
    int msg_id, target_pid;
    sscanf ( msgbuf, "%d %d", &msg_id, &target_pid );
    return target_pid;
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
    return_buf = (char*) malloc ( 2048 * 8 ); 
    msg_buf = (char*) malloc ( 2048 * 8 ); 

    while ( 1 ) {

        memset ( msg_buf, '\0', 2048 * 8 );
        memset ( return_buf, '\0', 2048 * 8 );

        recv_len = recv ( *handler_socket, msg_buf, 2048, 0 ); 

        if ( recv_len > 0 ) {

            msg_id = get_command ( msg_buf );

            switch ( msg_id ) {
                case TAP_START:
                    printf ( "start...\n" );

                    /* send an ACK for the start command */ 
                    send( *handler_socket, ACK, MAX_MSGSIZE, 0 );

                    /* extract the filter from the start command */
                    char *filter;
                    int len = 0;
                    filter = (char*) malloc ( sizeof(char) * 2048 );
                    memcpy ( filter, msg_buf+3, 2048 );
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
                        pid = getpid ( );
                        argv[0] = strdup ( "tap" );
                        argv[1] = strdup ( "-i" );
                        argv[2] = strdup ( CAPTURE_IF );
                        int n = 2;
                        char* iter = filter;
                        while ( iter < filter + strlen ( filter ) ) {
                            n++;
                            sscanf ( iter, "%s", item );
                            argv[n] = strdup ( item );
                            iter = iter + strlen ( item ) + 1;
                        }
                        argv[n+1] = NULL;
                        free ( filter );

                        /* run the tap program with the correct args */
                        execv ( TAP, argv );

                        exit( 0 );

                    } else {
                        /* if this is the parent process we register 
                           the child */
                        /* we really should check to make sure the exec 
                           was okay before we register something...
                        */
                        char cmd[1024];
                        sprintf ( cmd, "%s %s %s %s", TAP, "-i", 
                                  CAPTURE_IF, filter );
                        free ( filter );
                        pid_registry_add ( pid, cmd );
                        syslog ( LOG_ALERT, 
                            "starting monitoring session with pid: %d and filter: %s", pid, filter ); 
                    }                    
                    break;
                case TAP_STOP:
                    printf ( "stop...\n" );

                    /* send an ACK for the stop command */
                    send( *handler_socket, ACK, MAX_MSGSIZE, 0 );

                    /* extract the pid which we want to stop */
                    target_pid = get_target_pid ( msg_buf );
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
                    break;
                case SHOW_PROCESS_REGISTRY:
                    printf ( "show...\n" );
                    memset ( return_buf, '\0', 2048 * 8 );
                    pid_registry_show ( return_buf );
                    send_len = send ( *handler_socket, return_buf, 
                                      MAX_MSGSIZE, 0 );
                    break;
                case CLOSE_SESSION:
                    printf ( "close...\n" );
                    send( *handler_socket, QUIT, MAX_MSGSIZE, 0 );
                    close ( *handler_socket );
                    pthread_exit( NULL );
                    break;
                case CONNECT:
                    printf ( "connect...\n" );
                    memset ( return_buf, '\0', 2048 * 8 );
                    send ( *handler_socket, "0", MAX_MSGSIZE, 0 );
                    break;
                default:
                    printf ( "command code not valid\n" ); 
                    send ( *handler_socket, ACK, MAX_MSGSIZE, 0 );
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
    myaddr.sin_port = htons( 5555 );
    myaddr.sin_addr.s_addr = htonl ( INADDR_ANY );

    myaddrlen = sizeof( struct sockaddr_in );
    retval = bind ( s, (struct sockaddr*) &myaddr, sizeof(myaddr) );
    if ( retval == -1 ) {
        printf ( "Error while bindingsocket\n" );
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
