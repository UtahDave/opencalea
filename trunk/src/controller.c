#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>

#include "common.h"

#define MAX_CONNECTIONS 10
#define MAX_MSGSIZE 1024 

#define PROMPT "CALEA-CTRL> "

int controller_socket = 0;
struct sockaddr_in collector_addr;

int connected_flag = 0;

void print_help_msg (void) {
        printf ( " Valid commands are: \n" );
        printf ( " connect <ip-addr>\tConnect to a collector\n" );
        printf ( " start <filter>\t\tStart a new collection process\n" );
        printf ( " status\t\t\tShow currently running collection processes\n" );
        printf ( " stop <pid>\t\tStop a collection process\n" );
        printf ( " quit\t\t\tQuit this session\n" );
        printf ( " help\t\t\tThis Message\n" );
        printf ( " \n" );
        printf ( " Examples: \n" );
        printf ( " start \"-n host 1.1.1.1\" \n");
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

    if ( (strcmp ( cmd, "connect" ) != 0) && ( !connected_flag ) ) {
        printf ("you must be connected first before issuing this command...\n");
    }

    if ( strcmp ( cmd, "connect" ) == 0 ) {
        char *collector_ipaddr;
        collector_ipaddr = user_input + strlen ( cmd ) + 1;
        printf ( "connect cmd: %s", collector_ipaddr ); 

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
            connected_flag = 1;
            snprintf ( msgbuf, 64, "%d", CONNECT ); 
        } else {
            printf ( "connect failed..." );
        }
        return 1;
    } 

    if ( strcmp ( cmd, "start" ) == 0 ) {
        char *filter;
        filter = user_input + strlen ( cmd ) + 1;
        snprintf ( msgbuf, 2048, "%d %s", TAP_START, filter ); 
        return 1;
    } 
    if ( strcmp ( cmd, "stop" ) == 0 ) {
        int target_pid = 0;
        sscanf ( user_input, "%s %d", cmd, &target_pid );
        snprintf ( msgbuf, 64, "%d %d", TAP_STOP, target_pid ); 
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

    //int s = 0;
    //struct sockaddr_in myaddr;
    char* msgbuf;
    char* return_buf;
    char* user_input;

    printf ( "Starting client...\n" );

/*    s = socket ( AF_INET, SOCK_STREAM, 0 );

    if ( s == -1 ) {
        printf ( "Error while creating server socket\n" );
        exit ( -1 );
    }

    myaddr.sin_family = AF_INET;    
    myaddr.sin_port = htons ( 5555 ) ;
    myaddr.sin_addr.s_addr = inet_addr( "127.0.0.1" );

    connect ( s, (struct sockaddr*) &myaddr, sizeof(struct sockaddr_in) );

*/
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
        memset ( msgbuf, '\0', 8 * MAX_MSGSIZE);
    }

    free ( return_buf );
    free ( user_input );
    free ( msgbuf );

    close( controller_socket );

    return 0;
}

