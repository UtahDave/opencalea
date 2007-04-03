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

int pid_registry_add ( int batch_id, int pid, char* cmd ) {
    int i=0;
    int add_complete = 0;

    for ( i = 0; i < MAX_REGISTRY_ENTRIES; i++ ) {
        if ( pid_registry[i].valid == 0 ) {
            pid_registry[i].valid = 1;
            pid_registry[i].process_id = pid;
            pid_registry[i].batch_id = batch_id;
            strncpy ( pid_registry[i].command, cmd, 1024 ); 
            add_complete = 1;
            break;
        } else {
            /* registry slot is taken */
        }
    }
    return add_complete;
}

void pid_registry_del ( int target_pid ) {
    int i = 0;

    for ( i = 0; i < MAX_REGISTRY_ENTRIES; i++ ) {
        if ( pid_registry[i].process_id == target_pid ) {
           pid_registry[i].valid = 0;
           pid_registry[i].process_id = 0;
        }
    } 
}

void pid_registry_show ( char* buf ) {
    int i = 0;

    printf ("in registry show...\n" );    
    sprintf ( buf, "BATCH-ID\t\tPID:\tCOLLECTOR COMMAND:\n" );    
    for ( i = 0; i < MAX_REGISTRY_ENTRIES; i++ ) {
        if ( pid_registry[i].valid == 1) {
               sprintf ( buf, 
               "%s%d\t\t%d\t%s\n", buf, pid_registry[i].batch_id,
               pid_registry[i].process_id, pid_registry[i].command );
               printf ( 
               "valid: %d --- process id: %d\n", 
               pid_registry[i].valid, 
               pid_registry[i].process_id );;
        } else {
            /* entry not valid */
        }
    } 
    return ;
}

void pid_batch_id_lookup ( int batch_id, int* pid_list ) {

    int i = 0;
    int j = 0;
    if ( batch_id != 0 ) {
        for ( i = 0; i < MAX_REGISTRY_ENTRIES; i++ ) {
            if ( pid_registry[i].valid == 1) {
                if ( pid_registry[i].batch_id == batch_id ) {
                    pid_list[j] = pid_registry[i].process_id;
                    j++;
                }
            } else {
                /* entry not valid */
            }
        }  
    } else {
        /* should we allow people to batch-stop with id of 0 */
    }
}


/* make sure that a given pid is in the process registry */
int pid_validate ( int pid ) {

    int i = 0;
    int retval = 0;

    for ( i = 0; i < MAX_REGISTRY_ENTRIES; i++ ) {
        if ( pid_registry[i].valid == 1) {
               if ( pid == pid_registry[i].process_id ) {
                   retval = 1;
                   break;
               }
        } else {
            /* entry not valid */
        }
    } 
    return retval;
}



