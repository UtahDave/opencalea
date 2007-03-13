#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "process_registry.h"

int pid_registry_add(int pid, char* cmd) {
    int i=0;
    int add_complete = 0;

    for (i=0; i < MAX_REGISTRY_ENTRIES; i++) {
        if ( pid_registry[i].valid == 0) {
            pid_registry[i].valid = 1;
            pid_registry[i].process_id = pid;
            strncpy(pid_registry[i].command, cmd, 1024 ); 
            add_complete = 1;
            break;
        } else {
            /* registry slot is taken */
        }
    }
    return add_complete;
}

void pid_registry_del(int target_pid) {
    int i = 0;

    for (i=0; i < MAX_REGISTRY_ENTRIES; i++) {
        if ( pid_registry[i].process_id == target_pid) {
           pid_registry[i].valid = 0;
           pid_registry[i].process_id = 0;
        }
    } 
}

void pid_registry_show(char* buf) {
    int i = 0;

    printf ("in registry show...\n" );    
    sprintf ( buf, "PID:\tCOLLECTOR COMMAND:\n" );    
    for (i=0; i < MAX_REGISTRY_ENTRIES; i++) {
        if ( pid_registry[i].valid == 1) {
               sprintf ( buf, 
               "%s%d\t%s\n", buf,
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


