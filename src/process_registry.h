#ifndef _PROCESS_REGISTRY_H
#define _PROCESS_REGISTRY_H

typedef struct _pid_registry_entry_t {
    int valid;
    int process_id;
    char command[1024];
} pid_registry_entry_t;

#define PID_REGISTRY_ENTRY pid_registry_entry_t 
#define MAX_REGISTRY_ENTRIES 10

PID_REGISTRY_ENTRY pid_registry[MAX_REGISTRY_ENTRIES];

int pid_registry_add(int pid, char* cmd);
void pid_registry_del(int conn_id);
int pid_registry_get(int conn_id);
void pid_registry_show(char* buf);


#endif 
