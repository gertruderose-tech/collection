#define _GNU_SOURCE
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>

// Global state for tracking memfds
static int memfd_count = 0;
static char *output_dir = "/tmp/memfd_extraction";
static FILE *log_file = NULL;

// Original function pointers
static int (*original_memfd_create)(const char *name, unsigned int flags) = NULL;
static ssize_t (*original_write)(int fd, const void *buf, size_t count) = NULL;
static int (*original_close)(int fd) = NULL;

// Track memfd info
#define MAX_MEMFDS 100
struct memfd_info {
    int fd;
    char name[256];
    char dump_path[512];
    int dump_fd;
    size_t total_written;
} tracked_memfds[MAX_MEMFDS];

static void init_hook(void) __attribute__((constructor));
static void cleanup_hook(void) __attribute__((destructor));

static void init_hook(void) {
    // Create output directory
    mkdir(output_dir, 0755);
    
    // Open log file
    char log_path[512];
    snprintf(log_path, sizeof(log_path), "%s/memfd_hook.log", output_dir);
    log_file = fopen(log_path, "w");
    if (log_file) {
        fprintf(log_file, "MemFD Hook initialized\n");
        fflush(log_file);
    }
    
    // Get original function pointers
    original_memfd_create = dlsym(RTLD_NEXT, "memfd_create");
    original_write = dlsym(RTLD_NEXT, "write");
    original_close = dlsym(RTLD_NEXT, "close");
    
    if (!original_memfd_create || !original_write || !original_close) {
        if (log_file) {
            fprintf(log_file, "ERROR: Failed to get original function pointers\n");
            fflush(log_file);
        }
    }
    
    // Initialize tracking array
    memset(tracked_memfds, 0, sizeof(tracked_memfds));
}

static void cleanup_hook(void) {
    if (log_file) {
        fprintf(log_file, "MemFD Hook cleanup\n");
        fclose(log_file);
    }
    
    // Close any remaining dump files
    for (int i = 0; i < memfd_count && i < MAX_MEMFDS; i++) {
        if (tracked_memfds[i].dump_fd > 0) {
            close(tracked_memfds[i].dump_fd);
        }
    }
}

static int find_memfd_slot(int fd) {
    for (int i = 0; i < memfd_count && i < MAX_MEMFDS; i++) {
        if (tracked_memfds[i].fd == fd) {
            return i;
        }
    }
    return -1;
}

// Hook memfd_create
int memfd_create(const char *name, unsigned int flags) {
    if (!original_memfd_create) {
        // Direct syscall fallback
        return syscall(SYS_memfd_create, name, flags);
    }
    
    int fd = original_memfd_create(name, flags);
    
    if (fd >= 0 && memfd_count < MAX_MEMFDS) {
        // Track this memfd
        int slot = memfd_count++;
        tracked_memfds[slot].fd = fd;
        strncpy(tracked_memfds[slot].name, name ? name : "unnamed", sizeof(tracked_memfds[slot].name) - 1);
        
        // Create dump file
        snprintf(tracked_memfds[slot].dump_path, sizeof(tracked_memfds[slot].dump_path),
                "%s/memfd_%d_%s.dump", output_dir, fd, tracked_memfds[slot].name);
        
        tracked_memfds[slot].dump_fd = open(tracked_memfds[slot].dump_path, 
                                           O_CREAT | O_WRONLY | O_TRUNC, 0644);
        tracked_memfds[slot].total_written = 0;
        
        if (log_file) {
            fprintf(log_file, "MEMFD_CREATE: fd=%d, name='%s', flags=%u, dump_path='%s'\n", 
                   fd, name, flags, tracked_memfds[slot].dump_path);
            fflush(log_file);
        }
    }
    
    return fd;
}

// Hook write
ssize_t write(int fd, const void *buf, size_t count) {
    if (!original_write) {
        return syscall(SYS_write, fd, buf, count);
    }
    
    ssize_t result = original_write(fd, buf, count);
    
    // Check if this is a write to a tracked memfd
    int slot = find_memfd_slot(fd);
    if (slot >= 0 && result > 0) {
        // Duplicate the write to our dump file
        if (tracked_memfds[slot].dump_fd > 0) {
            ssize_t dump_result = original_write(tracked_memfds[slot].dump_fd, buf, result);
            if (dump_result > 0) {
                tracked_memfds[slot].total_written += dump_result;
            }
        }
        
        if (log_file) {
            fprintf(log_file, "WRITE to memfd %d ('%s'): %zd bytes, total: %zu\n", 
                   fd, tracked_memfds[slot].name, result, tracked_memfds[slot].total_written);
            
            // Log first few bytes for debugging
            if (count > 0 && buf) {
                fprintf(log_file, "  First bytes: ");
                const unsigned char *bytes = (const unsigned char *)buf;
                for (size_t i = 0; i < (count < 32 ? count : 32); i++) {
                    fprintf(log_file, "%02x ", bytes[i]);
                }
                fprintf(log_file, "\n");
            }
            fflush(log_file);
        }
    }
    
    return result;
}

// Hook close
int close(int fd) {
    if (!original_close) {
        return syscall(SYS_close, fd);
    }
    
    // Check if this is a tracked memfd being closed
    int slot = find_memfd_slot(fd);
    if (slot >= 0) {
        if (log_file) {
            fprintf(log_file, "CLOSE memfd %d ('%s'): total written %zu bytes\n", 
                   fd, tracked_memfds[slot].name, tracked_memfds[slot].total_written);
            fflush(log_file);
        }
        
        // Close our dump file
        if (tracked_memfds[slot].dump_fd > 0) {
            original_close(tracked_memfds[slot].dump_fd);
            tracked_memfds[slot].dump_fd = -1;
        }
        
        // Clear the slot
        tracked_memfds[slot].fd = -1;
    }
    
    return original_close(fd);
}