#ifndef __REMOTE_H__
#define __REMOTE_H__

#include <sys/types.h>
#include <stdint.h>

struct remote_process {
    pid_t pid;

    uint64_t remote_map_addr;
    uint64_t remote_map_size;
    uint64_t syscall_stub;
};

int init_remote_process(struct remote_process *info, pid_t pid);
void fini_remote_process(struct remote_process *info);

long remote_syscall(struct remote_process *info, uint32_t syscall_number, 
                    uint64_t arg1, uint64_t arg2, uint64_t arg3, 
                    uint64_t arg4, uint64_t arg5, uint64_t arg6);
int remote_mmap(struct remote_process *info, void *addr, size_t len, int prot,
                int flags, int fildes, off_t off, struct memory_map *map);
long remote_munmap(struct remote_process *info, uint64_t addr, size_t len);
long remote_open(struct remote_process *info, const char *path, int options);
long remote_close(struct remote_process *info, int remote_fd);

int write_process_memory(struct remote_process *process, uint64_t address,
                         const void *buf, size_t bufsize);
int read_process_memory(struct remote_process *process, uint64_t address,
                        void *buf, size_t bufsize);
#endif
