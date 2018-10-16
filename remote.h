/*
 * Copyright (c) Mike Bazov
 */

#ifndef __REMOTE_H__
#define __REMOTE_H__

#include <sys/user.h>
#include <sys/types.h>
#include <stdint.h>

#include "util.h"

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
uint64_t call_remote_function(struct remote_process *remote, uint64_t func_addr, ...);

/* Arch-specific external declarations */
struct function_call;
extern const unsigned char syscall_stub[];
extern const int syscall_stub_size;

/* 
 * Changes the instruction pointer to the stub address,
 * and marshal the system call arguments. 
 */
extern int marshal_syscall(pid_t pid, uint64_t stub_address, 
                           uint32_t syscall_number, uint64_t arg1, 
                           uint64_t arg2, uint64_t arg3, uint64_t arg4, 
                           uint64_t arg5, uint64_t arg6);
/* 
 * Returns the syscall return value(shocking..) 
 */
extern long syscall_return_value(pid_t pid);
/* 
 * Get a snapshot of the current remote process registers values. 
 */
extern int get_remote_regs(pid_t pid, struct user_regs_struct **regs);
/* 
 * Set the remote process registers values. 
 */
extern int set_remote_regs(pid_t pid, struct user_regs_struct *regs);
/*
 * Change the instruction pointer to the function address,
 * set the function return address, and marshal the function argumenst.
 */
extern int wind_function_call(struct remote_process *remote, uint64_t func_addr, uint64_t return_addr, 
                              struct function_call **out_call, ...);
/* 
 * Unwind whatever was winded for the function call. 
 */
extern int unwind_function_call(struct remote_process *remote, struct function_call *call);
/*
 * Get the function return value. 
 */
extern uint64_t function_return_value(pid_t pid);

#endif
