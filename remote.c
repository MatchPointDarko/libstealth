/*
 * Copyright (c) Mike Bazov
 */

#include <limits.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <elf.h>
#include <stdio.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/ptrace.h>

#include "util.h"
#include "remote.h"
#include "stealth.h"

/*
 * Assumes the tracee is in a trace-stop state(suspended)
 */
int read_process_memory(struct remote_process *process, uint64_t address,
                        void *buf, size_t bufsize)
{
    int read = 0;
    long data = 0;
    pid_t pid;

    pid = process->pid;

    /* If the buffer is not word-aligned, the remaining bytes
     * are zeroed. */
    while (bufsize) {
        data = ptrace(PTRACE_PEEKTEXT, pid, address + read, 0);
        if (data == -1)
            return -errno;

        if (bufsize < sizeof(data)) {
            memcpy((char *) buf + read, &data, bufsize);
            read += bufsize;
            bufsize = 0;
        } else {
            *(long *)((char *) buf + read) = data;
            read += sizeof(data);
            bufsize -= sizeof(data);
        }
    }

    return read;
}

/*
 * Assumes the tracee is in a trace-stop state(suspended)
 */
int write_process_memory(struct remote_process *process, uint64_t address,
                         const void *buf, size_t bufsize)
{
    int ret = 0;
    int written = 0;
    long data;
    pid_t pid;

    pid = process->pid;
    
    while (bufsize) {
        if (bufsize < sizeof(data)) {
            data = 0;

            /* First get the original data, to override only what
             * we actually need. */
            ret = read_process_memory(process, address + written, 
                                      &data, sizeof(data));
            if (ret < 0)
                return ret;

            memcpy(&data, (char *) buf + written, bufsize);
        } else {
            data = *(long *)((char *) buf + written);
        }

        ret = ptrace(PTRACE_POKETEXT, pid, address + written, data);
        if (ret == -1)
            return -errno;

        written += bufsize < sizeof(data) ? bufsize : sizeof(data);
        bufsize -= bufsize < sizeof(data) ? bufsize : sizeof(data);
    }

    return written;
}

/*
 * Execute a remote systemcall using the systemcall stub address.
 * This function assumes the tracee is suspended!
 */
static long do_remote_syscall(pid_t pid,
                              uint64_t stub_address, uint32_t syscall_number,
                              uint64_t arg1, uint64_t arg2, uint64_t arg3, 
                              uint64_t arg4, uint64_t arg5, uint64_t arg6)
{
    long ret = 0;
    int status = 0;
    struct user_regs_struct *orig_regs = NULL;

    ret = ptrace(PTRACE_GETREGS, pid, NULL, &orig_regs);
    if (ret == -1) {
        ret = -errno;
        goto out;
    }

    ret = get_remote_regs(pid, &orig_regs);
    if (ret < 0)
        goto out;

    ret = marshal_syscall(pid, stub_address, syscall_number, 
                          arg1, arg2, arg3, arg4, arg5, arg6);
    if (ret < 0)
        goto out;

    /* Now we have the remote thread pointing to our stub. 
     * Let it execute and catch the SIGTRAP in the end. */
    ret = ptrace(PTRACE_SINGLESTEP, pid);
    if (ret == -1) {
        ret = -errno;
        goto restore_regs;
    }

    for (;;) {
        ret = waitpid(pid, &status, 0);
        if (ret == -1) {
            ret = -errno;
            goto restore_regs;
        }

        /* Check if the reason we've returned is SIGTRAP . */
        if (WIFSTOPPED(status)) {
            /* Validate this is indeed a SIGTRAP. */
            if (unlikely(WSTOPSIG(status) != SIGTRAP)) {
                /* Hmmmm...  someone else stopped it? anyhow,
                 * this is not expected... */
                ret = -EINVAL;
                goto restore_regs;
            }

            /* Nice.. let's collect the syscall return value and be 
             * done with it. */
            ret = syscall_return_value(pid);

            /* We're now in signal-delivery-stop. Supress the SIGTRAP
             * signal by issuing a ptrace restart. */
            break;
        }
    }

restore_regs:
    set_remote_regs(pid, orig_regs);
    free(orig_regs);
out:
    return ret;
}

long remote_syscall(struct remote_process *info, uint32_t syscall_number, 
                    uint64_t arg1, uint64_t arg2, uint64_t arg3, 
                    uint64_t arg4, uint64_t arg5, uint64_t arg6)
{
    return do_remote_syscall(info->pid, info->syscall_stub, syscall_number, 
                             arg1, arg2, arg3, arg4, arg5, arg6);
}

int remote_mmap(struct remote_process *info, void *addr, size_t len, int prot,
                int flags, int fildes, off_t off, struct memory_map *map)
{
    long ret = 0;

    map->addr = NULL;
    map->size = 0;

    ret = remote_syscall(info, SYS_mmap, (uint64_t) addr, len, 
                         prot, flags, fildes, off);
    if (ret < 0)
        return ret;

    map->addr = (char *) ret;
    map->size = len;

    return 0;
}

long remote_munmap(struct remote_process *info, uint64_t addr, size_t len)
{
    return remote_syscall(info, SYS_munmap, (uint64_t) addr,
                          len, 0, 0, 0, 0);
}

long remote_open(struct remote_process *info, const char *path, int options)
{
    long ret = 0;

    /* We need to copy the path to the available location. */
    if (unlikely(strlen(path) > info->remote_map_size))
        return -ENOMEM;

    ret = write_process_memory(info, info->remote_map_addr, 
                               path, strlen(path) + 1);
    if (ret < 0)
        return ret;

    RETRY_SYSCALL(remote_syscall(info, SYS_open, info->remote_map_addr, 
                                 options, 0, 0, 0, 0), ret);

    return ret;
}

long remote_close(struct remote_process *info, int remote_fd)
{
    return remote_syscall(info, SYS_close, remote_fd, 0, 0, 0, 0, 0);
}

static int create_remote_syscall(struct remote_process *info)
{
    int ret = 0, fd = -1;
    long syscall_ret = 0;
    ssize_t bytes_read = 0;
    ssize_t bytes_written = 0;
    char path[PATH_MAX + 1] = { 0 };
    char exepath[PATH_MAX + 1] = { 0 };
    Elf64_Ehdr header;
    uint64_t entry_point = 0;
    uint8_t orig_content[syscall_stub_size];

    /* Copy the syscall stub, and call mmap() to create a remote
     * dispatch stub */
    snprintf(path, sizeof(path), "/proc/%u/exe", info->pid);

    bytes_read = readlink(path, exepath, sizeof(exepath));
    if (bytes_read == -1)
        return -errno;

    /* Find the entry point of the process, and hijack memoy
     * for the system call stub */
    RETRY_SYSCALL(open(exepath, O_RDONLY), fd);
    if (fd == -1)
        return -errno;

    RETRY_SYSCALL(read(fd, &header, sizeof(header)), bytes_read);
    if (bytes_read == -1) {
        ret = -errno;
        goto out;
    }

    if ((size_t) bytes_read < sizeof(header)) {
        /* Hmm... this is weird. */
        ret = -EBADFD;
        goto out;
    }

    /* Align the entry point to page boundary */
    entry_point = (uint64_t) PAGE_ALIGN_DOWN(header.e_entry);

    /* Make sure to backup the memory */
    bytes_read = read_process_memory(info, entry_point, 
                                     orig_content, 
                                     sizeof(orig_content));
    if (bytes_read < 0) {
        ret = bytes_read;
        goto out;
    }

    /* 
     * Now, copy the systemcall stub to the remote process
     * and actually call mmap() 
     *
     * XXX: Sadly, we currently assume no other thread is executing
     * the memory we're copying to, but this surely is a problem
     * we need to deal with.. although we do prepare the ground for it
     * by relocating the systemcall stub and restoring the original memory.
     * To the TODO list!
     */
    bytes_written = write_process_memory(info, entry_point, 
                                         syscall_stub, 
                                         syscall_stub_size);
    if (bytes_written < 0) {
        ret = bytes_written;
        goto out;
    }

    /* Ok, let's call the actual mmap systemcall. */
    syscall_ret = do_remote_syscall(info->pid, entry_point, SYS_mmap, 
                                    (uint64_t) NULL, getpagesize(), 
                                    PROT_READ | PROT_WRITE | PROT_EXEC,
                                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (syscall_ret < 0) {
        ret = syscall_ret;
        goto restore;
    }

    /* Ok, we've got the new location, copy the systemcall stub
     * to it and use it as our main stub(ground preparation for 
     * dealing with multithreaded programs that execute code while
     * we changed it) */
    bytes_written = write_process_memory(info, syscall_ret, 
                                         syscall_stub, syscall_stub_size);
    if (bytes_written < 0) {
        ret = bytes_written;
        goto restore;
    }

    info->syscall_stub = syscall_ret;
    info->remote_map_addr = info->syscall_stub + syscall_stub_size;
    info->remote_map_size = getpagesize() - syscall_stub_size;

restore:
    (void) write_process_memory(info, entry_point, 
                                orig_content, sizeof(orig_content));
out:
    if (fd != -1)
        close(fd);

    return ret;
}

int init_remote_process(struct remote_process *info, pid_t pid)
{
    int ret = 0;

    memset(info, 0, sizeof(*info));

    info->pid = pid;

    ret = ptrace(PTRACE_ATTACH, pid, 0, 0);
    if (ret == -1)
        return -errno;

    ret = waitpid(pid, NULL, 0);
    if (ret == -1) {
        ret = -errno;
        goto out;
    }

    ret = create_remote_syscall(info);
    if (ret != 0)
        goto out;

out:
    if (ret != 0) {
        (void) ptrace(PTRACE_DETACH, pid, 0, 0);
        (void) waitpid(pid, NULL, 0);
    }

    return ret;
}

void fini_remote_process(struct remote_process *info)
{
    if (info->syscall_stub)
        remote_munmap(info, info->syscall_stub, getpagesize());

    (void) ptrace(PTRACE_DETACH, info->pid, 0, 0);
    (void) waitpid(info->pid, NULL, 0);
}

uint64_t call_remote_function(struct remote_process *remote, uint64_t func_addr, ...)
{
    uint64_t ret = 0;
    int err = 0;
    int status;
    va_list args;
    struct function_call *call = NULL;

    va_start(args, func_addr);
    err = wind_function_call(remote, func_addr, 0, &call, args);
    va_end(args);
    if (err < 0) {
        ret = (uint64_t) err;
        goto out;
    }

    /* OK.. continue. */
    err = ptrace(PTRACE_CONT, remote->pid, NULL, NULL);
    if (err < 0) {
        ret = (uint64_t) err; 
        goto unwind;
    }

    /* Wait and catch a SIGSEGV. */
    for (;;) {
        err = waitpid(remote->pid, &status, 0);
        if (err == -1) {
            ret = (uint64_t) -errno;
            goto unwind;
        }

        /* Check if the reason we've returned is SIGSEGV. */
        if (WIFSTOPPED(status)) {
            /* Validate this is indeed a SIGSEGV . */
            if (unlikely(WSTOPSIG(status) != SIGSEGV)) {
                /* Hmmmm...  someone else stopped it? anyhow,
                 * this is not expected. */
                ret = (uint64_t) -EINVAL;
                goto unwind;
            }

            /* Nice.. let's collect the syscall return value and be 
             * done with it. We're assuming this is indeed our SIGSEGV, 
             * and not the program's... if it is indeed the program's, 
             * it's a bug and we don't care. */
            err = function_return_value(remote->pid);
            ret = (uint64_t) err;

            /* We're now in signal-delivery-stop. Supress the SIGSEGV
             * signal by issuing a ptrace restart. */
            break;
        }
    }

unwind:
    (void) unwind_function_call(remote, call);
    free(call);
out:
    return ret;
}

uint64_t stealth_call_remote_function(pid_t pid, uint64_t func_addr, ...)
{
    int ret = 0;
    va_list args;
    struct remote_process remote = { 0 };

    ret = init_remote_process(&remote, pid);
    if (ret < 0)
        return ret;

    va_start(args, func_addr);
    ret = call_remote_function(&remote, func_addr, args);
    va_end(args);

    fini_remote_process(&remote);

    return ret;
}
