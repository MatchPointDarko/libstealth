#include <assert.h>
#include <stdbool.h>
#include <sys/types.h>
#include <signal.h>
#include <stdint.h>
#include <limits.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <elf.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>


#define unlikely(x) __builtin_expect((x), 0)
#define RETRY_SYSCALL(exp, ret) \
    do {                        \
        ret = exp;              \
    } while (errno == EINTR)

#define PAGE_ALIGN_DOWN(val) ((val) & ~(getpagesize() - 1))

struct memory_map {
    char *addr;
    size_t size;
};

struct tracee {
    pid_t pid;
    uint64_t remote_map_addr;
    uint64_t remote_map_size;
    uint64_t syscall_stub;
};

/* System call stub currently __x86_64 only__. */
unsigned char syscall_stub[] = {
    0x0f, 0x05 /* syscall */
};

static int do_local_mmap(struct memory_map *map, const char *path, int prot)
{
    int ret = 0;
    int fd = -1;
    struct stat statbuf;
    void *mapping = MAP_FAILED;

    map->addr = NULL;
    map->size = 0;

    RETRY_SYSCALL(open(path, O_RDONLY), fd);
    if (fd == -1) {
        ret = -errno;
        goto out;
    }

    ret = fstat(fd, &statbuf);
    if (ret != 0) {
        ret = -errno;
        goto out;
    }

    mapping = mmap(NULL, statbuf.st_size, prot, MAP_PRIVATE, fd, 0);
    if (mapping == MAP_FAILED) {
        ret = -errno;
        goto out;
    }

    map->addr = mapping;
    map->size = statbuf.st_size;

out:
    if (fd != -1)
        close(fd);

    if (ret != 0)
        if (mapping != MAP_FAILED)
            munmap(mapping, statbuf.st_size);

    return ret;
}

/*
 * Assumes the tracee is in a trace-stop state(suspended)
 */
static int read_process_memory(pid_t pid, uint64_t address,
                               void *buf, size_t bufsize)
{
    int read = 0;
    long data = 0;

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
static int write_process_memory(pid_t pid, uint64_t address,
                                const void *buf, size_t bufsize)
{
    int ret = 0;
    int written = 0;
    long data;

    while (bufsize) {
        if (bufsize < sizeof(data)) {
            data = 0;

            /* First get the original data, to override only what
             * we actually need. */
            ret = read_process_memory(pid, address + written, 
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
long __do_remote_syscall(pid_t pid,
                         uint64_t stub_address, uint32_t syscall_number,
                         uint64_t arg1, uint64_t arg2, uint64_t arg3, 
                         uint64_t arg4, uint64_t arg5, uint64_t arg6)
{
    long ret = 0;
    int status = 0;
    ssize_t written = 0;
    struct user_regs_struct orig_regs;
    struct user_regs_struct regs;
    int bytes_read;

    ret = ptrace(PTRACE_GETREGS, pid, NULL, &orig_regs);
    if (ret == -1) {
        ret = -errno;
        goto out;
    }

    regs = orig_regs;

    /* TODO: Make this portable. */

    /* syscall number */
    regs.rax = syscall_number;

    /* Modify the instruction pointer to point to the stub address. */
    regs.rip = stub_address;

    /* arguments */
    regs.rdi = arg1;
    regs.rsi = arg2;
    regs.rdx = arg3;
    regs.r10 = arg4;
    regs.r8 = arg5;
    regs.r9 = arg6;

    ret = ptrace(PTRACE_SETREGS, pid, NULL, &regs);
    if (ret == -1) {
        ret = -errno;
        goto out;
    }

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
                 * this is not expected. */
                ret = -EINVAL;
                goto restore_regs;
            }

            /* Nice.. let's collect the syscall return value and be 
             * done with it. */
            ret = ptrace(PTRACE_GETREGS, pid, NULL, &regs);
            if (ret == -1) {
                ret = -errno;
                goto restore_regs;
            }

            ret = regs.rax;
            break;
        }
    }

restore_regs:
    (void) ptrace(PTRACE_SETREGS, pid, NULL, &orig_regs);
out:
    return ret;
}

long do_remote_syscall(struct tracee *info, uint32_t syscall_number, 
                       uint64_t arg1, uint64_t arg2, uint64_t arg3, 
                       uint64_t arg4, uint64_t arg5, uint64_t arg6)
{
    return __do_remote_syscall(info->pid, info->syscall_stub, syscall_number, 
                               arg1, arg2, arg3, arg4, arg5, arg6);
}

void *do_remote_mmap(struct tracee *info, void *addr, size_t len, int prot,
                     int flags, int fildes, off_t off)
{
    return (void *) do_remote_syscall(info, SYS_mmap, (uint64_t) addr, len, 
                                      prot, flags, fildes, off);
}

long do_remote_munmap(struct tracee *info, uint64_t addr, size_t len)
{
    return do_remote_syscall(info, SYS_munmap, (uint64_t) addr, len, 0, 0, 0, 0);
}

long do_remote_open(struct tracee *info, const char *path, int options)
{
    long ret = 0;

    /* We need to copy the path to the available location. */
    if (strlen(path) > info->remote_map_size)
        return -ENOMEM;

    ret = write_process_memory(info->pid, info->remote_map_addr, 
                              path, strlen(path) + 1);
    if (ret < 0)
        return ret;

    return do_remote_syscall(info, SYS_open, info->remote_map_addr, options, 0, 0, 0, 0);
}

long do_remote_close(struct tracee *info, int remote_fd)
{
    return do_remote_syscall(info, SYS_close, remote_fd, 0, 0, 0, 0, 0);
}

static int create_remote_syscall(struct tracee *info)
{
    int ret = 0, fd = -1;
    long syscall_ret = 0;
    ssize_t bytes_read = 0;
    ssize_t bytes_written = 0;
    char path[PATH_MAX + 1] = { 0 };
    char exepath[PATH_MAX + 1] = { 0 };
    Elf64_Ehdr header;
    uint64_t entry_point = 0;
    uint8_t orig_content[sizeof(syscall_stub)];

    /* Copy the syscall stub, and call mmap() to create a remote
     * dispatch stub */
    snprintf(path, sizeof(path), "/proc/%u/exe", info->pid);

    bytes_read = readlink(path, exepath, sizeof(exepath));
    if (bytes_read == -1)
        return -errno;

    /* There is __no__ way we can't find a systemcall stub within
     * the process. A process without a systemcall instruction 
     * is useless. You must interact with the kernel. Let's locate
     * it. */

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

    if (bytes_read < sizeof(header)) {
        /* Hmm... this is weird. */
        ret = -EBADFD;
        goto out;
    }

    /* Align the entry point to page boundary */
    entry_point = (uint64_t) PAGE_ALIGN_DOWN(header.e_entry);

    /* Make sure to backup the memory */
    bytes_read = read_process_memory(info->pid, entry_point, 
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
    bytes_written = write_process_memory(info->pid, entry_point, 
                                         syscall_stub, 
                                         sizeof(syscall_stub));
    if (bytes_written < 0) {
        ret = bytes_written;
        goto out;
    }

    /* Ok, let's call the actual mmap systemcall. */
    syscall_ret = __do_remote_syscall(info->pid, entry_point, SYS_mmap, 
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
     * we changed it)*/
    bytes_written = write_process_memory(info->pid, syscall_ret, 
                                         syscall_stub, sizeof(syscall_stub));
    if (bytes_written < 0) {
        ret = bytes_written;
        goto restore;
    }

    info->syscall_stub = syscall_ret;
    info->remote_map_addr = info->syscall_stub + sizeof(syscall_stub);
    info->remote_map_size = getpagesize() - sizeof(syscall_stub);

restore:
    (void) write_process_memory(info->pid, entry_point, 
                                orig_content, sizeof(orig_content));
out:
    if (fd != -1)
        close(fd);

    return ret;
}

static inline int init_tracee(struct tracee *info, pid_t pid,
                                   const char *libpath)
{
    int ret = 0;
    int wstatus;

    memset(info, sizeof(*info), 0);

    info->pid = pid;

    /* We must attach as a tracer to be able to use
     * waitpid() */
    ret = ptrace(PTRACE_ATTACH, pid, 0, 0);
    if (ret == -1)
        return -errno;

    ret = create_remote_syscall(info);
    if (ret != 0)
        goto out;

out:
    if (ret != 0)
        ptrace(PTRACE_DETACH, info->pid, 0, 0);

    return ret;
}

static void fini_tracee(struct tracee *info)
{
    if (info->syscall_stub)
        do_remote_munmap(info, info->syscall_stub, getpagesize());

    ptrace(PTRACE_DETACH, info->pid, 0, 0);
}

/*
 * Load library to the remote target. This function
 * does the actual "loader" job. 
 *
 * @info: a marshaled target information structure
 *
 * This function assumes the tracee is in trace-stop state(suspended).
 */
int __load_library(struct tracee *info, const char *path)
{
    int ret = 0;
    int remote_fd = 0;
    void *remote_map = NULL;
    size_t remote_map_size = 0;
    struct memory_map map;

    /* Load PT_LOAD segments to the remote process. */
    ret = do_local_mmap(&map, path, PROT_READ);
    if (ret != 0)
        return ret;

    /* Let's load the PT_LOAD segments into the remote process. */
    remote_fd = do_remote_open(info, path, O_RDWR);
    if (remote_fd < 0) {
        ret = remote_fd;
        remote_fd = 0;
        goto out;
    }

    /* OK, now let's iterate on the segment array and load PT_LOAD
     * segments. */
out:
    if (remote_fd)
        do_remote_close(info, remote_fd);

    if (map.addr)
        munmap(map.addr, map.size);
    return ret;
}

int load_library(pid_t pid, const char *path)
{
    int ret = 0;
    struct tracee info = { 0 };

    if (path == NULL)
        return -EINVAL;

    /* Marshal all the needed mappings and data to keep __load_library() 
     * simple.
     */
    ret = init_tracee(&info, pid, path);
    if (ret != 0)
        return ret;

    ret = __load_library(&info, path);

    fini_tracee(&info);

    return ret;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        printf("stealth <pid>\n");
        return -1;
    }

    load_library(atoi(argv[1]), "/home/mike/foo.so");

    return 0;
}
