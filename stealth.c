#include <assert.h>
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


#define RETRY_SYSCALL(exp, ret) \
    do {                        \
        ret = exp;              \
    } while (errno == EINTR)

#define PAGE_ALIGN_DOWN(val) ((val) & ~(getpagesize() - 1))

struct memory_map {
    char *addr;
    size_t size;
};

struct target_info {
    pid_t pid;
    struct memory_map local_map;
    uint64_t syscall_stub;
    const char *libpath;
};

/* System call stub */
#ifdef X86
#error "Not implemented"
#else
#define SYSCALL_NUMBER_OFFSET 1
unsigned char syscall_stub[] = {
    0xbf, 0x0, 0x0, 0x0, 0x0,              /* mov eax, 0x0 */
    0x0f, 0x05,                           /* syscall */
    0xc7, 0x04, 0x25, 0x0, 0x0, 0x0, 0x0, /* mov [0], 0 -> causes segfault that we catch */
    0x0, 0x0, 0x0, 0x0 
};
#endif
#if 0
#elif defined(ARM)
#error "Not implemented"
#elif defined (ARM64)
#error "Not implemented"
#endif

static int suspend_target(struct target_info *info)
{
    int ret = 0;

    ret = kill(info->pid, SIGSTOP);
    if (ret != 0)
        return ret;

    ret = waitpid(info->pid, NULL, WUNTRACED);
    if (ret > 0)
        ret = 0;

    return ret;
}

static int resume_target(struct target_info *info)
{
    int ret = 0;

    ret = kill(info->pid, SIGCONT);
    if (ret != 0)
        return ret;

    ret = waitpid(info->pid, NULL, WCONTINUED);
    if (ret > 0)
        ret = 0;

    return ret;
}

static int do_local_mmap(struct memory_map *map, const char *path, int prot)
{
    int ret = 0;
    int fd = -1;
    struct stat statbuf;
    void *mapping = MAP_FAILED;

    map->addr = NULL;
    map->size = 0;

    fd = open(path, O_RDONLY);
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

static int read_process_memory(pid_t pid, uint64_t address,
                               void *buf, size_t bufsize)
{
    int ret = 0;
    ssize_t bytes_read = 0;
    int fd = -1;
    off_t offset;
    char path[PATH_MAX + 1] = { 0 };

    snprintf(path, sizeof(path), "/proc/%u/mem", pid);

    RETRY_SYSCALL(open(path, O_RDWR), fd);
    if (fd == -1)
        return -errno;

    offset = lseek(fd, address, SEEK_SET);
    if (offset == -1) {
        ret = -errno;
        goto out;
    }

    if (__builtin_expect((offset != address), 0)) {
        ret = -EINVAL;
        goto out;
    }

    for (;;) {
        RETRY_SYSCALL(read(fd, (char *) buf + ret, bufsize - ret), bytes_read);
        if (bytes_read == -1) {
            ret = -errno;
            goto out;
        }

        bufsize -= bytes_read;
        ret += bytes_read;
        if (bufsize == 0 || bytes_read == 0)
            break;
    }

out:
    if (fd != -1)
        close(fd);

    return ret;
}

static int write_process_memory(pid_t pid, uint64_t address,
                                void *buf, size_t bufsize)
{
    int ret = 0;
    ssize_t bytes_written = 0;
    int fd = -1;
    off_t offset;
    char path[PATH_MAX + 1] = { 0 };

    snprintf(path, sizeof(path), "/proc/%u/mem", pid);

    RETRY_SYSCALL(open(path, O_RDWR), fd);
    if (fd == -1)
        return -errno;

    offset = lseek(fd, address, SEEK_SET);
    if (offset == -1) {
        ret = -errno;
        goto out;
    }

    if (__builtin_expect((offset != address), 0)) {
        ret = -EINVAL;
        goto out;
    }

    for (;;) {
        RETRY_SYSCALL(write(fd, (char *) buf + ret, bufsize - ret), bytes_written);
        if (bytes_written == -1) {
            ret = -errno;
            goto out;
        }

        ret += bytes_written;
        bufsize -= bytes_written;
        if (bufsize == 0 || bytes_written == 0)
            break;
    }

out:
    if (fd != -1)
        close(fd);

    return ret;}

long __do_remote_syscall(pid_t pid, uint64_t stub_address, uint32_t syscall_number,
                         uint64_t arg1, uint64_t arg2, uint64_t arg3, 
                         uint64_t arg4, uint64_t arg5, uint64_t arg6)
{
    int ret = 0;
    ssize_t written = 0;

    /* Ok, first copy the syscall number. */
    written = write_process_memory(pid, stub_address + SYSCALL_NUMBER_OFFSET,
                                   &syscall_number, sizeof(syscall_number));
    if (written < 0) {
        ret = written;
        goto out;
    }
    
    /* Now, it's time to actually modify the instruction pointer
     * and exceute the systemcall using ptrace. */

out:
    return ret;
}

long do_remote_syscall(struct target_info *info, uint32_t syscall_number, 
                       uint64_t arg1, uint64_t arg2, uint64_t arg3, 
                       uint64_t arg4, uint64_t arg5, uint64_t arg6)
{
    return __do_remote_syscall(info->pid, info->syscall_stub, syscall_number, 
                               arg1, arg2, arg3, arg4, arg5, arg6);
}

static int create_remote_syscall(struct target_info *info)
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

    /* Find the entry point of the process, and hijack memoy
     * for the system call stub */
    fd = open(exepath, O_RDONLY); 
    if (fd == -1)
        return -errno;

    bytes_read = read(fd, &header, sizeof(header));
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

    /* Now, copy the systemcall stub to the remote process
     * and actually call mmap() */
    bytes_written = write_process_memory(info->pid, entry_point, 
                                         syscall_stub, 
                                         sizeof(syscall_stub));
    if (bytes_written < 0) {
        ret = bytes_written;
        goto out;
    }


    /* Suspend the victim. */
    ret = suspend_target(info);
    if (ret != 0)  {
        goto restore;
    }

    /* Ok, let's call the actual mmap systemcall. */
    syscall_ret = __do_remote_syscall(info->pid, entry_point, SYS_mmap, 
                                      (uint64_t) NULL, getpagesize(), 
                                      PROT_READ | PROT_WRITE | PROT_EXEC,
                                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (syscall_ret < 0) {
        ret = syscall_ret;
        goto resume;
    }

    /* Ok, we've got the new location, copy the systemcall stub
     * to it and use it as our main stub. */
    bytes_written = write_process_memory(info->pid, syscall_ret, 
                                         syscall_stub, sizeof(syscall_stub));
    if (bytes_written < 0) {
        ret = bytes_written;
        goto resume;
    }

    info->syscall_stub = syscall_ret;
   
    /* OK, we're done. This was a roller-coaster! */

resume:
    (void) resume_target(info);

restore:
    (void) write_process_memory(info->pid, entry_point, 
                                orig_content, sizeof(orig_content));
out:
    if (fd != -1)
        close(fd);

    return ret;
}

static inline int init_target_info(struct target_info *info, pid_t pid,
                                   const char *libpath)
{
    int ret = 0;

    memset(info, sizeof(*info), 0);

    info->pid = pid;
    info->libpath = libpath;

    /* Locally mmap() the library file to quickly access its
     * ELF data structures */
    ret = do_local_mmap(&info->local_map, info->libpath, PROT_READ);
    if (ret != 0)
        goto out;

    /* Create a remote mmap functionality */
    ret = create_remote_syscall(info);
    if (ret != 0)
        goto out;

out:
    if (ret != 0)
        if (info->local_map.addr != 0)
            munmap(info->local_map.addr, info->local_map.size);

    return ret;
}

static inline void fini_target_info(struct target_info *info)
{
    munmap(info->local_map.addr, info->local_map.size);
}

/*
 * Load library to the remote target. This function
 * does the actual "loader" job. 
 *
 * @info: a marshaled target information structure
 */
int __load_library(struct target_info *info, const char *path)
{
    int ret = 0;

    /* Load PT_LOAD segments to the remote process. */

    /* OK, we're done loading the PT_LOAD segments, let's
     * fix the relocations and be done with it. */

    return ret;
}

int load_library(pid_t pid, const char *path)
{
    int ret = 0;
    struct target_info info = { 0 };

    if (path == NULL)
        return -EINVAL;

    /* Marshal all the needed mappings and data to keep __load_library() 
     * simple.
     */
    ret = init_target_info(&info, pid, path);
    if (ret != 0)
        return ret;

    ret = __load_library(&info, path);
    if (ret != 0)
        fini_target_info(&info);

    return ret;
}
