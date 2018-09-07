#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <elf.h>
#include <stdio.h>
#include <sys/utsname.h>

#include "util.h"
#include "remote.h"


struct memory_map_node {
    struct memory_map_node *next;
    struct memory_map map;
};

struct library {
    const char *path;
    struct memory_map_nodes *maps;
};

int load_remote_segments32(struct remote_process *tracee, Elf32_Ehdr *header)
{
    /* TODO */
    return -ENOSYS;
}

/* Loads PT_LOAD program headers into the tracee. 
 *
 * @tracee: the tracee object.
 * @remote_fd: a remote file descriptor that represent the library we're loading.
 * @header: a pointer to a localy memory mapping of the library we're loading.
 *
 * return how many segments were loaded. or <0 on failure. */
int load_remote_segments64(struct remote_process *tracee, int remote_fd, Elf64_Ehdr *header,
                           struct memory_map_node **out_head)
{
    int ret = 0, segments = 0;
    int prot = 0;
    Elf64_Phdr *program_header = NULL;    
    size_t num_phdrs = 0;
    size_t size;
    uint64_t offset;
    uint64_t base = 0, vaddr = 0;
    struct memory_map_node *head = NULL;
    struct memory_map_node *node = NULL;
    struct memory_map remote_map;

    program_header = (Elf64_Phdr *) ((char *) header + header->e_phoff);
    num_phdrs = header->e_phnum;

    for (; num_phdrs--; ++program_header) {
        if (program_header->p_type != PT_LOAD)
            continue;

        size = program_header->p_memsz;
        if (size == 0)
            continue;

        /* Segment protection. */
        prot |= program_header->p_flags & PF_W ? PROT_WRITE : 0;
        prot |= program_header->p_flags & PF_R ? PROT_READ : 0;
        prot |= program_header->p_flags & PF_X ? PROT_EXEC : 0;

        /* Offset in the file. */
        offset = program_header->p_offset;

        vaddr = program_header->p_vaddr;
        vaddr += base; 

        /* Let's align to page boundary. */
        size += vaddr - PAGE_ALIGN_DOWN(vaddr);
        offset -= vaddr - PAGE_ALIGN_DOWN(vaddr);
        size = PAGE_ALIGN(size);
        vaddr = PAGE_ALIGN_DOWN(vaddr);

        /* Do the remote mmap. */
        ret = remote_mmap(tracee, (void *) vaddr, size, prot,
                          MAP_PRIVATE, remote_fd, offset, &remote_map);
        if (ret != 0)
            goto out;

        if (base == 0)
            /* If we haven't got any base yet we can safely assume
             * the first mmapped region is the lowest one. */
            base = (uint64_t) remote_map.addr;

        /* Push this mapping to a list to gracefully cleanup
         * in case we've failed. we never leave leftovers in the tracee. */
        node = malloc(sizeof(*head));
        if (node == NULL) {
            ret = -ENOMEM;
            goto out;
        }

        node->map = remote_map;
        node->next = head;
        head = node;

        ++segments;
    }

    ret = segments;
out:
    /* Cleanup the list if we've failed. */
    while (head) {
        if (ret < 0)
            /* if we've failed, unmap the mapping. */
            remote_munmap(tracee, (uint64_t) head->map.addr, 
                          head->map.size);

        node = head->next;
        free(head);
        head = node;
    }

    return ret;
}

/* Return the running machine type in Elf format. */
static uint16_t get_machine_type(void)
{
    int ret;
    int length = 0;
    struct utsname utsname;

    ret = uname(&utsname);
    if (ret == -1)
        return -errno;

    length = strlen(utsname.machine);

    if (strncmp("x86_64", utsname.machine, length) == 0) {
        return EM_X86_64;
    } else {
        /* Unsupported.. */
        return -EINVAL;
    }
}

/* Make sure the locally memory mapped library 
 * answers all the requirements. */
static bool validate_elf(Elf64_Ehdr *header)
{
    int machine_type;

    /* Must be an ELF. */
    if (header->e_ident[EI_MAG0] != 0x7f || 
        strncmp(&header->e_ident[EI_MAG1], "ELF", 3) != 0)
        return false;

    /* Must be a shared object. */
    if (header->e_type != ET_DYN)
        return false;

    machine_type = get_machine_type();
    if (machine_type < 0)
        return false;

    /* Machine type must be the same as the machine
     * type we're running on. */
    if (header->e_machine != machine_type)
        return false;

    return true;
}

/*
 * Load library to the remote target. This function
 * does the actual "loader" job. 
 *
 */
int __load_library(struct remote_process *info, const char *path, 
                   struct library **out_library)
{
    int ret = 0;
    int remote_fd = 0;
    void *remote_map = NULL;
    size_t remote_map_size = 0;
    struct memory_map map;
    Elf64_Ehdr *header = NULL;
    struct memory_map_node *head = NULL;

    *out_library = NULL;

    ret = local_mmap(&map, path, PROT_READ);
    if (ret != 0)
        return ret;

    remote_fd = remote_open(info, path, O_RDWR);
    if (remote_fd < 0) {
        ret = remote_fd;
        remote_fd = 0;
        goto out;
    }

    header = (Elf64_Ehdr *) map.addr;
    if (!validate_elf(header)) {
        ret = -EINVAL;
        goto out;
    }

    /* Load all PT_LOAD segments into the remote process. */
    switch (header->e_ident[EI_CLASS]) {
    case 1: /* 32 bit */
        ret = load_remote_segments32(info, (Elf32_Ehdr *) header);
        break;
    case 2: /* 64 bit */
        ret = load_remote_segments64(info, remote_fd, header, &head);
        break;
    default:
        ret = -EINVAL;
        break;
    }

    if (ret <= 0) {
        ret = ret == 0 ? -EINVAL : ret;
        goto out;
    }

    /* TODO: Now, after we've mapped all the loadable segments, fix
     * the relocations. */

    /* TODO: Call init functions. */

    /* We're good to go. */
out:
    if (remote_fd)
        remote_close(info, remote_fd);

    if (map.addr)
        munmap(map.addr, map.size);

    if (ret < 0) {
        /* TODO: If we've failed... we must 
         * unload all the libraries we loaded.. */
    }

    return ret;
}

int load_library(pid_t pid, const char *path, struct library **out_library)
{
    int ret = 0;
    struct remote_process info = { 0 };
    struct library *library = NULL;

    if (path == NULL)
        return -EINVAL;

    /* Create a tracee instance for this PID, to be able
     * to call systemcalls remotely. */
    ret = init_remote_process(&info, pid);
    if (ret != 0)
        return ret;

    ret = __load_library(&info, path, &library);
out:
    //TODO
    //if (ret && library)
        //__unload_library(library);
        
    fini_remote_process(&info);

    return ret;
}

int main(int argc, char **argv)
{
    struct library *library;

    if (argc < 2) {
        printf("stealth <pid>\n");
        return -1;
    }

    load_library(atoi(argv[1]), "/home/mike/foo.so", &library);

    return 0;
}
