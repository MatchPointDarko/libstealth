#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#include "util.h"


int local_mmap(struct memory_map *map, const char *path, int prot)
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
