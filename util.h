#ifndef __UTIL_H__
#define __UTIL_H__

#define unlikely(x) __builtin_expect((x), 0)
#define RETRY_SYSCALL(exp, ret) \
    do {                        \
        ret = exp;              \
    } while (errno == EINTR)

#define PAGE_ALIGN_DOWN(val) ((val) & ~(getpagesize() - 1))
#define PAGE_ALIGN(val) (PAGE_ALIGN_DOWN(val) + getpagesize())

struct memory_map {
    char *addr;
    size_t size;
};

int local_mmap(struct memory_map *map, const char *path, int prot);

#endif
