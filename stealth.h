/*
 * Copyright (c) Mike Bazov
 */

#ifndef __STEALTH_H__
#define __STEALTH_H__

#include <unistd.h>

enum stealth_arg_type {
    STEALTH_ARG_INT8,
    STEALTH_ARG_INT16,
    STEALTH_ARG_INT32,
    STEALTH_ARG_INT64,

    STEALTH_ARG_END
};

struct dyn_library;

/* 
 * Load an ELF shared object into the remote process address space.
 * The behavior is similar to dlopen(...), except the library is loaded
 * remotely.
 *
 * @pid: pid of one of the remote threads.
 * @path: path of the library.
 * @out_library: a pointer to a dynamic library object.
 *
 * Returns a negative errno value in case of a failure, or 0
 * on success.
 */
int stealth_load_library(pid_t pid, const char *path, 
                         struct dyn_library **out_library);
/*
 * Unload a previosuly loaded library.
 * 
 * @library: a previously loaded library.
 *
 * Returns a negative errno value in case of a failure, or 0
 * on success.
 */
int stealth_unload_library(struct dyn_library *library);
/*
 * Call a function in the remote process.
 *
 * @pid: pid of one of the remote threads.
 * @func_addr: virtual address of the function to call.
 * ...: a list of function arguments.
 *
 * Returns a negative errno(cast it to signed) value in case of a failure, 
 * or the actual remote function return value.
 */
uint64_t stealth_call_remote_function(pid_t pid, uint64_t func_addr, 
                                      ...);

#endif
