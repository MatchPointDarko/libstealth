/*
 * Copyright (c) Mike Bazov
 */

#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/ptrace.h>
#include <errno.h>
#include <sys/user.h>

#include "stealth.h"

#include "util.h"
#include "remote.h"

enum arg_class {
    CLASS_MEMORY,
    CLASS_INTEGER,
    CLASS_SSE
};

enum int_arg_reg {
    REG_RDI,
    REG_RSI,
    REG_RDX,
    REG_RCX,
    REG_R8,
    REG_R9,

    NARG_REGS,
};

struct function_call {
    struct user_regs_struct orig_regs;
};

const unsigned char syscall_stub[] = {
    0x0f, 0x05 /* syscall */
};

const int syscall_stub_size = sizeof(syscall_stub);

int marshal_syscall(pid_t pid, uint64_t stub_address, 
                    uint32_t syscall_number, uint64_t arg1, 
                    uint64_t arg2, uint64_t arg3, uint64_t arg4, 
                    uint64_t arg5, uint64_t arg6)
{
    int ret = 0;
    struct user_regs_struct regs;

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
    if (ret < 0)
        return -errno;

    return 0;
}

long syscall_return_value(pid_t pid)
{
    int ret = 0;
    struct user_regs_struct regs;

    ret = ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    if (ret == -1) 
        return -errno;

    return (long) regs.rax;
}

int get_remote_regs(pid_t pid, struct user_regs_struct **regs)
{
    int ret = 0;

    *regs = malloc(sizeof(**regs));
    if (*regs == NULL)
        return -ENOMEM;

    ret = ptrace(PTRACE_GETREGS, pid, NULL, *regs);
    if (ret == -1) {
        free(*regs);
        *regs = NULL;
        return -errno;
    }

    return 0;
}

int set_remote_regs(pid_t pid, struct user_regs_struct *regs)
{
    int ret = 0;

    ret = ptrace(PTRACE_SETREGS, pid, NULL, regs);
    if (ret < 0)
        return -errno;

    return 0;
}

/* TODO: Support SSE class(e.g. float) and MEMORY class (e.g. structs) */
int wind_function_call(struct remote_process *remote, uint64_t func_addr, 
                       uint64_t return_addr, struct function_call **out_call, 
                       ...)
{
    int ret = 0;
    uint64_t value = 0;
    va_list args;
    size_t args_size = 0;
    enum int_arg_reg int_arg_reg = REG_RDI; /* We start from rdi. */
    uint64_t sp = 0;
    struct function_call *call = NULL;
    struct user_regs_struct orig_regs = { 0 }, regs = { 0 };

    ret = ptrace(PTRACE_GETREGS, remote->pid, NULL, &orig_regs);
    if (ret == -1)
        return -errno;

    regs = orig_regs;
    sp = orig_regs.rsp; 

    /* We're following the x86_64 SystemV ABI. */
    va_start(args, out_call);
    for (;;) {
        enum stealth_arg_type type = va_arg(args, enum stealth_arg_type);

        /* Every argument in the AMD64 SystemV ABI is aligned to 8 bytes,
         * therefore they are all basically int64. */
        switch (type) {
        case STEALTH_ARG_INT8:
        case STEALTH_ARG_INT16:
        case STEALTH_ARG_INT32:
        case STEALTH_ARG_INT64:
            value = va_arg(args, uint64_t);
        break;
        case STEALTH_ARG_END:
            /* We're done. */
            goto reverse_stack;
        break;
        }

        if (int_arg_reg < NARG_REGS) {
            switch (int_arg_reg) {
            case REG_RDI:
                regs.rdi = value;
            break;
            case REG_RSI:
                regs.rsi = value;
            break;
            case REG_RDX:
                regs.rdx = value;
            break;
            case REG_RCX:
                regs.rcx = value;
            break;
            case REG_R8:
                regs.r8 = value;
            break;
            case REG_R9:
                regs.r9 = value;
            break;
            }

            ++int_arg_reg;
        } else {
            /* Copy the value to the stack, and decrease the SP,
             * in Intel the stack grows down. We're also assuming
             * we have enough space in the stack to not cause a stack 
             * overflow. This could be easily checked if we fetch the
             * stack bounds, but leave it as is for now... */

            sp -= sizeof(value);
            ret = write_process_memory(remote, sp, &value, sizeof(value));
            if (ret < 0)
                goto failed;
        } 
    }
    va_end(args);

reverse_stack:
    args_size = orig_regs.rsp - sp; /* Total size of the arguments on stack in bytes. */
    
    /* Reverse the stack arguments... the left most argument
     * should be also be in the lowest address on the stack. */
    for (uint64_t left_idx = sp, right_idx = sp + args_size - sizeof(uint64_t); 
         left_idx != right_idx; 
         left_idx += sizeof(uint64_t), right_idx -= sizeof(uint64_t)) {
        uint64_t left = 0, right= 0;

        ret = read_process_memory(remote, left_idx, &left, sizeof(left));
        if (ret < 0)
            goto failed;

        ret = read_process_memory(remote, right_idx, &right, sizeof(right));
        if (ret < 0)
            goto failed;

        ret = write_process_memory(remote, right_idx, &left, sizeof(left));
        if (ret < 0)
            goto failed;

        ret = write_process_memory(remote, left_idx, &right, sizeof(right));
        if (ret < 0)
            goto failed;
    }

    /* Return address is saved on the stack. */
    sp -= sizeof(return_addr);
    ret = write_process_memory(remote, sp, &return_addr, sizeof(return_addr));
    if (ret < 0)
        goto failed;

    /* If we made it here, the arguments are set, and the return address is set.
     * Time to change RIP to point to the function. */
    regs.rip = func_addr;

    ret = ptrace(PTRACE_SETREGS, remote->pid, NULL, &regs);
    if (ret == -1) {
        ret = -errno;
        goto failed;
    }
    
    call = calloc(1, sizeof(*call));
    if (call == NULL)
        goto failed;

    call->orig_regs = orig_regs;

    *out_call = call;

    return 0;
    
failed:
    if (call)
        free(call);

    (void) ptrace(PTRACE_SETREGS, remote->pid, NULL, &orig_regs);
    return ret;
}

int unwind_function_call(struct remote_process *remote, struct function_call *call)
{
    int ret = 0;

    /* We simply set the old registers back. This should restore 
     * the stack pointer as well. */
    ret = ptrace(PTRACE_SETREGS, remote->pid, NULL, call->orig_regs);
    if (ret == -1)
        return -errno;

    return 0;
}
