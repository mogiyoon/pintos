#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

/** project2-System Call */

/* Process identifier. */
typedef int pid_t;

#include <stdbool.h>


/** Project 2-Extend File Descriptor */
//  int dup2(int oldfd, int newfd);

#endif /* userprog/syscall.h */