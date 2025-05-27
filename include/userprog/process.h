#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_create_initd (const char *file_name);
tid_t process_fork (const char *name, struct intr_frame *if_);
int process_exec (void *f_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (struct thread *next);
/* Project 2 : args */
#define MAX_ARGC 128
void argument_stack(char **argv, int argc, struct intr_frame *if_);

/* Project 2 : system call - File Descriptor */
#define STDIN 0
#define STDOUT 1
#define STDERR 2

int get_next_fd(struct file *f);
struct file *process_get_file(int fd);
int process_close_file(int fd);
struct thread *get_child_process(tid_t tid);

#endif /* userprog/process.h */
