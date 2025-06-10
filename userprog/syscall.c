#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <string.h>
#include "kernel/stdio.h"
#include "threads/synch.h"
#include "threads/interrupt.h"
#include "threads/init.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "threads/vaddr.h"
#include "threads/flags.h"
#include "threads/palloc.h"
#include "userprog/gdt.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/inode.h"
#include "intrinsic.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

//address enum
enum waddr {
	NADDR,
	KADDR,
	UADDR
};

/* Process identifier. */
typedef int pid_t;
#define PID_ERROR ((pid_t) -1)

void sys_halt (void) NO_RETURN;
void sys_exit (int status) NO_RETURN;
pid_t sys_fork (const struct intr_frame* thread_frame);
int sys_exec (const char *file);
int sys_wait (pid_t child_pid);
bool sys_create (const char *file, unsigned initial_size);
bool sys_remove (const char *file);
int sys_open (const char *file);
int sys_filesize (int fd);
int sys_read (int fd, void *buffer, unsigned length);
int sys_write (int fd, const void *buffer, unsigned length);
void sys_seek (int fd, unsigned position);
unsigned sys_tell (int fd);
void sys_close (int fd);

void *sys_mmap (void *addr, size_t length, int writable, int fd, off_t offset);
void sys_munmap (void *addr);

static bool ptr_error (char* input_ptr);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	lock_init(&syscall_lock);
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

char* call_name[] = {"sys_halt\0", "exit\0", "fork\0", "exec\0", "wait\0", "create\0", "remove\0", "open\0", "file size\0", "read\0", "write\0", "seek\0", "sys_tell\0", "close\0", "mmap\0", "munmap\0"};

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	uint64_t arg0 = f->R.rax;
	uint64_t arg1 = f->R.rdi;
	uint64_t arg2 = f->R.rsi;
	uint64_t arg3 = f->R.rdx;
	uint64_t arg4 = f->R.r10;
	uint64_t arg5 = f->R.r8;
	uint64_t arg6 = f->R.r9;
	thread_current()->user_rsp = f->rsp;

	uint64_t result = 0;
	// printf("\nsys call = %s\n", call_name[arg0]);
	// printf("sys cur name: %s\n", thread_current()->name);
	// printf("sys cur pid: %d\n\n", thread_current()->tid);
	// printf ("system wow call!\n");

	switch (arg0)
	{
		case SYS_HALT:
			sys_halt();
			break;
		case SYS_EXIT:
			sys_exit((int)arg1);
			break;
		case SYS_FORK:
			result = sys_fork(f);
			break;
		case SYS_EXEC:
			result = sys_exec((char*)arg1);
			break;
		case SYS_WAIT:
			result = sys_wait((pid_t)arg1);
			break;
		case SYS_CREATE:
			result = sys_create((char*)arg1, (unsigned)arg2);
			break;
		case SYS_REMOVE:
			result = sys_remove((char*)arg1);
			break;
		case SYS_OPEN:
			result = sys_open((char*)arg1);
			break;
		case SYS_FILESIZE:
			result = sys_filesize((int)arg1);
			break;
		case SYS_READ:
			result = sys_read((int)arg1, (char*)arg2, (unsigned)arg3);
			break;
		case SYS_WRITE:
			result = sys_write((int)arg1, (char*)arg2, (unsigned)arg3);
			break;
		case SYS_SEEK:
			sys_seek((int)arg1, (unsigned)arg2);
			break;
		case SYS_TELL:
			result = sys_tell((int)arg1);
			break;
		case SYS_CLOSE:
			sys_close((int)arg1);
			break;
		case SYS_MMAP:
			result = sys_mmap((void*)arg1, (size_t)arg2, (int)arg3, (int)arg4, (off_t)arg5);
			break;
		case SYS_MUNMAP:
			sys_munmap((void*)arg1);
			break;
		
		default:
		/* code for error not sys call */
		break;
	}
	f->R.rax = result;
}

void sys_halt (void) {
	power_off();
}

void sys_exit (int status) {
	struct thread *curr = thread_current();
	if (curr != NULL) {
		curr->self_status->exit_status = status;
		printf("%s: exit(%d)\n", curr->name, curr->self_status->exit_status);
		thread_exit();
	}
}

pid_t sys_fork (const struct intr_frame* thread_frame) {
	char* thread_name = thread_frame->R.rdi;
	return process_fork(thread_name, thread_frame);
}

int sys_exec (const char *file) {
	if (ptr_error(file)) {
		sys_exit(-1);
	}

	char* fn_copy = palloc_get_page (0);
	if (fn_copy == NULL) {
		sys_exit(-1);
	}
	strlcpy (fn_copy, file, PGSIZE);

	process_exec(fn_copy);
}

int sys_wait (pid_t child_pid) {
	return process_wait(child_pid);
}

bool sys_create (const char *file, unsigned initial_size) {
	if (ptr_error(file)) {
		sys_exit(-1);
	}
	if (strlen(file) == 0) {
		sys_exit(-1);
	}

	struct file* tmp_file = filesys_open(file);
	if (tmp_file != NULL) {
		file_close(tmp_file);
		return false;
	}

	if (filesys_create(file, initial_size)) {
		return true;
	} else {
		return false;
	}
}

bool sys_remove (const char *file) {
	if (ptr_error(file)) {
		sys_exit(-1);
	}

	bool result = filesys_remove(file);
	return result;
}

int sys_open (const char *file) {
	if (ptr_error(file)) {
		sys_exit(-1);
	}
	
	struct file* new_file = filesys_open(file);
	
	struct thread* curr = thread_current();
	int fd_num;

	if (curr->next_fd >= FD_MAX) {
		file_close(new_file);
		return -1;
	}

	if (new_file != NULL) {
		while (curr->next_fd < FD_MAX && curr->file_dt[curr->next_fd] != NULL) {
			curr->next_fd++;
		}
		if (curr->next_fd < FD_MAX && curr->file_dt[curr->next_fd] == NULL) {
			curr->file_dt[curr->next_fd] = new_file;
			fd_num = curr->next_fd;
			curr->next_fd++;
			return fd_num;
		}
	}
	return -1;
}

int sys_filesize (int fd) {
	struct thread* curr = thread_current();
	if (fd >= FD_MAX || fd < 0 || curr->file_dt[fd] == NULL) {
		return -1;
	}

	return file_length(curr->file_dt[fd]);
}

int sys_read (int fd, void *buffer, unsigned length) {
	if (ptr_error(buffer)) {
		sys_exit(-1);
	}

	struct page* get_page = spt_find_page(&thread_current()->spt, pg_round_down(buffer));
	if (get_page != NULL && !(get_page->writable)) {
		sys_exit(-1);
	}

	if (fd == 0) {
		for (unsigned i = 0; i < length; i++) {
			((uint8_t *)buffer)[i] = input_getc();
		}
		return length;
	}

	struct thread* curr = thread_current();
	if (fd >= FD_MAX || fd < 0 || curr->file_dt[fd] == NULL) {
		return -1;
	}

	lock_acquire(&syscall_lock);
	unsigned int read_len;
	read_len = file_read(curr->file_dt[fd], buffer, length);
	lock_release(&syscall_lock);

	return read_len;
}

int sys_write (int fd, const void *buffer, unsigned length) {
	if (ptr_error(buffer)) {
		sys_exit(-1);
	}

	// struct page* get_page = spt_find_page(&thread_current()->spt, pg_round_down(buffer));
	// if (get_page != NULL && !(get_page->writable)) {
	// 	exit(-1);
	// }

	if (fd == 1) {
		putbuf(buffer, length);
		return length;
	}

	struct thread* curr = thread_current();
	if (fd >= FD_MAX || fd < 0 || curr->file_dt[fd] == NULL) {
		return -1;
	}

	if (curr->file_dt[fd]->deny_write) {
		return 0;	
	}

	lock_acquire(&syscall_lock);
	unsigned int write_len;
	write_len = file_write(curr->file_dt[fd], buffer, length);
	lock_release(&syscall_lock);
	return write_len;
}

void sys_seek (int fd, unsigned position) {
	struct file* tmp_file = thread_current()->file_dt[fd];
	if (tmp_file == NULL) {
		sys_exit(-1);
	}

	file_seek(tmp_file, position);
}

unsigned sys_tell (int fd) {
	struct file* tmp_file = thread_current()->file_dt[fd];
	if (ptr_error(tmp_file)) {
		sys_exit(-1);
	}

	return file_tell(tmp_file);
}

void sys_close (int fd) {
	if (fd >= FD_MAX) {
		sys_exit(-1);
	}

	struct file* tmp_file = thread_current()->file_dt[fd];
	if (tmp_file == NULL) {
		return;
	}

	file_close(thread_current()->file_dt[fd]);
	
	thread_current()->file_dt[fd] = NULL;
	if (thread_current()->next_fd > fd) {
		thread_current()->next_fd = fd;
	}
}

void* sys_mmap (void *addr, size_t length, int writable, int fd, off_t offset) {
	if (ptr_error(addr) || ptr_error(addr + length)) {
		return NULL;
	}

	struct thread* curr = thread_current();
	if (fd >= FD_MAX || fd < 2 || curr->file_dt[fd] == NULL) {
		return NULL;
	}

	//mis-align
	if ((uint64_t)addr % PGSIZE != 0) {
		return NULL;
	}

	//zero-len
	if (length == 0 || length < (uint64_t)offset) {
		return NULL;
	}

	return do_mmap(addr, length, writable, thread_current()->file_dt[fd], offset);
}

void sys_munmap (void *addr) {
	do_munmap(addr);
}

static bool ptr_error (char* input_ptr) {
	if (input_ptr == NULL) {
		return true;
	}
	
	if (!is_user_vaddr(input_ptr)) {
		return true;
	}

	return false;
}

