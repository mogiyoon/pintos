#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <string.h>
#include "kernel/stdio.h"
#include "threads/interrupt.h"
#include "threads/init.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "threads/vaddr.h"
#include "threads/flags.h"
#include "userprog/gdt.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
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

void halt (void) NO_RETURN;
void exit (int status) NO_RETURN;
pid_t fork (const char *thread_name);
int exec (const char *file);
int wait (pid_t child_pid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned length);
int write (int fd, const void *buffer, unsigned length);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

static bool ptr_error (char* input_ptr, void* aux);

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
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

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
	
	uint64_t result = 0;
	// msg("sysnum = %d", arg0);
	// printf ("system wow call!\n");

	// uint64_t* temp = thread_current()->file_dt[1];
	// *temp = "1\n";

	switch (arg0)
	{
		case SYS_HALT:
			halt();
			break;
		case SYS_EXIT:
			exit((int)arg1);
			break;
		case SYS_FORK:
			result = fork((char*)arg1);
			break;
		case SYS_EXEC:
			result = exec((char*)arg1);
			break;
		case SYS_WAIT:
			result = wait((pid_t)arg1);
			break;
		case SYS_CREATE:
			result = create((char*)arg1, (unsigned)arg2);
			break;
		case SYS_REMOVE:
			result = remove((char*)arg1);
			break;
		case SYS_OPEN:
			result = open((char*)arg1);
			break;
		case SYS_FILESIZE:
			result = filesize((int)arg1);
			break;
		case SYS_READ:
			result = read((int)arg1, (void*)arg2, (unsigned)arg3);
			break;
		case SYS_WRITE:
			result = write((int)arg1, (void*)arg2, (unsigned)arg3);
			break;
		case SYS_SEEK:
			seek((int)arg1, (unsigned)arg2);
			break;
		case SYS_TELL:
			result = tell((int)arg1);
			break;
		case SYS_CLOSE:
			close((int)arg1);
			break;
		
		default:
		/* code for error not sys call */
		break;
	}
	f->R.rax = result;
}

void halt (void) {
	power_off();
}

void exit (int status) {
	struct thread *curr = thread_current();
	if (curr != NULL) {
		printf("%s: exit(%d)\n", curr->name, status);
		thread_exit();
	} else {
		 return;
	}
}

pid_t fork (const char *thread_name) {
	if (ptr_error(thread_name, KADDR)) {
		exit(-1);
	}
}

int exec (const char *file) {
	if (ptr_error(file, KADDR)) {
		exit(-1);
	}
}

int wait (pid_t child_pid) {
	return process_wait(child_pid);
}

bool create (const char *file, unsigned initial_size) {
	if (ptr_error(file, KADDR)) {
		exit(-1);
	}
	if (strlen(file) == 0) {
		exit(-1);
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

bool remove (const char *file) {
	if (ptr_error(file, KADDR)) {
		exit(-1);
	}

}

int open (const char *file) {
	if (ptr_error(file, KADDR)) {
		exit(-1);
	}

	if (strlen(file) == 0) {
		exit(-1);
	}

	struct file* new_file = filesys_open(file);
	struct thread* curr = thread_current();
	int fd_num;

	if (new_file != NULL) {
		curr->file_dt[curr->next_fd] = new_file;
		fd_num = curr->next_fd;
		curr->next_fd++;
		return fd_num;
	} else {
		return -1;
	}
}

int filesize (int fd) {

}

int read (int fd, void *buffer, unsigned length) {
	if (ptr_error(buffer, KADDR)) {
		exit(-1);
	}

	msg("fd num: %d", fd);
	msg("read len: %d", length);

	if (fd == 0) {
		for (unsigned i = 0; i < length; i++) {
			((uint8_t *)buffer)[i] = input_getc(); // 키보드 입력 1바이트씩 받기
		}
		return length;
	}
	struct thread* curr = thread_current();
	if (curr->file_dt[fd] != NULL) {
		return file_read(curr->file_dt[fd], buffer, length);
	} else {
		return -1;
	}
}

int write (int fd, const void *buffer, unsigned length) {
	if (ptr_error(buffer, KADDR)) {
		exit(-1);
	}

	if (fd == 1) {
		putbuf(buffer, length);
		return length;
	}
	struct thread* curr = thread_current();
	return file_write(curr->file_dt[fd], buffer, length);
}

void seek (int fd, unsigned position) {

}

unsigned tell (int fd) {

}

void close (int fd) {

}

static bool ptr_error (char* input_ptr, void* aux) {
	if (input_ptr == NULL || pml4_get_page(thread_current()->pml4, input_ptr) == NULL) {
		return true;
	} else {
		//address is kernel area
		if ((enum waddr)aux == UADDR) {
			if (is_user_vaddr(input_ptr)) {
				return true;
			}
		} else if ((enum waddr)aux == KADDR) {
			if (is_kernel_vaddr(input_ptr)) {
				return true;
			}
		}
		return false;
	}
}