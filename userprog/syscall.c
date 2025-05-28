
#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

/** project2-System Call */
#include "threads/mmu.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/palloc.h"
#include "userprog/process.h"

void halt(void);
void exit (int status);
pid_t fork (const char *thread_name);
int exec(const char *cmd_line);
bool create (const char *file, unsigned initial_size);
int open (const char *file);
int filesize (int fd);
int read(int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
int wait(pid_t pid);
void close(int fd);
void check_address(void *addr);

void syscall_entry (void);
void syscall_handler (struct intr_frame *);


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
syscall_handler (struct intr_frame *f) {
	// TODO: Your implementation goes here.
	int syscall_num = f->R.rax;
	// printf ("system call!\n Number: %d, Thread  %s\n", syscall_num, thread_current()->name);
	
	switch (syscall_num)
	{
		case SYS_HALT:
		halt();
		break;
	case SYS_EXIT:
		exit(f->R.rdi);
		break;
	case SYS_FORK:
		f->R.rax = fork(f->R.rdi);
		break;
	case SYS_EXEC:
		f->R.rax = exec(f->R.rdi);
		break;
	// case SYS_WAIT:
	// 	f->R.rax = process_wait(f->R.rdi);
	// 	break;
	case SYS_CREATE:
		f->R.rax = create(f->R.rdi, f->R.rsi);
		break;
	// case SYS_REMOVE:
	// 	f->R.rax = remove(f->R.rdi);
	// 	break;
	case SYS_OPEN:
		f->R.rax = open(f->R.rdi);
		break;
	case SYS_FILESIZE:
		f->R.rax = filesize(f->R.rdi);
		break;
	case SYS_READ:
		f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_WRITE:
		f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	// case SYS_SEEK:
	// 	seek(f->R.rdi, f->R.rsi);
	// 	break;
	// case SYS_TELL:
	// 	f->R.rax = tell(f->R.rdi);
	// 	break;
	case SYS_CLOSE:
		close(f->R.rdi);
		break;
	default:
	exit(-1);
}	
}

void halt(void){
	power_off();
}

void exit (int status){
	struct thread *t = thread_current();
	t->exit_status = status;
	printf("%s: exit(%d)\n", thread_name(), status);
	thread_exit();
	// return status;
}

pid_t fork (const char *thread_name){
	check_address(thread_name);

	return process_fork(thread_name, NULL);
}

int exec(const char *cmd_line){
	check_address(cmd_line);

	int size = strlen(cmd_line) + 1;
	char *cmd_copy = palloc_get_page(PAL_ZERO);
	
	if(cmd_copy == NULL)
	return -1;

	memcpy(cmd_copy, cmd_line, size);

	if(process_exec(cmd_copy) == -1);
		return -1;

	return 0;
}

// int wait(pid_t pid){
// 	return process_wait(pid);
// }

bool create (const char *file, unsigned initial_size){
	check_address(file);

	return filesys_create(file, initial_size);
}

bool remove (const char *file){

}

int open (const char *file){
	check_address(file);
	struct file *newfile = filesys_open(file);

	if(newfile == NULL)
	return -1;

	int fd = process_add_file(newfile);

	if(fd == -1)
		file_close(newfile);
	
	return fd;

}

int filesize (int fd){
    // struct file *open_file = process_get_file(fd);
	// if (open_file == NULL){
	// 	return -1;
	// }
	// return file_length(open_file);
	struct file *file = process_get_file(fd);

	if(file == NULL)
	return -1;

	return file_length(file);
}

int read(int fd, void *buffer, unsigned size){
    check_address(buffer);
    struct thread *curr = thread_current();
    struct file *readed_file = curr-> fdt[fd];
    int bytes = 0;
    if(fd == 0){
        for(int i = 0; i <= size; i++){
            char c = input_getc();
            buffer = c;
            buffer+= 8;
			if(c == '\0');
			break;
			bytes = i;
        }
		
    } 
	else if(fd == 1){
		exit(-1);
	}
    else if(fd >=2){
    bytes = file_read (readed_file, buffer, size);
    }

	return bytes;
}

int write (int fd, const void *buffer, unsigned size){
	// printf("write\n");
	check_address(buffer);
	// if(fd == 1)
	// 	putbuf(buffer, size);
	// return size;
	int bytes = -1;
	if (fd <= 0)  // stdin에 쓰려고 할 경우 & fd 음수일 경우
    	return -1;

    if (fd < 3) {  // 1(stdout) * 2(stderr) -> console로 출력
        putbuf(buffer, size);
        return size;
    }

    struct file *file = process_get_file(fd);

    if (file == NULL)
        return -1;
		
	bytes = file_write(file, buffer, size);
	return bytes;
}
int wait(pid_t tid){
	return process_wait(tid);
}
void
close(int fd){
	struct file *file = process_get_file(fd);

	if(fd<3 || file == NULL)
	return;

	process_close_file(fd);
	file_close(file);
}

void check_address(void *addr){
	struct thread *cur = thread_current(); 
	if (is_kernel_vaddr(addr) || pml4_get_page(cur->pml4, addr) == NULL){
		exit(-1);
	}
}