#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

/* Project 2 : system call */
#include "threads/mmu.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/palloc.h"
#include "userprog/process.h"
#include "devices/input.h"
#include "console.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* Project 2 : system call - write, read */
struct lock filesys_lock;

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
	
	/* Project 2 : system call */
	lock_init(&filesys_lock);
}

/* The main system call interface */
/* Project 2 : system call */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	int sys_number = f->R.rax;
	switch(sys_number){
		case SYS_HALT :
			halt();
			break;
		case SYS_EXIT :
			exit(f->R.rdi);
			break;
		case SYS_FORK :
			f->R.rax = fork(f->R.rdi);
			break;
		case SYS_EXEC :
			f->R.rax = exec(f->R.rdi);
			break;
		case SYS_WAIT :
			f->R.rax = wait(f->R.rdi);
			break;
		case SYS_CREATE :
			f->R.rax = create(f->R.rdi,f->R.rsi);
			break;
		case SYS_REMOVE :
			f->R.rax = remove(f->R.rdi);
			break;
		case SYS_OPEN :
			f->R.rax = open(f->R.rdi);
			break;
		case SYS_FILESIZE :
			f->R.rax = filesize(f->R.rdi);
			break;
		case SYS_READ :
			f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_WRITE :
			f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_SEEK :
			seek(f->R.rdi, f->R.rsi);
			break;
		case SYS_TELL :
			f->R.rax = tell(f->R.rdi);
			break;
		case SYS_CLOSE :
			close(f->R.rdi);
			break;
		default :
			exit(-1);
	}
	// printf ("system call!\n");
	// thread_exit ();
}
/* Project 2 : system call */
/* Address validation :
 * - 사용자 포인터가 유효한지 검사하고 유효하지 않다면 프로세스를 종료시킨다
 * - “이 포인터가 사용자 영역이고, 실제로 매핑되어 있나?”를 커널이 확인한다 */
void
check_address(void *addr){
	if(addr == NULL || is_kernel_vaddr(addr) || pml4_get_page(thread_current()->pml4, addr) == NULL){
		exit(-1);
	}
}

void halt (void){
	power_off();
}

void exit (int status){
	struct thread *curr = thread_current();
	curr->exit_status = status;
	printf("%s: exit(%d)\n", curr->name, curr->exit_status);
	thread_exit();
}

/* Dummy Code */
pid_t fork (const char *thread_name){
	check_address(thread_name);
	return process_fork(thread_name, NULL);
}

int exec (const char *file){
	check_address(file);

	off_t size = strlen(file) + 1; 
	char *exec_copy = palloc_get_page(PAL_ZERO);
	
	if (exec_copy == NULL)
		return -1;

	// strlcpy (exec_copy, file, PGSIZE);
	memcpy(exec_copy, file, size);

	if(process_exec(file) == -1)
		return -1;

	return 0;
}

int wait (pid_t pid){
	return process_wait(pid);
}

bool create (const char *file, unsigned initial_size){
	check_address(file);
	return filesys_create(file, initial_size);
}

bool remove (const char *file){
	check_address(file);
	return filesys_remove(file);
}

int open (const char *file){
	check_address(file);

	struct file *f = filesys_open(file);
	if (f == NULL)
		return -1;
	
	int fd = get_next_fd(f);	// 함수 구현

	if (fd == -1)
		file_close(f);
	
	return fd;
}

int filesize (int fd){
	struct file *file = process_get_file(fd);

	if (file == NULL)
		return -1;
	
	return file_length(file);
}

int read (int fd, void *buffer, unsigned length){
	check_address(buffer);

	// stdin 키보드 입력은 파일이 아니기 때문에 직접 읽어온다
	if (fd == 0){
		unsigned char *buff = buffer;
		for (int i = 0; i < length; i++){
			buff[i] = input_getc();
		}
		return length;
	}
	// stdout, stderr인 경우 또는 fd < 0 인 경우 -> 읽을게 없으니 에러 반환
	if (fd < 3)
		return -1;

	// fd >= 3 인 경우
	struct file *file = process_get_file(fd);
	if (file == NULL)
		return -1;
	
	lock_acquire(&filesys_lock);
	off_t bytes_read = file_read(file, buffer, length);
	lock_release(&filesys_lock);

	return bytes_read;
}

int write (int fd, const void *buffer, unsigned length){
	check_address(buffer);

	// stdin or fd < 0 인 경우 쓸게 없으니 에러 반환
	if (fd <= 0)
		return -1;
	
	// stdout, stderr는 콘솔에 바로 length만큼 출력한다
	if (fd < 3){
		putbuf(buffer, length);
		return length;
	}

	struct file *file = process_get_file(fd);
	if (file == NULL)
		return -1;

	off_t bytes_write = -1;
	lock_acquire(&filesys_lock);
	bytes_write = file_write(file, buffer, length);
	lock_release(&filesys_lock);

	return bytes_write;
}

// 파일을 읽거나 쓸 때의 위치(offset)를 지정하는 함수
void seek (int fd, unsigned position){
	struct file *file = process_get_file(fd);

	if (fd < 3 || file == NULL)
		return;
	
	file_seek(file, position);
}

// 파일의 위치(offset)을 리턴한다
unsigned tell (int fd){
	struct file *file = process_get_file(fd);

	if (fd < 3 || file == NULL)
		return -1;

	return file_tell(file);
}

void close (int fd){
	struct file *file = process_get_file(fd);

	if (fd < 3 || file == NULL)
		return;
	
	process_close_file(fd);		// 함수 구현

	file_close(file);
}