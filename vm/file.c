/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
/* Project 3 : Memory Mapped Files */
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "userprog/syscall.h"
#include "userprog/process.h"

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void
vm_file_init (void) {
}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &file_ops;

	struct file_page *file_page = &page->file;

	/* Project 3 : Memory Mapped Files */
	struct load_info *aux = (struct load_info *)page->uninit.aux;
	file_page->file = aux->file;
	file_page->offset = aux->offset;
	file_page->read_bytes = aux->read_bytes;

	return true;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
	struct thread *curr = thread_current;

	/*
	// 프레임이 존재하고 dirty한 경우 write back
	if(pml4_is_dirty(curr->pml4, page->va)){
		file_write_at(file_page->file, page->va, file_page->read_bytes, file_page->offset);
		pml4_set_dirty(curr->pml4, page->va, false);
	}
	
	if(page->frame){
		list_remove(&page->frame->frame_elem);
		page->frame->page = NULL;
		page->frame = NULL;
		free(page->frame);
	}

	pml4_clear_page(curr->pml4, page->va);
	*/
	
	if (!pml4_get_page(thread_current()->pml4, page->va))
		// printf("[DEBUG] VA=%p not mapped. Skipping...\n", page->va);
		return;

	if(pml4_is_dirty(curr->pml4, page->va)){
		// printf("[DEBUG] Writing back dirty page: VA=%p\n", page->va);
		file_write_at(file_page->file, page->va, file_page->read_bytes, file_page->offset);
		pml4_set_dirty(curr->pml4, page->va, false);
	}

	if(page->frame){
		list_remove(&page->frame->frame_elem);
		page->frame->page = NULL;
		page->frame = NULL;
		free(page->frame);
	}

	pml4_clear_page(curr->pml4, page->va);
	
}

/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t offset) {
	// 1. file reopen
	lock_acquire(&filesys_lock);
	struct file *m_file = file_reopen(file);

	// 2. 총 매핑 크기 계산
	void *original_addr = addr;
	size_t read_bytes = (length > file_length(m_file)) ? file_length(m_file) : length;
	size_t zero_bytes = PGSIZE - read_bytes % PGSIZE;

	// 예외 체크 (필수 정렬 조건)
	ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);	// 전체 매핑 크기는 PGSIZE 배수
	ASSERT(pg_ofs(addr) == 0);		// addr 페이지 정렬
	ASSERT(offset % PGSIZE == 0);	// offset 정렬

	// 3. 페이지마다 vm_alloc_page_with_initializer 호출 -> while 루프로 페이지마다 초기화
	struct load_info *aux;
	while(read_bytes > 0 || zero_bytes > 0){
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Set up aux to pass information to the lazy_load_segment. */
		aux = (struct load_info *)malloc(sizeof(struct load_info));
		if(!aux)
			goto err;
		
		aux->file = m_file;
		aux->offset = offset;
		aux->read_bytes = page_read_bytes;

		if(!vm_alloc_page_with_initializer(VM_FILE, addr, writable, lazy_load_segment, aux))
			goto err;

		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		addr += PGSIZE;
		offset += page_read_bytes;
	}
	// 4. 성공 시 addr 반환
	lock_release(&filesys_lock);
	return original_addr;
err:
	// 5. 실패 시 do_munmap 호출
	free(aux);
	do_munmap(original_addr);
	lock_release(&filesys_lock);
	return NULL;
}

/* Do the munmap */
void
do_munmap (void *addr) {
	struct thread *curr = thread_current();
	struct page *page;

	lock_acquire(&filesys_lock);
	// addr 부터 매핑된 모든 페이지를 순차적으로 탐색하여 해제
	while(page = spt_find_page(&curr->spt, addr)){
		// destory -> file_backed_destory 호출
		if(page)
			destroy(page);
		addr += PGSIZE;
	}
	lock_release(&filesys_lock);
}
