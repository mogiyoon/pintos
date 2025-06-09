/* file.c: Implementation of memory backed file object (mmaped object). */

#include <stdio.h>
#include <round.h>
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "vm/vm.h"

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
	page->now_type = VM_FILE;

	struct file_page *file_page = &page->file;
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
}

static bool
lazy_load_mmap (struct page *page, void *aux) {
	/* TODO: Load the segment from the file */
	/* TODO: This called when the first page fault occurs on address VA. */
	/* TODO: VA is available when calling this function. */

	// printf("mmap lazy load\n");

	uint8_t* upage = page->va;
	uint8_t* kpage = page->frame->kva;
	
	struct file_aux_info* aux_info = (struct file_aux_info*)aux;
	struct file* file = aux_info->file;
	off_t ofs = aux_info->ofs;
	size_t page_read_bytes = aux_info->read_bytes;
	size_t page_zero_bytes = aux_info->zero_bytes;

	ASSERT ((page_read_bytes + page_zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	/* Do calculate how to fill this page.
		* We will read PAGE_READ_BYTES bytes from FILE
		* and zero the final PAGE_ZERO_BYTES bytes. */

	/* Load this page. */
	if (file_read_at (file, kpage, page_read_bytes, ofs) != (int) page_read_bytes) {
		return false;
	}
	memset (kpage + page_read_bytes, 0, page_zero_bytes);

	free(aux);
	return true;
}

/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable,
	struct file *file, off_t offset) {
	off_t total_len = file_length(file);
	uint32_t read_bytes = total_len - offset;
	uint32_t zero_bytes = ROUND_UP(read_bytes, PGSIZE) - read_bytes;
	off_t ofs = offset;
	uint8_t* upage = addr;

	// printf("do mmap cur: %s\n", thread_current()->name);
	// printf("do mmap va: %p\n", addr);
	// printf("do mmap total len: %d\n", total_len);
	// printf("do mmap read bytes: %d\n", read_bytes);
	// printf("do mmap zero bytes: %d\n", zero_bytes);
	// printf("do mmap offset: %d\n", ofs);
	// printf("do mmap writable: %d\n", writable);
	
	while (read_bytes > 0 || zero_bytes > 0) {
		// printf("do mmap while\n");
		/* Do calculate how to fill this page.
			* We will read PAGE_READ_BYTES bytes from FILE
			* and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* TODO: Set up aux to pass information to the lazy_load_segment. */
		struct file_aux_info* aux_info = calloc(1, sizeof(struct file_aux_info));
		if (aux_info == NULL) {
			return NULL;
		}
		aux_info->file = file;
		aux_info->ofs = ofs;
		aux_info->read_bytes = page_read_bytes;
		aux_info->zero_bytes = page_zero_bytes;

		void *aux = aux_info;
		if (!vm_alloc_page_with_initializer (VM_FILE, upage,
					writable, lazy_load_mmap, aux)) {
						return NULL;
					}

		/* Advance. */
		ofs += PGSIZE;
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}

	return addr;
}

/* Do the munmap */
void
do_munmap (void *addr) {

}

void
file_copy_page () {

}