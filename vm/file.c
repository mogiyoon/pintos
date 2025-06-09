/* file.c: Implementation of memory backed file object (mmaped object). */

#include <stdio.h>
#include <round.h>
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "vm/vm.h"
#include "filesys/file.h"

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
	// file_write_at(page->mmaped_file, page->frame->kva, page->file.read_bytes, page->file.ofs);

	free(page->frame);	
	// if (page->mmaped_file != NULL) {
		// printf("mmaped file: %d", page->mmaped_file->inode);
		// file_close(page->mmaped_file);
	// }
}

static bool
lazy_load_mmap (struct page *page, void *aux) {
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

	page->file.ofs = ofs;
	page->file.read_bytes = page_read_bytes;
	page->file.zero_bytes = page_zero_bytes;

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
	
	struct list* mmap_pages_list = malloc(sizeof(struct list));
	if (mmap_pages_list == NULL) {
		return NULL;
	}
	list_init(mmap_pages_list);
	struct page* tmp_page;
	struct file* new_file;
	
	while (read_bytes > 0 || zero_bytes > 0) {
		// printf("do mmap while\n");

		new_file = file_open(file->inode);
		if (new_file == NULL) {
			free(mmap_pages_list);
			return NULL;
		}
		/* Do calculate how to fill this page.
			* We will read PAGE_READ_BYTES bytes from FILE
			* and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* TODO: Set up aux to pass information to the lazy_load_segment. */
		struct file_aux_info* aux_info = calloc(1, sizeof(struct file_aux_info));
		if (aux_info == NULL) {
			file_close(new_file);
			free(mmap_pages_list);
			return NULL;
		}
		aux_info->file = new_file;
		aux_info->ofs = ofs;
		aux_info->read_bytes = page_read_bytes;
		aux_info->zero_bytes = page_zero_bytes;

		void *aux = aux_info;
		if (!vm_alloc_page_with_initializer (VM_FILE, upage,
					writable, lazy_load_mmap, aux)) {
						file_close(new_file);
						free(mmap_pages_list);
						free(aux_info);
						return NULL;
					}

		tmp_page = spt_find_page(&thread_current()->spt, upage);
		tmp_page->mmaped_file = new_file;
		tmp_page->mmaped_list = mmap_pages_list;
		list_push_back(mmap_pages_list, &tmp_page->mmaped_elem);

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
	addr = pg_round_down(addr);
	struct page* munmap_page = spt_find_page(&thread_current()->spt, addr);
	if (munmap_page == NULL) {
		return;
	}

	struct list* mapped_pages = munmap_page->mmaped_list;
	if(mapped_pages == NULL) {
		return;
	}

	struct list_elem* mapped_page_elem;
	struct page* tmp_page;
	while (!list_empty(mapped_pages)) {
		mapped_page_elem = list_pop_front(mapped_pages);
		tmp_page = list_entry(mapped_page_elem, struct page, mmaped_elem);
		spt_remove_page(&thread_current()->spt, tmp_page);
	}
	free(mapped_pages);
}

void
file_copy_page () {

}