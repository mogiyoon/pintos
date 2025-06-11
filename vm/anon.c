/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include <stdio.h>
#include "vm/vm.h"
#include "threads/malloc.h"
#include "threads/mmu.h"
#include "devices/disk.h"

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static bool anon_swap_in (struct page *page, void *kva);
static bool anon_swap_out (struct page *page);
static void anon_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};

#define SECTOR_SIZE 64
#define SEC_BYTES 512

static bool disk_sector[SECTOR_SIZE] = {false};
static int next_page_num = 0;

/* Initialize the data for anonymous pages */
void
vm_anon_init (void) {
	/* TODO: Set up the swap_disk. */
	swap_disk = disk_get(1, 1);
}

/* Initialize the file mapping */
bool
anon_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &anon_ops;
	struct anon_page *anon_page = &page->anon;
	anon_page->is_swap_out = false;
	anon_page->swap_sector = 0;
}

/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in (struct page *page, void *kva) {
	struct anon_page *anon_page = &page->anon;
	for (int i = 0; i < PGSIZE/SEC_BYTES; i++) {
		disk_read(swap_disk, page_to_sector(page->anon.swap_sector) + i, kva + i*SEC_BYTES);
	}
	disk_sector[page->anon.swap_sector] = false;
	page->anon.is_swap_out = false;
	if (next_page_num < page->anon.swap_sector) {
		next_page_num = page->anon.swap_sector;
	}

	
	// printf("anon text: %s\n", kva);
	// printf("anon swap in\n");
	// printf("anon page va: %p\n", page->va);
	// printf("anon page kva: %p\n", kva);
	pml4_set_page(page->owner->pml4, page->va, kva, page->writable);
	return true;
}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out (struct page *page) {
	struct anon_page *anon_page = &page->anon;
	while (next_page_num < SECTOR_SIZE && disk_sector[next_page_num]) {
		next_page_num++;
	}
	if (next_page_num >= SECTOR_SIZE) {
		return false;
	}

	for (int i = 0; i < PGSIZE/SEC_BYTES; i++) {
		disk_write(swap_disk, page_to_sector(next_page_num) + i, page->frame->kva + i*SEC_BYTES);
	}
	disk_sector[next_page_num] = true;
	page->anon.is_swap_out = true;
	page->anon.swap_sector = next_page_num;
	next_page_num++;
	// printf("anon text: %s\n", page->frame->kva);
	// printf("anon swap out\n");
	return true;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy (struct page *page) {
	struct anon_page *anon_page = &page->anon;
	free(page->frame);
}

void
anon_copy_page () {

}

int
sector_to_page (disk_sector_t input_sector) {
	return input_sector/8;
}

disk_sector_t
page_to_sector (int page_num) {
	return page_num*8;
}