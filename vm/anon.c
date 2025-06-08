/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "vm/vm.h"
#include "devices/disk.h"
#include "lib/kernel/bitmap.h"

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

static struct bitmap *swap_table;
static struct lock swap_lock;

/* Initialize the data for anonymous pages */
void
vm_anon_init (void) {
	/* TODO: Set up the swap_disk. */
	swap_disk = NULL;
	/*swap_disk = disk_get(1,1);
	if(swap_disk == NULL)
		PANIC("vm anon init: swap_disk failed");
	
	size_t total_sectors = disk_size(swap_disk);
	if(!total_sectors)
		PANIC("vm_anon_init : no sectors available");

	size_t sector_count = (1<<12) / DISK_SECTOR_SIZE;
	ASSERT(sector_count > 0);

	size_t total_slots = total_sectors / sector_count;
	if(!total_slots)
		PANIC("vm anon init: disk too small");
	
	swap_table = bitmap_create(total_slots);
	if(swap_table == NULL)
		PANIC("vm anon init : bitmap failed");
	
	bitmap_set_all(swap_table, false);
	lock_init(&swap_lock);*/
}

/* Initialize the file mapping */
bool
anon_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	// ASSERT(type == VM_ANON);
	page->operations = &anon_ops;

	struct anon_page *anon_page = &page->anon;
	/* Project 3 : VM */
	// anon_page->swap_slot_index = -1;
}

/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in (struct page *page, void *kva) {
	struct anon_page *anon_page = &page->anon;
}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out (struct page *page) {
	struct anon_page *anon_page = &page->anon;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy (struct page *page) {
	struct anon_page *anon_page = &page->anon;
}
