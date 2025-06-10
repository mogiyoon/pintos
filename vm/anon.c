/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include <stdio.h>
#include "vm/vm.h"
#include "threads/malloc.h"
#include "devices/disk.h"

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static struct hash swap_hash;
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

/* Initialize the data for anonymous pages */
void
vm_anon_init (void) {
	/* TODO: Set up the swap_disk. */
	swap_disk = disk_get(1, 1);
	hash_init(&swap_hash, va_to_hashvalue, hash_value_comparer, NULL);
}

/* Initialize the file mapping */
bool
anon_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &anon_ops;
	struct anon_page *anon_page = &page->anon;
	anon_page->anon_swap_disk = swap_disk;
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
	struct swap_tag* anon_swap_tag = calloc(1, sizeof(struct swap_tag));
	if (anon_swap_tag == NULL) {
		return false;
	}

	printf("dist sector: %d", disk_size(swap_disk));
	anon_swap_tag->swap_anon_page = page;
	anon_swap_tag->kva = page->frame->kva;

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