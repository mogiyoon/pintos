/* vm.c: Generic interface for virtual memory objects. */

#include <stdio.h>
#include <string.h>
#include "threads/malloc.h"
#include "threads/mmu.h"
#include "vm/vm.h"
#include "vm/inspect.h"

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)
	upage = pg_round_down(upage);

	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
		struct page* new_page = malloc(sizeof(struct page));
		if (new_page == NULL) {
			goto err;
		}

		bool (*init_func)(struct page *, enum vm_type, void *);

		switch (VM_TYPE(type))
		{
		case VM_ANON:
			init_func = anon_initializer;
			break;
		case VM_FILE:
			init_func = file_backed_initializer;
			break;
		
		default:
			vm_dealloc_page(new_page);
			goto err;
		}
		uninit_new(new_page, upage, init, type, aux, init_func);
		new_page->writable = writable;
		// printf("vm alloc page va: %p\n", upage);
		// printf("vm alloc page writable: %d\n", writable);

		/* TODO: Insert the page into the spt. */
		if (!spt_insert_page(spt, new_page)) {
			vm_dealloc_page(new_page);
			goto err;
		}

		return true;
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	struct page tmp_page;
	/* TODO: Fill this function. */
	va = pg_round_down(va);
	tmp_page.va = va;
	struct hash_elem* tmp_hash = hash_find(&spt->sup_page_hash, &tmp_page.hash_elem);
	if (tmp_hash != NULL) {
		return hash_entry(tmp_hash, struct page, hash_elem);
	} else {
		return NULL;
	}
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	int succ = false;
	/* TODO: Fill this function. */
	if (spt_find_page (spt, page->va) != NULL) {
		return succ;
	}

	if(hash_insert(&spt->sup_page_hash, &page->hash_elem) == NULL) {
		succ = true;
	}
	return succ;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	hash_delete(&spt->sup_page_hash, &page->hash_elem);
	vm_dealloc_page (page);
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */

	return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	struct frame *frame = calloc(1, sizeof(struct frame));
	/* TODO: Fill this function. */
	frame->kva = palloc_get_multiple(PAL_ZERO, 1);
	frame->page = NULL;
	if (frame == NULL || frame->kva == NULL) {
		PANIC("TODO");
		// ADD evict func
		//frame NULL과 kva NULL 분리하기
	}

	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static int stack_full = 1;

static void
vm_stack_growth (void *addr UNUSED) {
	vm_alloc_page_with_initializer(VM_ANON, addr, true, NULL, NULL);
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	struct page *page = NULL;
	uint64_t* cur_pml4 = thread_current()->pml4;
	if (!is_user_vaddr(addr)) {
		return false;
	}
	// printf("try fault cur: %s\n", thread_current()->name);
	// printf("try fault through \n");

	void* rdown_addr = addr;
	rdown_addr = pg_round_down(rdown_addr);
	uint64_t now_rsp = user ? f->rsp : thread_current()->user_rsp;
	// printf("user: %d\n", user);
	// printf("rsp : %p\n", now_rsp);
	// printf("addr: %p\n", addr);
	// printf("maximum: %p\n", USER_STACK - (1<<20));
	
	/* TODO: Validate the fault */
	if (pml4_get_page(cur_pml4, rdown_addr) != NULL) {
		return false;
	}
	
	if ((USER_STACK >= addr) && (addr >= now_rsp - sizeof(void*)) && (addr >= USER_STACK - (1<<20)))
	{
		if (stack_full < 20) {
			// printf("growth\n");
			// printf("user stack: %p\n", USER_STACK);
			// printf("addr: %p\n", rdown_addr);
			vm_stack_growth(rdown_addr);
		} else {
			return false;
		}
	}

	/* TODO: Your code goes here */
	page = spt_find_page(spt, rdown_addr);
	if (page == NULL) {
		return false;
	}

	if (write && !(page->writable)) {
		return false;
	}

	return vm_do_claim_page (page);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	// printf("called dealloc\n");
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function */
	page = spt_find_page(&thread_current()->spt, va);
	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();
	if (frame == NULL) {
		return false;
	}

	/* Set links */
	frame->page = page;
	page->frame = frame;

	// printf("vm do addr: %p\n", page->va);
	// printf("vm do writable: %d\n", page->writable);

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	uint64_t* cur_pml4 = thread_current()->pml4;
	if (pml4_get_page(cur_pml4, page->va) != NULL) {
		free(frame);
		return false;
	} else {
		if (!pml4_set_page(cur_pml4, page->va, frame->kva, page->writable)) {
			free(frame);
			return false; 
		}
	}
	return swap_in (page, frame->kva);
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	hash_init(&spt->sup_page_hash, va_to_hashvalue, hash_value_comparer, NULL);
	spt->thread = thread_current();
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
		return hash_copy(&dst->sup_page_hash, &src->sup_page_hash, copy_page_by_hash);
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	hash_clear(&spt->sup_page_hash, delete_page_by_hash);
}

uint64_t
va_to_hashvalue(struct hash_elem *e, void* aux) {
	struct page* tmp_page = hash_entry(e, struct page, hash_elem);
	return hash_bytes(&tmp_page->va, sizeof(void *));
}

bool
hash_value_comparer(struct hash_elem* a, struct hash_elem* b, void *aux) {
	uint64_t pva_a; 
	uint64_t pva_b;

	struct page* tmp_a = hash_entry(a, struct page, hash_elem);
	struct page* tmp_b = hash_entry(b, struct page, hash_elem);

	pva_a = tmp_a->va;
	pva_b = tmp_b->va;

if (pva_a < pva_b)
    return true;
else
    return false;
}

struct hash_elem*
copy_page_by_hash (struct hash_elem* src_elem) {
	struct page* old_page = hash_entry(src_elem, struct page, hash_elem);
	struct page* new_page = malloc(sizeof(struct page));
	//TODO: determine true or false result of function

	switch (old_page->operations->type)
	{
		case VM_UNINIT:
			vm_copy_uninit_page(old_page, new_page);
			break;
		case VM_ANON:
			vm_copy_claim_page(old_page, new_page);
			break;
		case VM_FILE:
			vm_copy_claim_page(old_page, new_page);
			break;
	
		default:
			break;
	}
	return &new_page->hash_elem;
}

bool
vm_copy_uninit_page (struct page* old_page, struct page* new_page) {
	bool succ = false;
	succ = uninit_copy_page(new_page, old_page->va, old_page->uninit.init, old_page->uninit.type, old_page->uninit.aux, old_page->uninit.page_initializer);
	new_page->writable = old_page->writable;
	return succ;
}

bool
vm_copy_claim_page (struct page* old_page, struct page* new_page) {
	new_page->operations = old_page->operations;
	new_page->va = old_page->va;
	new_page->writable = old_page->writable;
	new_page->owner = thread_current();

	//to obtain kva
	struct frame *frame = vm_get_frame ();
	if (frame == NULL) {
		free(frame);
	}

	/* Set links */
	frame->page = new_page;
	new_page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	uint64_t* cur_pml4 = thread_current()->pml4;
	if (pml4_get_page(cur_pml4, new_page->va) != NULL) {
		free(frame);
		return false;
	} else {
		if (!pml4_set_page(cur_pml4, new_page->va, frame->kva, new_page->writable)) {
			free(frame);
			palloc_free_page(new_page->va);
			return false; 
		}
	}
	memcpy(new_page->frame->kva, old_page->frame->kva, PGSIZE);
	return true;
}

void
delete_page_by_hash (struct hash_elem* e, void* aux) {
	// printf("delete hash work\n");
	struct page* d_page = hash_entry(e, struct page, hash_elem);
	// printf("d_page: %p\n", d_page);
	// printf("d_page va: %p\n", d_page->va);

	vm_dealloc_page(d_page);
	//TODO: ADD release aux for each typess in destroy function
	//TODO: use dealloc and modify each destroy function
}