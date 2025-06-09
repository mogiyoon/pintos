/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "threads/mmu.h"
#include "userprog/exception.h"
#include "intrinsic.h"

struct list frame_table;
struct lock frame_lock;
static struct list_elem *clock_ptr = NULL;

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
	list_init(&frame_table);
	lock_init(&frame_lock);
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

	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */

		/* TODO: Insert the page into the spt. */
		struct page *page = malloc(sizeof(struct page));
		if(!page)
			goto err;

		typedef bool (*initializer_by_type)(struct page *, enum vm_type, void *);
		initializer_by_type initializer = NULL;

		switch (VM_TYPE(type))
		{
			case VM_ANON:
				initializer = anon_initializer;
				break;
			case VM_FILE:
				initializer = file_backed_initializer;
				break;
		}

		uninit_new(page, upage, init, type, aux, initializer);
		page->writable = writable;
		return spt_insert_page(spt, page);
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	/* TODO: Fill this function. */
	struct page *page = (struct page *)malloc(sizeof(struct page));
	page->va = pg_round_down(va);

	struct hash_elem *e = hash_find(&spt->spt_hash, &page->hash_elem);
	free(page);

	if(e == NULL)
		return NULL;

	return hash_entry(e, struct page, hash_elem);
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	/* TODO: Fill this function. */
	struct hash_elem *result = hash_insert(&spt->spt_hash, &page->hash_elem);
	return result ? false : true;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	hash_delete(&thread_current()->spt.spt_hash, &page->hash_elem);
	vm_dealloc_page (page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	// TODO: The policy for eviction is up to you.
	ASSERT(!list_empty(&frame_table));
	lock_acquire(&frame_lock);
	
	// list를 한 바퀴 돌고도 victim을 못찾은 경우, 강제로 선정하기 위한 포인터
	struct list_elem *start = clock_ptr;

	if (clock_ptr == NULL || clock_ptr == list_end(&frame_table))
		clock_ptr = list_begin(&frame_table);

	start = clock_ptr;

	struct frame *victim = NULL;
	
	while(1){
		victim = list_entry(clock_ptr, struct frame, frame_elem);
		struct page *page = victim->page;

		if(page != NULL && !pml4_is_accessed(thread_current()->pml4, page->va)){
			break;
		}
		if(page != NULL)
			pml4_set_accessed(thread_current()->pml4, page->va, false);

		clock_ptr = list_next(clock_ptr);
		if(clock_ptr == list_end(&frame_table))
			clock_ptr = list_begin(&frame_table);

		// 찾을 수 없는 경우, 강제로 start를 victim으로 선정.
		// 최대 한 바퀴만 루프를 돌게 하여 데드락 가능성 차단. swap-anon에서 무한루프 해결
		if(clock_ptr == start)
			break;
	}

	clock_ptr = list_next(clock_ptr);
	if(clock_ptr == list_end(&frame_table))
		clock_ptr = list_begin(&frame_table);
	
	lock_release(&frame_lock);
	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */
	ASSERT(victim != NULL);
	ASSERT(victim->page != NULL);

	if(!swap_out(victim->page))
		PANIC("vm_evict : swap out failed");
	victim->page = NULL;

	return victim;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	/* TODO: Fill this function. */
	
	struct frame *frame = (struct frame *)malloc(sizeof(struct frame));
	ASSERT(frame != NULL);

	frame->kva = palloc_get_page(PAL_USER | PAL_ZERO);

	if(frame->kva == NULL){
		frame = vm_evict_frame();
	}else{
		list_push_back(&frame_table, &frame->frame_elem);
	}
	frame->page = NULL;
	ASSERT(frame->page == NULL);

	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
	bool success = false;
	addr = pg_round_down(addr);
	struct thread *curr = thread_current();

	while (curr->stack_bottom > addr){
		curr->stack_bottom -= PGSIZE;
		if(!vm_alloc_page(VM_ANON | VM_MARKER_0, curr->stack_bottom, true))
			return;
		if(!vm_claim_page(curr->stack_bottom))
			return;
	}
	// printf("GROW stack at %p (rounded to %p)\n", addr, pg_round_down(addr));

}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */
	if(addr == NULL || is_kernel_vaddr(addr))
		return false;

	struct page *page = NULL;
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;

	if(not_present){
		// 스택 포인터 추출
		void *rsp;
		if (user)
			rsp = f->rsp;
		else
			thread_current()->stack_pointer;

		// case 1: PUSH 등으로 rsp보다 8바이트 아래 주소에 접근한 경우 (스택 미리 증가)
		if(STACK_LIMIT <= rsp - 8 && rsp - 8 == addr && addr <= USER_STACK){
			vm_stack_growth(addr);
			return true;
		}
		// case 2: rsp 이후 주소에 접근한 일반적인 스택 확장 상황
		else if(STACK_LIMIT <= rsp && rsp <= addr && addr <= USER_STACK){
			vm_stack_growth(addr);
			return true;
		}
		page = spt_find_page(spt, addr);

		// printf("FAULT addr: %p, rsp: %p, user: %d, write: %d, not_present: %d\n", addr, f->rsp, user, write, not_present);
		if(!page || (write && !page->writable))
			return false;
		return vm_do_claim_page(page);
	}
	return false;
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va UNUSED) {
	// struct page *page = NULL;
	/* TODO: Fill this function */
	struct page *page = spt_find_page(&thread_current()->spt, va);
	if(page == NULL)
		return false;

	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	// 변환에 성공하면 swap-in, 실패하면 frame 메모리 free
	if(!pml4_set_page(thread_current()->pml4, page->va, frame->kva, page->writable)){
		return false;
	}

	return swap_in (page, frame->kva);
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	hash_init(spt, page_hash, page_less, NULL);
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
	struct hash_iterator i;
	struct page *src_page, *dst_page;
	hash_first(&i, &src->spt_hash);

	while(hash_next(&i)){
		src_page = hash_entry(hash_cur(&i), struct page, hash_elem);
		enum vm_type type = src_page->operations->type;
		void *upage = src_page->va;
		bool writable = src_page->writable;

		if(type == VM_UNINIT)
		{
			void *aux = src_page->uninit.aux;
			vm_alloc_page_with_initializer(page_get_type(src_page), upage, writable, src_page->uninit.init, aux);
		}
		else if(type == VM_FILE)
		{
			struct load_info *li = malloc(sizeof(struct load_info));
			li->file = src_page->file.file;
			li->offset = src_page->file.offset;
			li->read_bytes = src_page->file.read_bytes;

			// init은 file_backed_initializer에서 수행
			if(!vm_alloc_page_with_initializer(type, upage, writable, NULL, li));

			dst_page = spt_find_page(dst, upage);
			file_backed_initializer(dst_page, type, NULL);
			dst_page->frame = src_page->frame;
			pml4_set_page(thread_current()->pml4, dst_page->va, src_page->frame->kva, src_page->writable);
		}
		else{
			if(!vm_alloc_page(type, upage, writable))
				return false;
			if(!vm_claim_page(upage))
				return false;
			dst_page = spt_find_page(dst, upage);
			memcpy(dst_page->frame->kva, src_page->frame->kva, PGSIZE);
		}
	}
	return true;
}

/* spt kill helper function - if my method doesn't work */
void hash_page_kill (struct hash_elem *e, void *aux){
	struct page *p = hash_entry(e, struct page, hash_elem);
	destroy(p);
	free(p);
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	hash_clear(&spt->spt_hash, hash_page_kill);
}

/* Returns a hash value for the page based on its user va.
 * Used as key in the supplemental page table (SPT) hash map. */
uint64_t page_hash(const struct hash_elem *e, void *aux){
	const struct page *p = hash_entry(e, struct page, hash_elem);
	return hash_bytes(&p->va, sizeof p->va);
}

/* Compares two pages by their va.
 * Used for ordering elements in the SPT hash map to resolve collisions. */
bool page_less(const struct hash_elem *a, const struct hash_elem *b, void *aux){
	struct page *pa = hash_entry(a, struct page, hash_elem);
	struct page *pb = hash_entry(b, struct page, hash_elem);

	return pa->va < pb->va;
}