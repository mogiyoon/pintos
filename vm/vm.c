/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "threads/mmu.h"
#include "userprog/exception.h"
#include "intrinsic.h"

struct list frame_table;

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
	/* TODO: Fill this function. */
	struct frame *frame = (struct frame *)malloc(sizeof(struct frame));
	ASSERT(frame != NULL);

	frame->kva = palloc_get_page(PAL_USER | PAL_ZERO);

	if(frame->kva == NULL)
		frame = vm_evict_frame();
	else
		list_push_back(&frame_table, &frame->frame_elem);

	frame->page = NULL;
	ASSERT(frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
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

	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	struct page *page = spt_find_page(spt, addr);


	if(not_present){
		page = spt_find_page(spt, addr);
		if(page == NULL)
			return false;
		if(write == 1 && page->writable == 0)
			return false;
		return vm_do_claim_page(page);
	}
	void *fault_addr = (void *) rcr2();
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

	/* 의문 1: 페이지 구조체 복사 방식
	- 원래는 struct page를 malloc으로 만들고 필드 직접 복사하려 했음
	- 예: dst_page->va = src_page->va 등
	- 하지만 union 구조와 타입 정보가 섞여 있어 직접 어떻게 복사하지?
	- 해결: vm_alloc_page_with_initializer()로 새 페이지를 생성하고 claim하는 방식으로 대체*/ 

	/* 의문 2: 메모리 할당과 데이터 복사 방식
	- 구조체 자체는 malloc 등으로 커널 힙에 할당해야 함 (palloc은 물리 페이지용)
	- frame은 물리 메모리를 가리키므로 공유 불가 → frame 자체는 복사하지 않음
	- 대신 부모의 frame->kva 내용을 memcpy로 자식 frame에 복사*/

	while(hash_next(&i)){
		src_page = hash_entry(hash_cur(&i), struct page, hash_elem);
		enum vm_type type = src_page->operations->type;

		if(type == VM_UNINIT)
		{
			vm_alloc_page_with_initializer(
				src_page->uninit.type,
				src_page->va,
				src_page->writable,
				src_page->uninit.init,
				src_page->uninit.aux
			);
		}else{
			if(vm_alloc_page(type, src_page->va, src_page->writable) && vm_claim_page(src_page->va)){
				dst_page = spt_find_page(dst, src_page->va);
				memcpy(dst_page->frame->kva, src_page->frame->kva, PGSIZE);
			}
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