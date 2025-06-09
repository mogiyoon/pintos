/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "vm/vm.h"
#include "devices/disk.h"

#include "lib/kernel/bitmap.h"
#include "threads/vaddr.h"		// PGSIZE용
#include "threads/mmu.h"		// pml4

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static bool anon_swap_in (struct page *page, void *kva);
static bool anon_swap_out (struct page *page);
static void anon_destroy (struct page *page);

/* Project 3 : Swap In/Out */
#define SECTORS_PER_PAGE (PGSIZE / DISK_SECTOR_SIZE)
static struct bitmap *swap_table;
static struct lock swap_lock;

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
	/* 1. 스왑 디스크를 가져옵니다. IDE controller 1의 slave 디스크를 사용합니다. */
	swap_disk = disk_get(1,1);
	ASSERT(swap_disk != NULL)	// IDE controller 1의 slave 디스크

	/* 2. 하나의 페이지를 디스크에 저장하려면 필요한 섹터 수를 계산
	   PGSIZE = 4096, DISK_SECTOR_SIZE = 512 이므로 8 섹터가 필요 */
	ASSERT(SECTORS_PER_PAGE > 0);

	/* 3. 디스크 전체를 페이지 단위로 나누었을 때 만들 수 있는 스왑 슬롯 수를 계산 */
	const size_t total_slots = disk_size(swap_disk) / SECTORS_PER_PAGE;
	ASSERT(total_slots > 0);

	/* 4. 스왑 슬롯 관리를 위한 비트맵을 생성합니다.
	   각 비트는 한 슬롯(즉, 한 페이지)에 해당합니다. false는 사용 가능함을 의미합니다. */
	swap_table = bitmap_create(total_slots);
	ASSERT(swap_table != NULL);
	
	/* 5. 모든 스왑 슬롯을 초기에는 비어있는 상태(false)로 설정합니다. */
	bitmap_set_all(swap_table, false);
	lock_init(&swap_lock);
}

/* Initialize the file mapping */
bool
anon_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	// ASSERT(type == VM_ANON);
	page->operations = &anon_ops;

	struct anon_page *anon_page = &page->anon;
	/* Project 3 : VM */
	anon_page->swap_slot_index = -1;
	return true;
}

/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in (struct page *page, void *kva) {
	struct anon_page *anon_page = &page->anon;

	// 1. 스왑 아웃 시 저장한 스왑 슬롯 인덱스를 가져온다
	size_t idx = anon_page->swap_slot_index;
	ASSERT(bitmap_test(swap_table, idx));
	// 2. 스왑 디스크에서 데이터를 읽어와 kva에 복원한다
	for(size_t i = 0; i < SECTORS_PER_PAGE; i++){
		disk_read(swap_disk, (idx * SECTORS_PER_PAGE) + i, kva + (i * DISK_SECTOR_SIZE));
	}

	// 3. 스왑 테이블에서 해당 슬롯을 다시 사용 가능하도록 비어있음 처리
	lock_acquire(&swap_lock);
	bitmap_reset(swap_table, idx);
	lock_release(&swap_lock);

	return true;
}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out (struct page *page) {
	struct anon_page *anon_page = &page->anon;

	lock_acquire(&swap_lock);
	size_t idx = bitmap_scan_and_flip(swap_table, 0, 1, false);

	// 스왑 디스크에 빈 슬롯이 없다면, 커널 패닉
	if(idx == BITMAP_ERROR){
		lock_release(&swap_lock);
		// PANIC("swap space full!");
		return false;
	}
	// 스왑 테이블로 빈 슬롯을 탐색한다
	void *kva = page->frame->kva;		// page->va 로 생각했는데, kva로 해야한다. 물리 주소랑 매핑되는 거니까. (확인 필요)
	for(size_t i = 0; i < SECTORS_PER_PAGE; i++){
		disk_write(swap_disk, (idx * SECTORS_PER_PAGE) + i, kva + (i * DISK_SECTOR_SIZE));
	}

	// 메모리에 있는 페이지 데이터를 스왑 슬롯에 복사한다
	// 복사된 위치 정보를 해당 페이지 구조체에 저장한다
	anon_page->swap_slot_index = idx;
	page->frame->page = NULL;
	page->frame = NULL;
	pml4_clear_page(thread_current()->pml4, page->va);
	lock_release(&swap_lock);
	
	return true;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy (struct page *page) {
	struct anon_page *anon_page = &page->anon;

	if(page->frame == NULL){
		lock_acquire(&swap_lock);
		bitmap_reset(swap_table, anon_page->swap_slot_index);
		lock_release(&swap_lock);
	}else{
		lock_acquire(&swap_lock);
		list_remove(&page->frame->frame_elem);
		lock_release(&swap_lock);
		page->frame->page = NULL;
		free(page->frame);
		page->frame = NULL;
	}
}
