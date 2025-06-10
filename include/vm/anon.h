#ifndef VM_ANON_H
#define VM_ANON_H
#include "vm/vm.h"
#include "devices/disk.h"

struct page;
enum vm_type;

struct anon_page {
  struct disk* anon_swap_disk;
};

struct swap_tag {
  void* kva;
  struct page* swap_anon_page;
  struct hash_elem swap_hash_elem;
  disk_sector_t swap_sector;
};

void vm_anon_init (void);
bool anon_initializer (struct page *page, enum vm_type type, void *kva);

#endif
