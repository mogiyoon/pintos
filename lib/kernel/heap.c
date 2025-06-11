#include <stdio.h>
#include "heap.h"
#include "../debug.h"
#include "threads/malloc.h"
#include "vm/vm.h"

bool
heap_init (struct heap* h, heap_cmp_func* cmp, void* aux) {
  h->elem_cnt = 0;
  h->cmp = cmp;
  h->heap_head = calloc(HEAP_MAX_SIZE, sizeof (struct heap_elem*));
  h->aux = aux;

  if (h->heap_head == NULL) {
    return false;
  }
}

void
heap_insert (struct heap* h, struct heap_elem* new) {
  h->heap_head[h->elem_cnt] = new;
  h->elem_cnt++;
}

// heap_modify