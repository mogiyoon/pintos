#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "list.h"

#define HEAP_MAX_SIZE 64

struct heap_elem {
  int heap_index;
};

#define heap_entry(HEAP_ELEM, STRUCT, MEMBER)                   \
	((STRUCT *) ((uint8_t *) &(HEAP_ELEM)->heap_index        \
		- offsetof (STRUCT, MEMBER.heap_elem)))

typedef bool heap_cmp_func (const struct heap_elem *a,
		const struct heap_elem *b,
		void *aux);

struct heap {
  size_t elem_cnt;
  heap_cmp_func *cmp;
  struct heap_elem* heap_head;
  void* aux;
};