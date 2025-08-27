#ifndef MM_PAGE_TABLE_H
#define MM_PAGE_TABLE_H

#include "mm_common.h"
#include "mm_types.h"

/* Page table flags (architecture-agnostic aliases used in the mm layer) */
#define _PAGE_PRESENT       (1 << 0)        /* Page présente */
#define _PAGE_RW            (1 << 1)        /* Read/Write */
#define _PAGE_USER          (1 << 2)        /* User/Supervisor */
#define PAGE_PRESENT        _PAGE_PRESENT
#define PAGE_WRITABLE       _PAGE_RW
#define PAGE_USER           _PAGE_USER

/* Prototypes used by page table and page fault modules (if any) */
extern int map_page_in_directory(void *pd, virt_addr_t virt_addr, phys_addr_t phys_addr, uint32_t flags);

#endif /* MM_PAGE_TABLE_H */
