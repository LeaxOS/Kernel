/**
 * physical_page.h
 * Header implementation for physical memory pages.
 * @date 25/08/25
 */

/*
 * physical_page.h
 * Header for physical memory page descriptor.
 */

#ifndef LEAX_KERNEL_MM_INCLUDE_PHYSICAL_PAGE_H
#define LEAX_KERNEL_MM_INCLUDE_PHYSICAL_PAGE_H

#ifdef __cplusplus
extern "C" {
#endif

/* Include the project's stdint.h using a relative path from Mm/Include */
#include "stdint.h"

/* Physical page descriptor structure */
typedef struct PhysicalPage {
    uint64_t frame_number; // Frame number of the physical page
    uint32_t flags;        // Flags for the physical page
} physical_page_t;

void init_physical_page(physical_page_t *page, uint64_t frame_number);
void set_page_flags(physical_page_t *page, uint32_t flags);
uint32_t get_page_flags(const physical_page_t *page);

#ifdef __cplusplus
}
#endif

#endif /* LEAX_KERNEL_MM_INCLUDE_PHYSICAL_PAGE_H */