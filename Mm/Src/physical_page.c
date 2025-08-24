/**
 * physical_page.c
 * Implementation of physical memory page management functions.
 */

#include "physical_page.h"

void init_physical_page(physical_page_t *page, uint32_t frame_number) {
    if (!page) return;
    page->frame_number = frame_number;
    page->flags = 0;
}

void set_page_flags(physical_page_t *page, uint32_t flags) {
    if (!page) return;
    page->flags = flags;
}

uint32_t get_page_flags(const physical_page_t *page) {
    return page ? page->flags : 0u;
}