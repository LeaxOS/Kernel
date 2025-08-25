/**
 * @file vmalloc.h
 * @brief Virtual memory allocator interface
 * 
 * This header defines the interface for the virtual memory allocator,
 * which provides functions for allocating and managing virtual memory
 * regions.
 * 
 * @author LeaxOS Team
 * @date 2025
 * @version 1.0
 */

#ifndef LEAX_KERNEL_MM_VMALLOC_H
#define LEAX_KERNEL_MM_VMALLOC_H

#ifdef __cplusplus
extern "C" {
#endif

#include "stddef.h"
#include "stdint.h"
#include "stdbool.h"

/* Forward declarations */
typedef struct vm_area_struct vm_area_t;
typedef struct vm_region_struct vm_region_t;

/* Virtual page size definition */
#define VM_PAGE_SIZE 4096
#define VM_PAGE_MASK (~(VM_PAGE_SIZE - 1))
#define VM_NUM_PAGES(addr) (((addr) + VM_PAGE_SIZE - 1) / VM_PAGE_SIZE)

/* virtual page allocation flags */
#define VM_FLAG_READ  (1 << 0)
#define VM_FLAG_WRITE (1 << 1)
#define VM_FLAG_EXEC  (1 << 2)
#define VM_FLAG_USER  (1 << 3)

