/**
 * @file page_alloc.c
 * @brief Physical page allocator
 * 
 * @author LeaxOS Team
 * @version 1.0
 */

#include "stdint.h"
#include "stddef.h"
#include "page_alloc.h"
#include "phys_page.h"

/**
 * @brief Alloue une page avec des flags spécifiques
 * @param flags Flags d'allocation (GFP_*)
 * @return Pointeur vers la structure page ou NULL
 */
page_t* alloc_page(unsigned int flags) {
    // TODO: Allocation d'une page avec flags
    return NULL;
}

/**
 * @brief Alloue plusieurs pages contiguës
 * @param order Ordre d'allocation (2^order pages)
 * @param flags Flags d'allocation
 * @return Pointeur vers la première page ou NULL
 */
page_t* alloc_pages(unsigned int order, unsigned int flags) {
    // TODO: Allocation de 2^order pages contiguës
    return NULL;
}

/**
 * @brief Libère une page
 * @param page Pointeur vers la page à libérer
 */
void free_page(page_t* page) {
    // TODO: Libération d'une page
}

/**
 * @brief Libère plusieurs pages
 * @param page Pointeur vers la première page
 * @param order Ordre de libération
 */
void free_pages(page_t* page, unsigned int order) {
    // TODO: Libération de 2^order pages
}

/**
 * @brief Obtient une page physique à partir d'une adresse
 * @param addr Adresse physique
 * @return Pointeur vers la structure page
 */
page_t* get_page(uint64_t addr) {
    // TODO: Conversion adresse -> page
    return NULL;
}

/**
 * @brief Incrémente le compteur de références d'une page
 * @param page Pointeur vers la page
 */
void get_page_ref(page_t* page) {
    if (page) {
        page->ref_count++;
    }
}

/**
 * @brief Décrémente le compteur de références d'une page
 * @param page Pointeur vers la page
 * @return true si la page peut être libérée
 */
bool put_page_ref(page_t* page) {
    if (page && page->ref_count > 0) {
        page->ref_count--;
        return page->ref_count == 0;
    }
    return false;
}
