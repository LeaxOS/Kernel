/**
 * @file buddy_system.c
 * @brief Système buddy pour la gestion de la fragmentation
 * 
 * Implémente l'algorithme buddy system pour minimiser la fragmentation
 * de la mémoire physique.
 */

#include "../../../Include/stdint.h"
#include "../../../Include/stddef.h"
#include "../../../Include/stdbool.h"
#include "phys_page.h"

#define MAX_ORDER 11  // 2^11 = 2048 pages = 8MB max

/**
 * @brief Structure pour une liste libre d'un ordre donné
 */
typedef struct {
    page_t* head;           ///< Tête de la liste libre
    size_t count;           ///< Nombre de blocs libres
} free_list_t;

/**
 * @brief Zone buddy pour chaque zone mémoire
 */
typedef struct {
    free_list_t free_lists[MAX_ORDER + 1];  ///< Listes libres par ordre
    size_t total_pages;                      ///< Nombre total de pages
    size_t free_pages;                       ///< Nombre de pages libres
} buddy_zone_t;

static buddy_zone_t buddy_zones[ZONE_COUNT];

/**
 * @brief Initialise le système buddy
 * @param zone Zone mémoire à initialiser
 * @param start_addr Adresse de début de la zone
 * @param size Taille de la zone en octets
 */
void buddy_init_zone(memory_zone_t zone, uint64_t start_addr, size_t size) {
    // TODO: Initialisation d'une zone buddy
    if (zone >= ZONE_COUNT) return;
    
    buddy_zone_t* bz = &buddy_zones[zone];
    
    // Initialiser les listes libres
    for (int i = 0; i <= MAX_ORDER; i++) {
        bz->free_lists[i].head = NULL;
        bz->free_lists[i].count = 0;
    }
    
    bz->total_pages = size / PAGE_SIZE;
    bz->free_pages = 0;
}

/**
 * @brief Trouve l'adresse du buddy d'un bloc
 * @param addr Adresse du bloc
 * @param order Ordre du bloc
 * @return Adresse du buddy
 */
static uint64_t get_buddy_addr(uint64_t addr, unsigned int order) {
    uint64_t page_idx = addr >> PAGE_SHIFT;
    uint64_t buddy_idx = page_idx ^ (1 << order);
    return buddy_idx << PAGE_SHIFT;
}

/**
 * @brief Alloue un bloc dans le système buddy
 * @param zone Zone mémoire
 * @param order Ordre d'allocation
 * @return Adresse du bloc alloué ou 0 si échec
 */
uint64_t buddy_alloc(memory_zone_t zone, unsigned int order) {
    // TODO: Allocation buddy
    if (zone >= ZONE_COUNT || order > MAX_ORDER) {
        return 0;
    }
    
    buddy_zone_t* bz = &buddy_zones[zone];
    
    // Chercher un bloc libre de l'ordre demandé ou supérieur
    for (unsigned int current_order = order; current_order <= MAX_ORDER; current_order++) {
        if (bz->free_lists[current_order].head != NULL) {
            // TODO: Retirer le bloc de la liste libre
            // TODO: Diviser le bloc si nécessaire
            break;
        }
    }
    
    return 0;
}

/**
 * @brief Libère un bloc dans le système buddy
 * @param zone Zone mémoire
 * @param addr Adresse du bloc
 * @param order Ordre du bloc
 */
void buddy_free(memory_zone_t zone, uint64_t addr, unsigned int order) {
    // TODO: Libération buddy avec coalescence
    if (zone >= ZONE_COUNT || order > MAX_ORDER) {
        return;
    }
    
    buddy_zone_t* bz = &buddy_zones[zone];
    
    // TODO: Tenter de fusionner avec le buddy
    // TODO: Ajouter à la liste libre appropriée
}

/**
 * @brief Obtient les statistiques d'une zone buddy
 * @param zone Zone mémoire
 * @param total_pages Pointeur pour stocker le total
 * @param free_pages Pointeur pour stocker les pages libres
 */
void buddy_get_stats(memory_zone_t zone, size_t* total_pages, size_t* free_pages) {
    if (zone >= ZONE_COUNT) return;
    
    buddy_zone_t* bz = &buddy_zones[zone];
    
    if (total_pages) *total_pages = bz->total_pages;
    if (free_pages) *free_pages = bz->free_pages;
}
