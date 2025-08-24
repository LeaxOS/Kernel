/**
 * isolation_page.c
 * Implementation of page isolation mechanisms.
 */

/*
 * This function checks whether the range [start_pfn, end_pfn) includes
 * unmovable pages or not. The range must fall into a single pageblock and
 * consequently belong to a single zone.
 *
 * PageLRU check without isolation or lru_lock could race so that
 * MIGRATE_MOVABLE block might include unmovable pages. Similarly, pages
 * with movable_ops can only be identified some time after they were
 * allocated. So you can't expect this function should be exact.
 *
 * Returns a page without holding a reference. If the caller wants to
 * dereference that page (e.g., dumping), it has to make sure that it
 * cannot get removed (e.g., via memory unplug) concurrently.
 *
 * 
 * Credits for this comment btw: file `linux/mm/page_isolation.c`
 */
