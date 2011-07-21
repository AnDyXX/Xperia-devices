
/*
 * Replace the page in the mapping.
 *
 * The number of remaining references must be:
 * 1 for anonymous pages without a mapping
 * 2 for pages with a mapping
 * 3 for pages with a mapping and PagePrivate set.
 */
static int ax8swap_migrate_page_move_mapping(struct address_space *mapping,
		struct page *newpage, struct page *page)
{
	int expected_count;
	void **pslot;

	if (!mapping) {
		/* Anonymous page without mapping */
		if (page_count(page) != 1)
			return -EAGAIN;
		return 0;
	}

	spin_lock_irq(&mapping->tree_lock);

	pslot = radix_tree_lookup_slot(&mapping->page_tree,
 					page_index(page));

	expected_count = 2 + !!PagePrivate(page);
	if (page_count(page) != expected_count ||
			(struct page *)radix_tree_deref_slot(pslot) != page) {
		spin_unlock_irq(&mapping->tree_lock);
		return -EAGAIN;
	}

	if (!page_freeze_refs(page, expected_count)) {
		spin_unlock_irq(&mapping->tree_lock);
		return -EAGAIN;
	}

	/*
	 * Now we know that no one else is looking at the page.
	 */
	get_page(newpage);	/* add cache reference */
	if (PageSwapCache(page)) {
		SetPageSwapCache(newpage);
		set_page_private(newpage, page_private(page));
	}

	radix_tree_replace_slot(pslot, newpage);

	page_unfreeze_refs(page, expected_count);
	/*
	 * Drop cache reference from old page.
	 * We know this isn't the last reference.
	 */
	__put_page(page);

	/*
	 * If moved to a different zone then also account
	 * the page for that zone. Other VM counters will be
	 * taken care of when we establish references to the
	 * new page and drop references to the old page.
	 *
	 * Note that anonymous pages are accounted for
	 * via NR_FILE_PAGES and NR_ANON_PAGES if they
	 * are mapped to swap space.
	 */
	__dec_zone_page_state(page, NR_FILE_PAGES);
	__inc_zone_page_state(newpage, NR_FILE_PAGES);

	spin_unlock_irq(&mapping->tree_lock);

	return 0;
}

