
/**
 * pagevec_swap_free - try to free swap space from the pages in a pagevec
 * @pvec: pagevec with swapcache pages to free the swap space of
 *
 * The caller needs to hold an extra reference to each page and
 * not hold the page lock on the pages.  This function uses a
 * trylock on the page lock so it may not always free the swap
 * space associated with a page.
 */
void ax8swap_pagevec_swap_free(struct pagevec *pvec)
{
	int i;

	for (i = 0; i < pagevec_count(pvec); i++) {
		struct page *page = pvec->pages[i];

		if (PageSwapCache(page) && trylock_page(page)) {
			try_to_free_swap(page);
			unlock_page(page);
		}
	}
}


struct address_space *ax8swap_swapper_space;

/*
 * Perform any setup for the swap system
 */
void ax8swap_swap_setup(void)
{
	bdi_init(ax8swap_swapper_space->backing_dev_info);
}
