#ifndef __HIJACKED_TYPE_H__
#define __HIJACKED_TYPE_H__

#include <linux/pipe_fs_i.h>
#include <linux/mmdebug.h>
#include <linux/mm.h>
#include <linux/cgroup.h>
#include <linux/shmem_fs.h>
#include <linux/pagevec.h>

/* Flag allocation requirements to shmem_getpage and shmem_swp_alloc */
enum sgp_type {
	SGP_READ,	/* don't exceed i_size, don't allocate page */
	SGP_CACHE,	/* don't exceed i_size, may allocate page */
	SGP_DIRTY,	/* like SGP_CACHE, but set new page dirty */
	SGP_WRITE,	/* may exceed i_size, may allocate page */
};

struct vmalloc_info {
	unsigned long	used;
	unsigned long	largest_chunk;
};

#ifdef CONFIG_MMU
#define VMALLOC_TOTAL (VMALLOC_END - VMALLOC_START)
extern void get_vmalloc_info(struct vmalloc_info *vmi);
#else

#define VMALLOC_TOTAL 0UL
#define get_vmalloc_info(vmi)			\
do {						\
	(vmi)->used = 0;			\
	(vmi)->largest_chunk = 0;		\
} while(0)
#endif

typedef int (*ax8swap_adjust_pte_type)(struct vm_area_struct *vma, unsigned long address);
extern ax8swap_adjust_pte_type ax8swap_adjust_pte;

typedef void (*ax8swap___flush_dcache_page_type)(struct address_space *mapping, struct page *page);
extern ax8swap___flush_dcache_page_type ax8swap___flush_dcache_page;

void ax8swap_update_mmu_cache(struct vm_area_struct *vma, unsigned long addr, pte_t pte);
void ax8swap_flush_dcache_page(struct page *page);

extern struct meminfo *ax8swap_meminfo;

void ax8swap_show_mem(void);
void ax8swap_block_sync_page(struct page *page);
void ax8swap_mark_buffer_dirty(struct buffer_head *bh);
int ax8swap___set_page_dirty_buffers(struct page *page);
void ax8swap___set_page_dirty(struct page *page,
		struct address_space *mapping, int warn);

int ax8swap_meminfo_proc_show(struct seq_file *m, void *v);

int ax8swap_page_cache_pipe_buf_steal(struct pipe_inode_info *pipe,
				     struct pipe_buffer *buf);

typedef void (*ax8swap_get_vmalloc_info_type)(struct vmalloc_info *vmi);
extern ax8swap_get_vmalloc_info_type ax8swap_get_vmalloc_info;

asmlinkage long sys_ax8swap_mincore(unsigned long start, size_t len,
				unsigned char __user * vec);

asmlinkage long sys_ax8swap_remap_file_pages(unsigned long start, unsigned long size,
			unsigned long prot, unsigned long pgoff,
			unsigned long flags); 

typedef void (*ax8swap_munlock_vma_pages_range_type)(struct vm_area_struct *vma,
			   unsigned long start, unsigned long end) ;

extern ax8swap_munlock_vma_pages_range_type ax8swap_munlock_vma_pages_range;

static inline void
ax8swap_flush_cache_page(struct vm_area_struct *vma, unsigned long user_addr, unsigned long pfn)
{
	if (cpu_isset(smp_processor_id(), vma->vm_mm->cpu_vm_mask)) {
		unsigned long addr = user_addr & PAGE_MASK;
		__cpuc_flush_user_range(addr, addr + PAGE_SIZE, vma->vm_flags);
	}
}

extern struct mutex * ax8swap_shmem_swaplist_mutex;
extern struct list_head * ax8swap_shmem_swaplist;

typedef void (*ax8swap_shmem_truncate_address_only_type)(struct inode *inode);
extern ax8swap_shmem_truncate_address_only_type ax8swap_shmem_truncate_address_only;

swp_entry_t *ax8swap_shmem_swp_entry(struct shmem_inode_info *info, unsigned long index, struct page **page);
swp_entry_t *ax8swap_shmem_swp_alloc(struct shmem_inode_info *info, unsigned long index, enum sgp_type sgp);
int ax8swap_shmem_free_swp(swp_entry_t *dir, swp_entry_t *edir,
						spinlock_t *punch_lock);
void ax8swap_shmem_truncate_range(struct inode *inode, loff_t start, loff_t end);
void ax8swap_shmem_truncate(struct inode *inode);
int ax8swap_shmem_notify_change(struct dentry *dentry, struct iattr *attr);
void ax8swap_shmem_delete_inode(struct inode *inode);
int ax8swap_shmem_unuse(swp_entry_t entry, struct page *page);
int ax8swap_shmem_writepage(struct page *page, struct writeback_control *wbc);

int ax8swap_shmem_getpage(struct inode *inode, unsigned long idx,
			struct page **pagep, enum sgp_type sgp, int *type);

int ax8swap_shmem_fault(struct vm_area_struct *vma, struct vm_fault *vmf);

int ax8swap_shmem_lock(struct file *file, int lock, struct user_struct *user);
void ax8swap_shmem_free_blocks(struct inode *inode, long pages);
int ax8swap_shmem_reserve_inode(struct super_block *sb);
void ax8swap_shmem_free_inode(struct super_block *sb);

typedef void (*ax8swap_vma_prio_tree_remove_type)(struct vm_area_struct *, struct prio_tree_root *);
extern ax8swap_vma_prio_tree_remove_type ax8swap_vma_prio_tree_remove;

typedef void (*ax8swap_user_shm_unlock_type)(size_t, struct user_struct *);
extern ax8swap_user_shm_unlock_type ax8swap_user_shm_unlock;

typedef int (*ax8swap_cap_vm_enough_memory_type)(struct mm_struct *mm, long pages);
extern ax8swap_cap_vm_enough_memory_type ax8swap_cap_vm_enough_memory;

static inline int ax8swap_security_vm_enough_memory(long pages)
{
	WARN_ON(current->mm == NULL);
	return ax8swap_cap_vm_enough_memory(current->mm, pages);
}

static inline int ax8swap_security_vm_enough_memory_mm(struct mm_struct *mm, long pages)
{
	WARN_ON(mm == NULL);
	return ax8swap_cap_vm_enough_memory(mm, pages);
}

static inline int ax8swap_security_vm_enough_memory_kern(long pages)
{
	/* If current->mm is a kernel thread then we will pass NULL,
	   for this specific case that is fine */
	return ax8swap_cap_vm_enough_memory(current->mm, pages);
}

void ax8swap_mmput(struct mm_struct *mm);

typedef void (*ax8swap_exit_aio_type)(struct mm_struct *mm);
extern ax8swap_exit_aio_type ax8swap_exit_aio;

typedef void (*ax8swap_set_mm_exe_file_type)(struct mm_struct *mm, struct file *new_exe_file);
extern ax8swap_set_mm_exe_file_type ax8swap_set_mm_exe_file;

typedef int (*ax8swap_user_shm_lock_type)(size_t, struct user_struct *);
extern ax8swap_user_shm_lock_type ax8swap_user_shm_lock;

#endif
