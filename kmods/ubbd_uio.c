#include "ubbd_internal.h"

static int ubbd_irqcontrol(struct uio_info *info, s32 irq_on)
{
	struct ubbd_device *ubbd_dev = container_of(info, struct ubbd_device, uio_info);

	queue_work(ubbd_dev->task_wq, &ubbd_dev->complete_work);

	return 0;
}

static void ubbd_vma_open(struct vm_area_struct *vma)
{
	struct ubbd_device *ubbd_dev = vma->vm_private_data;

	pr_debug("vma_open\n");
	ubbd_dev_get(ubbd_dev);
}

static void ubbd_vma_close(struct vm_area_struct *vma)
{
	struct ubbd_device *ubbd_dev = vma->vm_private_data;

	pr_debug("vma_close\n");
	ubbd_dev_put(ubbd_dev);
}

static int ubbd_find_mem_index(struct vm_area_struct *vma)
{
	struct ubbd_device *ubbd_dev = vma->vm_private_data;
	struct uio_info *info = &ubbd_dev->uio_info;

	if (vma->vm_pgoff < MAX_UIO_MAPS) {
		if (info->mem[vma->vm_pgoff].size == 0)
			return -1;
		return (int)vma->vm_pgoff;
	}
	return -1;
}

static struct page *ubbd_try_get_data_page(struct ubbd_device *ubbd_dev, uint32_t dpi)
{
	struct page *page;

	page = xa_load(&ubbd_dev->data_pages_array, dpi);
	if (unlikely(!page)) {
		pr_debug("Invalid addr to data page mapping (dpi %u) on device %s\n",
		       dpi, ubbd_dev->name);
		return NULL;
	}
	
	return page;
}

static vm_fault_t ubbd_vma_fault(struct vm_fault *vmf)
{
	struct ubbd_device *ubbd_dev = vmf->vma->vm_private_data;
	struct uio_info *info = &ubbd_dev->uio_info;
	struct page *page;
	unsigned long offset;
	void *addr;

	int mi = ubbd_find_mem_index(vmf->vma);
	if (mi < 0)
		return VM_FAULT_SIGBUS;

	offset = (vmf->pgoff - mi) << PAGE_SHIFT;

	if (offset < ubbd_dev->data_off) {
		addr = (void *)(unsigned long)info->mem[mi].addr + offset;
		page = vmalloc_to_page(addr);
	} else {
		uint32_t dpi;

		dpi = (offset - ubbd_dev->data_off) / PAGE_SIZE;
		page = ubbd_try_get_data_page(ubbd_dev, dpi);
		if (!page)
			return VM_FAULT_SIGBUS;
		pr_debug("ubbd uio fault page: %p", page);
	}

	get_page(page);
	pr_debug("ubbd uio fault return page: %p", page);
	vmf->page = page;
	return 0;
}

static const struct vm_operations_struct ubbd_vm_ops = {
	.open = ubbd_vma_open,
	.close = ubbd_vma_close,
	.fault = ubbd_vma_fault,
};

static int ubbd_uio_mmap(struct uio_info *info, struct vm_area_struct *vma)
{
	struct ubbd_device *ubbd_dev = container_of(info, struct ubbd_device, uio_info);

	vma->vm_flags |= VM_DONTEXPAND | VM_DONTDUMP;
	vma->vm_ops = &ubbd_vm_ops;

	vma->vm_private_data = ubbd_dev;

	if (vma_pages(vma) != ubbd_dev->mmap_pages)
		return -EINVAL;

	ubbd_vma_open(vma);

	return 0;
}

static int ubbd_uio_open(struct uio_info *info, struct inode *inode)
{
	struct ubbd_device *ubbd_dev = container_of(info, struct ubbd_device, uio_info);

	ubbd_dev->inode = inode;
	pr_debug("open\n");

	return 0;
}

static int ubbd_uio_release(struct uio_info *info, struct inode *inode)
{
	pr_debug("close\n");

	return 0;
}

int ubbd_queue_uio_init(struct ubbd_queue *ubbd_q)
{
	struct uio_info *info;

	info = &ubbd_q->uio_info;
	info->version = __stringify(UBBD_SB_VERSION);

	info->mem[0].name = "ubbd buffer";
	info->mem[0].addr = (phys_addr_t)(uintptr_t)ubbd_q->sb_addr;
	info->mem[0].size = ubbd_q->mmap_pages << PAGE_SHIFT;
	info->mem[0].memtype = UIO_MEM_NONE;

	info->irqcontrol = ubbd_irqcontrol;
	info->irq = UIO_IRQ_CUSTOM;

	info->mmap = ubbd_uio_mmap;
	info->open = ubbd_uio_open;
	info->release = ubbd_uio_release;

	info->name = kasprintf(GFP_KERNEL, "ubbd%d-%d", ubbd_q->ubbd_dev->dev_id, ubbd_q->index);
	if (!info->name)
		return -ENOMEM;

	return uio_register_device(ubbd_uio_root_device, info);
}

void ubbd_queue_uio_destroy(struct ubbd_queue *ubbd_q)
{
	struct uio_info *info = &ubbd_q->uio_info;

	kfree(info->name);
	uio_unregister_device(info);
}
