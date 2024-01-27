﻿#include "sys.h"
#include "linux/pid.h"
#include "linux/printk.h"

int rwProcMem_open(struct inode *inode, struct file *filp) {
	return 0;
}

int rwProcMem_release(struct inode *inode, struct file *filp) {
	return 0;
}


ssize_t rwProcMem_read(struct file* filp, char __user* buf, size_t size, loff_t* ppos) {
	char data[17] = { 0 };
	unsigned long read = x_copy_from_user(data, buf, 17);
	if (read == 0) {
		pid_t pid = (pid_t)*(size_t*)&data;
		size_t proc_virt_addr = *(size_t*)&data[8];
		bool is_force_read = data[16] == '\x01' ? true : false;
		size_t read_size = 0;
		struct pid * pid_struct = find_get_pid(pid);
		if(!pid_struct){
			return -EINVAL;
		}

		if (is_force_read == false && !check_proc_map_can_read(pid_struct, proc_virt_addr, size)) {
			put_pid(pid_struct);
			return -EFAULT;
		}

		while (read_size < size) {
			size_t phy_addr = 0;
			size_t pfn_sz = 0;
			char *lpOutBuf = NULL;


#ifdef CONFIG_USE_PAGEMAP_FILE_CALC_PHY_ADDR
			struct file * pFile = open_pagemap(pid_nr(proc_pid_struct));
			printk_debug(KERN_INFO "open_pagemap %d\n", pFile);
			if (!pFile) { break; }

			phy_addr = get_pagemap_phy_addr(pFile, proc_virt_addr);

			close_pagemap(pFile);
			printk_debug(KERN_INFO "pagemap phy_addr:0x%zx\n", phy_addr);
#endif

#ifdef CONFIG_USE_PAGE_TABLE_CALC_PHY_ADDR
			pte_t *pte;

			bool old_pte_can_read;
			phy_addr = get_proc_phy_addr(pid_struct, proc_virt_addr + read_size, (pte_t*)&pte);
			printk_debug(KERN_INFO "calc phy_addr:0x%zx\n", phy_addr);
#endif
			if (phy_addr == 0) {
				break;
			}

#ifdef CONFIG_USE_PAGE_TABLE_CALC_PHY_ADDR
			old_pte_can_read = is_pte_can_read(pte);
			if (is_force_read) {
				if (!old_pte_can_read) {
					if (!change_pte_read_status(pte, true)) { break; }

				}
			}
			else if (!old_pte_can_read) { break; }
#endif

			pfn_sz = size_inside_page(phy_addr, ((size - read_size) > PAGE_SIZE) ? PAGE_SIZE : (size - read_size));
			printk_debug(KERN_INFO "pfn_sz:%zu\n", pfn_sz);


			lpOutBuf = (char*)(buf + read_size);
			read_ram_physical_addr(phy_addr, lpOutBuf, false, pfn_sz);


#ifdef CONFIG_USE_PAGE_TABLE_CALC_PHY_ADDR
			if (is_force_read && old_pte_can_read == false) {
				change_pte_read_status(pte, false);
			}
#endif

			read_size += pfn_sz;
		}

		put_pid(pid_struct);
		return read_size;
	} else {
		printk_debug(KERN_INFO "READ FAILED ret:%lu, user:%p, size:%zu\n", read, buf, size);

	}
	return -EFAULT;
}

ssize_t rwProcMem_write(struct file* filp, const char __user* buf, size_t size, loff_t *ppos) {
	char data[17] = { 0 };
	unsigned long write = x_copy_from_user(data, buf, 17);
	if (write == 0) {
		pid_t pid = (pid_t)*(size_t*)data;
		size_t proc_virt_addr = *(size_t*)&data[8];
		bool is_force_write = data[16] == '\x01' ? true : false;
		size_t write_size = 0;
		struct pid * pid_struct = find_get_pid(pid);
		if(!pid_struct){
			return -EINVAL;
		}

		if (is_force_write == false && !check_proc_map_can_write(pid_struct, proc_virt_addr, size)) {
			put_pid(pid_struct);
			return -EFAULT;
		}

		while (write_size < size) {
			size_t phy_addr = 0;
			size_t pfn_sz = 0;
			char *lpInputBuf = NULL;

#ifdef CONFIG_USE_PAGEMAP_FILE_CALC_PHY_ADDR
			struct file * pFile = open_pagemap(pid_nr(proc_pid_struct));
			printk_debug(KERN_INFO "open_pagemap %d\n", pFile);
			if (!pFile) { break; }

			phy_addr = get_pagemap_phy_addr(pFile, proc_virt_addr);

			close_pagemap(pFile);
#endif

#ifdef CONFIG_USE_PAGE_TABLE_CALC_PHY_ADDR
			pte_t *pte;
			bool old_pte_can_write;
			phy_addr = get_proc_phy_addr(pid_struct, proc_virt_addr + write_size, (pte_t*)&pte);
#endif

			printk_debug(KERN_INFO "phy_addr:0x%zx\n", phy_addr);
			if (phy_addr == 0) {
				break;
			}


#ifdef CONFIG_USE_PAGE_TABLE_CALC_PHY_ADDR
			old_pte_can_write = is_pte_can_write(pte);
			if (is_force_write) {
				if (!old_pte_can_write) {
					if (!change_pte_write_status(pte, true)) { break; }
				}
			}
			else if (!old_pte_can_write) { break; }
#endif

			pfn_sz = size_inside_page(phy_addr, ((size - write_size) > PAGE_SIZE) ? PAGE_SIZE : (size - write_size));
			printk_debug(KERN_INFO "pfn_sz:%zu\n", pfn_sz);



			lpInputBuf = (char*)(((size_t)buf + (size_t)17 + write_size));
			write_ram_physical_addr(phy_addr, lpInputBuf, false, pfn_sz);

#ifdef CONFIG_USE_PAGE_TABLE_CALC_PHY_ADDR
			if (is_force_write && old_pte_can_write == false) {
				change_pte_write_status(pte, false);
			}
#endif

			write_size += pfn_sz;
		}
		put_pid(pid_struct);
		return write_size;
	} else {
		printk_debug(KERN_INFO "WRITE FAILED ret:%lu, user:%p, size:%zu\n", write, buf, size);
	}
	return -EFAULT;
}



static inline long DispatchCommand(unsigned int cmd, unsigned long arg) {
	switch (cmd) {
	case IOCTL_GET_PROCESS_MAPS_COUNT:
	{
		pid_t pid;
		uint64_t res;
		struct pid * pid_struct;
		if (x_copy_from_user((void*)&pid, (void*)arg, 8)) {
			return -EINVAL;
		}
		pid_struct = find_get_pid(pid);
		if(!pid_struct){
			return -EINVAL;
		}
		res = get_proc_map_count(pid_struct);
		put_pid(pid_struct);

		return res;
	}
	case IOCTL_GET_PROCESS_MAPS_LIST:
	{
		char buf[24];
		size_t name_len, buf_size;
		pid_t pid;
		struct pid * pid_struct;
		int have_pass = 0;
		int count = 0;
		unsigned char res;
		if (x_copy_from_user((void*)buf, (void*)arg, 24)) {
			return -EINVAL;
		}
		pid = (pid_t)*(size_t*)buf;
		name_len = *(size_t*)&buf[8];
		buf_size = *(size_t*)&buf[16];

		pid_struct = find_get_pid(pid);
		if(!pid_struct){
			return -EINVAL;
		}
		count = get_proc_maps_list(pid_struct, name_len, (void*)((size_t)arg + (size_t)1), buf_size - 1, false, &have_pass);
		put_pid(pid_struct);
		res = have_pass == 1;
		if (x_copy_to_user((void*)arg, &res, 1)) {
			return -EFAULT;
		}
		return count;
	}
	case IOCTL_CHECK_PROCESS_ADDR_PHY:
	{
		char buf[16] = { 0 };
		pid_t pid;
		size_t proc_virt_addr;
		struct pid * pid_struct;
#ifdef CONFIG_USE_PAGEMAP_FILE_CALC_PHY_ADDR
		struct file * pFile;
#endif

#ifdef CONFIG_USE_PAGE_TABLE_CALC_PHY_ADDR
		pte_t *pte;
#endif
		size_t ret = 0;
		if (x_copy_from_user((void*)buf, (void*)arg, 16)) {
			return -EFAULT;
		}
		pid = (pid_t)*(size_t*)buf;
		proc_virt_addr = *(size_t*)&buf[8];

#ifdef CONFIG_USE_PAGEMAP_FILE_CALC_PHY_ADDR
		pFile = open_pagemap(pid);
		printk_debug(KERN_INFO "open_pagemap %p\n", pFile);
		if (!pFile) { return -EINVAL; }
		ret = get_pagemap_phy_addr(pFile, proc_virt_addr);
		close_pagemap(pFile);
#endif

#ifdef CONFIG_USE_PAGE_TABLE_CALC_PHY_ADDR
		pid_struct = find_get_pid(pid);
		if(!pid_struct){
			return -EINVAL;
		}
		ret = get_proc_phy_addr(pid_struct, proc_virt_addr, (pte_t*)&pte);
		put_pid(pid_struct);
#endif
		if (ret) {
			return 1;
		}
		return 0;

		break;
	}
	default:
		return -EINVAL;
	}
	return -EINVAL;

}



//static long (*unlocked_ioctl) (struct file *, unsigned int, unsigned long);
//static long (*compat_ioctl) (struct file *, unsigned int cmd, unsigned long arg);
long rwProcMem_ioctl(
	struct file *filp,
	unsigned int cmd,
	unsigned long arg) {
	return DispatchCommand(cmd, arg);
}
loff_t rwProcMem_llseek(struct file* filp, loff_t offset, int orig) {
	unsigned int cmd = 0;
	printk_debug("rwProcMem_llseek offset:%zd\n", (ssize_t)offset);

	if (!!x_copy_from_user((void*)&cmd, (void*)offset, sizeof(unsigned int))) {
		return -EINVAL;
	}
	printk_debug("rwProcMem_llseek cmd:%u\n", cmd);
	return DispatchCommand(cmd, offset + sizeof(unsigned int));
}


static int __init rwProcMem_dev_init(void) {
	int result;
	printk(KERN_EMERG "Start init.\n");
	
	g_rwProcMem_devp = kmalloc(sizeof(struct rwProcMemDev), GFP_KERNEL);
	if (!g_rwProcMem_devp) {
		result = -ENOMEM;
		goto _fail;
	}
	memset(g_rwProcMem_devp, 0, sizeof(struct rwProcMemDev));

	result = alloc_chrdev_region(&g_rwProcMem_devno, 0, 1, DEV_FILENAME);
	g_rwProcMem_major = MAJOR(g_rwProcMem_devno);

	if (result < 0) {
		printk(KERN_EMERG "rwProcMem alloc_chrdev_region failed %d\n", result);
		return result;
	}

	g_rwProcMem_devp->pcdev = kmalloc(sizeof(struct cdev) * 3, GFP_KERNEL);
	cdev_init(g_rwProcMem_devp->pcdev, (struct file_operations*)&rwProcMem_fops);
	g_rwProcMem_devp->pcdev->owner = THIS_MODULE;
	g_rwProcMem_devp->pcdev->ops = (struct file_operations*)&rwProcMem_fops;
	if (cdev_add(g_rwProcMem_devp->pcdev, g_rwProcMem_devno, 1)) {
		printk(KERN_NOTICE "Error in cdev_add()\n");
		result = -EFAULT;
		goto _fail;
	}
	g_Class_devp = class_create(THIS_MODULE, DEV_FILENAME);
	device_create(g_Class_devp, NULL, g_rwProcMem_devno, NULL, "%s", DEV_FILENAME);
	return 0;
_fail:
	unregister_chrdev_region(g_rwProcMem_devno, 1);
	return result;
}

static void __exit rwProcMem_dev_exit(void) {

	printk(KERN_EMERG "Start exit.\n");

	device_destroy(g_Class_devp, g_rwProcMem_devno);
	class_destroy(g_Class_devp);

	cdev_del(g_rwProcMem_devp->pcdev);
	unregister_chrdev_region(g_rwProcMem_devno, 1);
	kfree(g_rwProcMem_devp->pcdev);
	kfree(g_rwProcMem_devp);
	printk(KERN_EMERG "Goodbye, %s\n", DEV_FILENAME);
}

module_init(rwProcMem_dev_init);
module_exit(rwProcMem_dev_exit);

MODULE_AUTHOR("Linux");
MODULE_DESCRIPTION("Linux default module");
MODULE_LICENSE("GPL");

