﻿#include "sys.h"
#include "linux/kern_levels.h"
#include "linux/pid.h"
#include "linux/printk.h"
#include "linux/types.h"
#include "linux/mutex.h"

static DEFINE_MUTEX(rwProcMem_mutex);

int rwProcMem_open(struct inode *inode, struct file *filp) { return 0; }

int rwProcMem_release(struct inode *inode, struct file *filp) { return 0; }

ssize_t rwProcMem_read(struct file *filp, char __user *buf, size_t size, loff_t *ppos) {
    char data[17] = {0};
    unsigned long read = x_copy_from_user(data, buf, sizeof(data));
    if (read == 0) {
        pid_t pid = (pid_t) * (size_t *)&data;
        size_t proc_virt_addr = *(size_t *)&data[8];
        bool is_force_read = data[16] == '\x01' ? true : false;
        size_t read_size = 0;
        struct pid *pid_struct = find_get_pid(pid);
        if (!pid_struct) {
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

            pte_t *pte;

            bool old_pte_can_read;
            phy_addr = get_proc_phy_addr(pid_struct, proc_virt_addr + read_size, (pte_t *)&pte);
            printk_debug(KERN_INFO "calc phy_addr:0x%zx\n", phy_addr);
            if (phy_addr == 0) {
                break;
            }

            old_pte_can_read = is_pte_can_read(pte);
            if (is_force_read) {
                if (!old_pte_can_read) {
                    if (!change_pte_read_status(pte, true)) {
                        break;
                    }
                }
            } else if (!old_pte_can_read) {
                break;
            }

            pfn_sz = size_inside_page(phy_addr, ((size - read_size) > PAGE_SIZE) ? PAGE_SIZE : (size - read_size));
            printk_debug(KERN_INFO "pfn_sz:%zu\n", pfn_sz);

            lpOutBuf = (char *)(buf + read_size);
            read_ram_physical_addr(phy_addr, lpOutBuf, false, pfn_sz);

            if (is_force_read && old_pte_can_read == false) {
                change_pte_read_status(pte, false);
            }

            read_size += pfn_sz;
        }

        put_pid(pid_struct);
        return read_size;
    } else {
        printk_debug(KERN_INFO "READ FAILED ret:%lu, user:%p, size:%zu\n", read, buf, size);
    }
    return -EFAULT;
}

ssize_t rwProcMem_write(struct file *filp, const char __user *buf, size_t size, loff_t *ppos) {
    char data[17] = {0};
    unsigned long write = x_copy_from_user(data, buf, sizeof(data));
    if (write == 0) {
        pid_t pid = (pid_t) * (size_t *)data;
        size_t proc_virt_addr = *(size_t *)&data[8];
        bool is_force_write = data[16] == '\x01' ? true : false;
        size_t write_size = 0;
        struct pid *pid_struct = find_get_pid(pid);
        if (!pid_struct) {
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

            pte_t *pte;
            bool old_pte_can_write;
            phy_addr = get_proc_phy_addr(pid_struct, proc_virt_addr + write_size, (pte_t *)&pte);

            printk_debug(KERN_INFO "phy_addr:0x%zx\n", phy_addr);
            if (phy_addr == 0) {
                break;
            }

            old_pte_can_write = is_pte_can_write(pte);
            if (is_force_write) {
                if (!old_pte_can_write) {
                    if (!change_pte_write_status(pte, true)) {
                        break;
                    }
                }
            } else if (!old_pte_can_write) {
                break;
            }

            pfn_sz = size_inside_page(phy_addr, ((size - write_size) > PAGE_SIZE) ? PAGE_SIZE : (size - write_size));
            printk_debug(KERN_INFO "pfn_sz:%zu\n", pfn_sz);

            lpInputBuf = (char *)(((size_t)buf + (size_t)17 + write_size));
            write_ram_physical_addr(phy_addr, lpInputBuf, false, pfn_sz);

            if (is_force_write && old_pte_can_write == false) {
                change_pte_write_status(pte, false);
            }

            write_size += pfn_sz;
        }
        put_pid(pid_struct);
        return write_size;
    } else {
        printk_debug(KERN_INFO "WRITE FAILED ret:%lu, user:%p, size:%zu\n", write, buf, size);
    }
    return -EFAULT;
}

ssize_t rwProcMem_search_int(struct SearchParamsInt *params) {
    pid_t pid = params->pid;
    bool is_force_read = params->is_force_read;
    size_t value_size = 4;
    size_t read_size = 0;
    size_t i = 0;
    size_t num_addresses = params->num_addresses;

    struct pid *pid_struct = find_get_pid(pid);
    if (!pid_struct) {
        return -EINVAL;
    }

    if (num_addresses > 70) {
        num_addresses = 70;
    }

    params->num_matching_addresses = 0;

    for (i = 0; i < num_addresses; ++i) {
        uint64_t proc_virt_addr = params->addresses[i];
        char buf[4] = {0};
        pte_t *pte;
        size_t phy_addr = 0;
        bool old_pte_can_read;
        size_t pfn_sz = 0;
        size_t actual_read = 0;
        int read_value = 0;
        int value_to_compare = params->value_to_compare;

        if (!is_force_read && !check_proc_map_can_read(pid_struct, proc_virt_addr, value_size)) {
            continue;
        }

        phy_addr = get_proc_phy_addr(pid_struct, proc_virt_addr, (pte_t *)&pte);
        if (phy_addr == 0) {
            continue;
        }

        old_pte_can_read = is_pte_can_read(pte);
        if (is_force_read) {
            if (!old_pte_can_read && !change_pte_read_status(pte, true)) {
                continue;
            }
        } else if (!old_pte_can_read) {
            continue;
        }

        pfn_sz = size_inside_page(phy_addr, value_size);
        actual_read = read_ram_physical_addr(phy_addr, buf, true, pfn_sz);
        if (actual_read != pfn_sz) {
            if (is_force_read && !old_pte_can_read) {
                change_pte_read_status(pte, false);
            }
            continue;
        }

        if (is_force_read && !old_pte_can_read) {
            change_pte_read_status(pte, false);
        }

        read_value = *(int*)buf;

        if (read_value == value_to_compare) {
            params->matching_addresses[params->num_matching_addresses++] = proc_virt_addr;
        }

        read_size += pfn_sz;
    }

    put_pid(pid_struct);

    if (params->num_matching_addresses == 0) {
        return -EFAULT;
    }

    return 0;
}

ssize_t rwProcMem_search_float(struct SearchParamsFloat *params) {
    pid_t pid = params->pid;
    bool is_force_read = params->is_force_read;
    size_t value_size = 4;
    size_t read_size = 0;
    size_t i = 0;
    size_t num_addresses = params->num_addresses;

    struct pid *pid_struct = find_get_pid(pid);
    if (!pid_struct) {
        return -EINVAL;
    }

    if (num_addresses > 70) {
        num_addresses = 70;
    }

    params->num_matching_addresses = 0;

    for (i = 0; i < num_addresses; ++i) {
        uint64_t proc_virt_addr = params->addresses[i];
        char buf[4] = {0};
        pte_t *pte;
        size_t phy_addr = 0;
        bool old_pte_can_read;
        size_t pfn_sz = 0;
        size_t actual_read = 0;
        float read_value = 0.0f;
        float value_to_compare = params->value_to_compare;

        if (!is_force_read && !check_proc_map_can_read(pid_struct, proc_virt_addr, value_size)) {
            continue;
        }

        phy_addr = get_proc_phy_addr(pid_struct, proc_virt_addr, (pte_t *)&pte);
        if (phy_addr == 0) {
            continue;
        }

        old_pte_can_read = is_pte_can_read(pte);
        if (is_force_read) {
            if (!old_pte_can_read && !change_pte_read_status(pte, true)) {
                continue;
            }
        } else if (!old_pte_can_read) {
            continue;
        }

        pfn_sz = size_inside_page(phy_addr, value_size);
        actual_read = read_ram_physical_addr(phy_addr, buf, true, pfn_sz);
        if (actual_read != pfn_sz) {
            if (is_force_read && !old_pte_can_read) {
                change_pte_read_status(pte, false);
            }
            continue;
        }

        if (is_force_read && !old_pte_can_read) {
            change_pte_read_status(pte, false);
        }

        read_value = *(float*)buf;

        if (read_value == value_to_compare) {
            params->matching_addresses[params->num_matching_addresses++] = proc_virt_addr;
        }

        read_size += pfn_sz;
    }

    put_pid(pid_struct);

    if (params->num_matching_addresses == 0) {
        return -EFAULT;
    }

    return 0;
}

ssize_t rwProcMem_search_long(struct SearchParamsLong *params) {
    pid_t pid = params->pid;
    bool is_force_read = params->is_force_read;
    size_t value_size = 8;
    size_t read_size = 0;
    size_t i = 0;
    size_t num_addresses = params->num_addresses;

    struct pid *pid_struct = find_get_pid(pid);
    if (!pid_struct) {
        return -EINVAL;
    }

    if (num_addresses > 70) {
        num_addresses = 70;
    }

    params->num_matching_addresses = 0;

    for (i = 0; i < num_addresses; ++i) {
        uint64_t proc_virt_addr = params->addresses[i];
        char buf[8] = {0};
        pte_t *pte;
        size_t phy_addr = 0;
        bool old_pte_can_read;
        size_t pfn_sz = 0;
        size_t actual_read = 0;
        long read_value = 0;
        long value_to_compare = params->value_to_compare;

        if (!is_force_read && !check_proc_map_can_read(pid_struct, proc_virt_addr, value_size)) {
            continue;
        }

        phy_addr = get_proc_phy_addr(pid_struct, proc_virt_addr, (pte_t *)&pte);
        if (phy_addr == 0) {
            continue;
        }

        old_pte_can_read = is_pte_can_read(pte);
        if (is_force_read) {
            if (!old_pte_can_read && !change_pte_read_status(pte, true)) {
                continue;
            }
        } else if (!old_pte_can_read) {
            continue;
        }

        pfn_sz = size_inside_page(phy_addr, value_size);
        actual_read = read_ram_physical_addr(phy_addr, buf, true, pfn_sz);
        if (actual_read != pfn_sz) {
            if (is_force_read && !old_pte_can_read) {
                change_pte_read_status(pte, false);
            }
            continue;
        }

        if (is_force_read && !old_pte_can_read) {
            change_pte_read_status(pte, false);
        }

        read_value = *(long*)buf;

        if (read_value == value_to_compare) {
            params->matching_addresses[params->num_matching_addresses++] = proc_virt_addr;
        }

        read_size += pfn_sz;
    }

    put_pid(pid_struct);

    if (params->num_matching_addresses == 0) {
        return -EFAULT;
    }

    return 0;
}

ssize_t rwProcMem_search_double(struct SearchParamsDouble *params) {
    pid_t pid = params->pid;
    bool is_force_read = params->is_force_read;
    size_t value_size = 8;
    size_t read_size = 0;
    size_t i = 0;
    size_t num_addresses = params->num_addresses;

    struct pid *pid_struct = find_get_pid(pid);
    if (!pid_struct) {
        return -EINVAL;
    }

    if (num_addresses > 70) {
        num_addresses = 70;
    }

    params->num_matching_addresses = 0;

    for (i = 0; i < num_addresses; ++i) {
        uint64_t proc_virt_addr = params->addresses[i];
        char buf[8] = {0};
        pte_t *pte;
        size_t phy_addr = 0;
        bool old_pte_can_read;
        size_t pfn_sz = 0;
        size_t actual_read = 0;
        double read_value = 0.0;
        double value_to_compare = params->value_to_compare;

        if (!is_force_read && !check_proc_map_can_read(pid_struct, proc_virt_addr, value_size)) {
            continue;
        }

        phy_addr = get_proc_phy_addr(pid_struct, proc_virt_addr, (pte_t *)&pte);
        if (phy_addr == 0) {
            continue;
        }

        old_pte_can_read = is_pte_can_read(pte);
        if (is_force_read) {
            if (!old_pte_can_read && !change_pte_read_status(pte, true)) {
                continue;
            }
        } else if (!old_pte_can_read) {
            continue;
        }

        pfn_sz = size_inside_page(phy_addr, value_size);
        actual_read = read_ram_physical_addr(phy_addr, buf, true, pfn_sz);
        if (actual_read != pfn_sz) {
            if (is_force_read && !old_pte_can_read) {
                change_pte_read_status(pte, false);
            }
            continue;
        }

        if (is_force_read && !old_pte_can_read) {
            change_pte_read_status(pte, false);
        }

        read_value = *(double*)buf;

        if (read_value == value_to_compare) {
            params->matching_addresses[params->num_matching_addresses++] = proc_virt_addr;
        }

        read_size += pfn_sz;
    }

    put_pid(pid_struct);

    if (params->num_matching_addresses == 0) {
        return -EFAULT;
    }

    return 0;
}

// based on code extracted from the internet from some kernel module, I don't know the author
uint64_t get_module_info(pid_t pid, const char* name, bool get_base) {
    struct task_struct* task;
    struct mm_struct* mm;
    struct vm_area_struct *vma;
    uint64_t addr = 0;

    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!task)
        return 0;

    mm = get_task_mm(task);
    if (!mm) {
        return 0;
    } else {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
        VMA_ITERATOR(iter, mm, 0);
        for_each_vma(iter, vma) {
#else
        for (vma = mm->mmap; vma; vma = vma->vm_next) {
#endif
            char buf[M_PATH_MAX];
            char *path_nm = "";
            if (vma->vm_file) {
                path_nm = file_path(vma->vm_file, buf, M_PATH_MAX);
                if (!IS_ERR(path_nm)) {
                    if (!strcmp(kbasename(path_nm), name)) {
                        addr = get_base ? vma->vm_start : vma->vm_end;
                        break;
                    }
                }
            }
        }
        mmput(mm);
        return addr;
    }
}

uint64_t get_module_base(pid_t pid, const char* name) {
    return get_module_info(pid, name, true);
}

uint64_t get_module_end(pid_t pid, const char* name) {
    return get_module_info(pid, name, false);
}

static inline long DispatchCommand(unsigned int cmd, unsigned long arg) {
    switch (cmd) {
    case IOCTL_GET_PROCESS_MAPS_COUNT: {
        pid_t pid;
        uint64_t res;
        struct pid *pid_struct;
        if (x_copy_from_user((void *)&pid, (void *)arg, sizeof(pid))) {
            return -EINVAL;
        }
        pid_struct = find_get_pid(pid);
        if (!pid_struct) {
            return -EINVAL;
        }
        res = get_proc_map_count(pid_struct);
        put_pid(pid_struct);

        return res;
    }
    case IOCTL_GET_PROCESS_MAPS_LIST: {
        char buf[24];
        size_t name_len, buf_size;
        pid_t pid;
        struct pid *pid_struct;
        int have_pass = 0;
        uint64_t count = 0;
        if (x_copy_from_user((void *)buf, (void *)arg, sizeof(buf))) {
            return -EINVAL;
        }
        pid = (pid_t) * (size_t *)buf;
        name_len = *(size_t *)&buf[8];
        buf_size = *(size_t *)&buf[16];

        pid_struct = find_get_pid(pid);
        if (!pid_struct) {
            return -EINVAL;
        }
        count = get_proc_maps_list(pid_struct, name_len, (void *)((size_t)arg + (size_t)8), buf_size - 8, false, &have_pass);
        put_pid(pid_struct);
        if (x_copy_to_user((void *)arg, &count, 8)) {
            return -EFAULT;
        }
        return have_pass;
    }
    case IOCTL_CHECK_PROCESS_ADDR_PHY: {
        struct {
            pid_t pid;
            size_t virt_addr_start, virt_addr_end;
        } param;
        size_t proc_virt_addr;
        struct pid *pid_struct;
        struct task_struct *task;
        pte_t *pte;
        size_t ret = 0;
        size_t pages, bufLen, i;
        uint8_t *retBuf;
        if (x_copy_from_user((void *)&param, (void *)arg, sizeof(param))) {
            return -EFAULT;
        }
        if ((param.virt_addr_start | param.virt_addr_end) & (PAGE_SIZE - 1)) {
            return -EINVAL;
        }
        if (param.virt_addr_start >= param.virt_addr_end) {
            return -EINVAL;
        }

        pid_struct = find_get_pid(param.pid);
        if (!pid_struct) {
            return -EINVAL;
        }
        task = pid_task(pid_struct, PIDTYPE_PID);
        if (!task) {
            put_pid(pid_struct);
            return -EINVAL;
        }

#define MAX_MALLOC_SIZE 1024

        pages = (param.virt_addr_end - param.virt_addr_start) / PAGE_SIZE;
        bufLen = (pages + 7) / 8;
        bufLen = bufLen > MAX_MALLOC_SIZE ? MAX_MALLOC_SIZE : bufLen;
        retBuf = kmalloc(bufLen, GFP_KERNEL);
        if (!retBuf) {
            put_pid(pid_struct);
            return -ENOMEM;
        }
        memset(retBuf, 0, bufLen);

        for (proc_virt_addr = param.virt_addr_start, i = 0; proc_virt_addr < param.virt_addr_end; proc_virt_addr += PAGE_SIZE) {
            ret = get_task_proc_phy_addr(task, proc_virt_addr, (pte_t *)&pte);
            if (ret && is_pte_can_read(pte)) {
                retBuf[i / 8] |= 1 << (i % 8);
            }
            i++;
            if (i == MAX_MALLOC_SIZE * 8) {
                if (x_copy_to_user((void *)arg, retBuf, bufLen)) {
                    kfree(retBuf);
                    put_pid(pid_struct);
                    return -EFAULT;
                }
                i = 0;
                memset(retBuf, 0, bufLen);
                arg += MAX_MALLOC_SIZE;
            }
        }
        put_pid(pid_struct);
        if (i && x_copy_to_user((void *)arg, retBuf, (i + 7) / 8)) {
            kfree(retBuf);
            return -EFAULT;
        }
        kfree(retBuf);
        return pages;
    }
    case IOCTL_MEM_SEARCH_INT: {
        struct SearchParamsInt params;
        ssize_t result = -1;
        if (x_copy_from_user((void *)&params, (void *)arg, sizeof(params))) {
            return -EINVAL;
        }

        mutex_lock(&rwProcMem_mutex);

        result = rwProcMem_search_int(&params);

        mutex_unlock(&rwProcMem_mutex);

        if (result < 0) {
            return result;
        }

        if (x_copy_to_user((void *)arg, &params, sizeof(params))) {
            return -EINVAL;
        }

        return 0;
    }
    case IOCTL_MEM_SEARCH_FLOAT: {
        struct SearchParamsFloat params;
        ssize_t result = -1;
        if (x_copy_from_user((void *)&params, (void *)arg, sizeof(params))) {
            return -EINVAL;
        }

        mutex_lock(&rwProcMem_mutex);

        result = rwProcMem_search_float(&params);

        mutex_unlock(&rwProcMem_mutex);

        if (result < 0) {
            return result;
        }

        if (x_copy_to_user((void *)arg, &params, sizeof(params))) {
            return -EINVAL;
        }

        return 0;
    }
    case IOCTL_MEM_SEARCH_LONG: {
        struct SearchParamsLong params;
        ssize_t result = -1;
        if (x_copy_from_user((void *)&params, (void *)arg, sizeof(params))) {
            return -EINVAL;
        }

        mutex_lock(&rwProcMem_mutex);

        result = rwProcMem_search_long(&params);

        mutex_unlock(&rwProcMem_mutex);

        if (result < 0) {
            return result;
        }

        if (x_copy_to_user((void *)arg, &params, sizeof(params))) {
            return -EINVAL;
        }

        return 0;
    }
    case IOCTL_MEM_SEARCH_DOUBLE: {
        struct SearchParamsDouble params;
        ssize_t result = -1;
        if (x_copy_from_user((void *)&params, (void *)arg, sizeof(params))) {
            return -EINVAL;
        }

        mutex_lock(&rwProcMem_mutex);

        result = rwProcMem_search_double(&params);

        mutex_unlock(&rwProcMem_mutex);

        if (result < 0) {
            return result;
        }

        if (x_copy_to_user((void *)arg, &params, sizeof(params))) {
            return -EINVAL;
        }

        return 0;
    }
    case IOCTL_GET_MODULE_RANGE: {
        struct ModuleRange params;
        uint64_t address_base = 0;
        uint64_t address_end = 0;
        if (x_copy_from_user((void *)&params, (void *)arg, sizeof(params))) {
            return -EINVAL;
        }

        address_base = get_module_base(params.pid, params.name);
        address_end = get_module_end(params.pid, params.name);

        params.address_base = address_base;
        params.address_end = address_end;

        if (x_copy_to_user((void *)arg, &params, sizeof(params))) {
            return -EINVAL;
        }

        return 0;
    }
    default:
        return -EINVAL;
    }
    return -EINVAL;
}

// static long (*unlocked_ioctl) (struct file *, unsigned int, unsigned long);
// static long (*compat_ioctl) (struct file *, unsigned int cmd, unsigned long arg);
long rwProcMem_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) { return DispatchCommand(cmd, arg); }
loff_t rwProcMem_llseek(struct file *filp, loff_t offset, int orig) {
    unsigned int cmd = 0;
    printk_debug("rwProcMem_llseek offset:%zd\n", (ssize_t)offset);

    if (!!x_copy_from_user((void *)&cmd, (void *)offset, sizeof(unsigned int))) {
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
    cdev_init(g_rwProcMem_devp->pcdev, (struct file_operations *)&rwProcMem_fops);
    g_rwProcMem_devp->pcdev->owner = THIS_MODULE;
    g_rwProcMem_devp->pcdev->ops = (struct file_operations *)&rwProcMem_fops;
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
