#include <linux/module.h>
#include <linux/lsm_hooks.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/dcache.h>

//---HOOK
static int mmap_file_interceptor(struct file *file, unsigned long reqprot,
	unsigned long prot, unsigned long flags)
{

/*--- CHECKING FOR ANONYMOUS MEMORY --- */
	if(file == NULL)
		return 0;
	
	char buff[256];
	char *path = d_path(&file->f_path, buff, sizeof(buff));
	if(path != NULL && (*path) > 0)
		printk(KERN_ALERT "Trying load %s", path);
	
	return 0;
}

//---HOOKS REGISTERING
static struct security_hook_list interceptor_hooks[] =
{
	LSM_HOOK_INIT(mmap_file, mmap_file_interceptor),
};

//---INIT
void __init interceptor_add_hooks(void)
{
	security_add_hooks(interceptor_hooks, ARRAY_SIZE(interceptor_hooks));
	printk(KERN_ALERT "Interceptor added.");
}
