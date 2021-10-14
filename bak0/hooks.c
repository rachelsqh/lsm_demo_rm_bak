// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2020 Google LLC.
 */
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/lsm_hooks.h>
#include <linux/sched.h>
#include <linux/fs_struct.h>
#include <linux/path.h>

#define back_dir "/var/bak_dir"

static struct path *get_task_root(struct task_struct *task)
{
	struct path *root = NULL;
	struct fs_struct *fs = NULL;
	task_lock(task);
	if(task->fs) {
		fs = task->fs;
		spin_lock(&(fs->lock));
		root = &(fs->pwd);
		path_get(root);
		spin_unlock(&(fs->lock));
	}
	task_unlock(task);
	return root;
}


#define LSM_HOOK_FUN(RET,DEFAULT,NAME,...) \
	RET m_recyle_lsm_##NAME(__VA_ARGS__)
LSM_HOOK_FUN(int,0,inode_unlink,struct inode *dir,struct dentry *dentry)
{
	char name_comm[16];
	char d_path0[512];
	char *ret_ptr;
	struct path *p_root = NULL;
	int ret = 0;
	get_task_comm(name_comm,current);
	if(!strcmp(name_comm,"rm")){
		printk("%s:task comm:%s\n",__func__,name_comm);

		p_root = get_task_root(current);
		if(p_root){
			printk("Task root:%s\n",p_root->dentry->d_iname);
			ret_ptr = d_path(p_root,d_path0,512);
			if(ret_ptr){
				printk("d_path:%s\n",ret_ptr);
			}
			ret_ptr = dentry_path_raw(dentry,d_path0,512);
			if(ret_ptr){
				printk("d_path:%s\n",ret_ptr);

				ret = strcmp("bak_dir"
			}
		}
		path_put(p_root);
	}
	return 0;
}
LSM_HOOK_FUN(int,0,inode_rmdir,struct inode *dir,struct dentry *dentry)
{

	char name_comm[16];
	char d_path0[512];
	char *ret_ptr;
	struct path *p_root = NULL;
	get_task_comm(name_comm,current);
	if(!strcmp(name_comm,"rm")){
		printk("%s:task comm:%s\n",__func__,name_comm);

		p_root = get_task_root(current);
		if(p_root){
			printk("Task root:%s\n",p_root->dentry->d_iname);
			ret_ptr = d_path(p_root,d_path0,512);
			if(ret_ptr){
				printk("d_path:%s\n",ret_ptr);
			}

			ret_ptr = dentry_path_raw(dentry,d_path0,512);
			if(ret_ptr){
				printk("d_path:%s\n",ret_ptr);
			}
		}
		path_put(p_root);
	}
	return 0;
}
#ifdef CONFIG_SECURITY_PATH
LSM_HOOK_FUN(int,0,path_unlink,const struct path *dir,struct dentry *dentry)
{

	char name_comm[16];
	char d_path0[512];
	char *ret_ptr;
	struct path *p_root = NULL;
	get_task_comm(name_comm,current);
	if(!strcmp(name_comm,"rm")){
		printk("%s:task comm:%s\n",__func__,name_comm);

		p_root = get_task_root(current);
		if(p_root){
			printk("Task root:%s\n",p_root->dentry->d_iname);
			ret_ptr = d_path(p_root,d_path0,512);
			if(ret_ptr){
				printk("d_path:%s\n",ret_ptr);
			}

			ret_ptr = dentry_path_raw(dentry,d_path0,512);
			if(ret_ptr){
				printk("d_path:%s\n",ret_ptr);
			}
		}
		path_put(p_root);
	}
	return 0;
}
LSM_HOOK_FUN(int,0,path_rmdir,const struct path *dir,struct dentry *dentry)
{
	char name_comm[16];
	char d_path0[512];
	char *ret_ptr;
	struct path *p_root = NULL;
	get_task_comm(name_comm,current);
	if(!strcmp(name_comm,"rm")){
		printk("%s:task comm:%s\n",__func__,name_comm);

		p_root = get_task_root(current);
		if(p_root){
			printk("Task root:%s\n",p_root->dentry->d_iname);
			ret_ptr = d_path(p_root,d_path0,512);
			if(ret_ptr){
				printk("d_path:%s\n",ret_ptr);
			}

			ret_ptr = dentry_path_raw(dentry,d_path0,512);
			if(ret_ptr){
				printk("d_path:%s\n",ret_ptr);
			}
		}
		path_put(p_root);
	}
	return 0;
}
#endif

#if 1
static struct security_hook_list m_recyle_lsm_hooks[] __lsm_ro_after_init = {
	#define LSM_HOOK(RET, DEFAULT, NAME, ...) \
	LSM_HOOK_INIT(NAME, m_recyle_lsm_##NAME),
	LSM_HOOK(int,0,inode_unlink,struct inode *dir,struct dentry *dentry)
	LSM_HOOK(int,0,inode_rmdir,struct inode *dir,struct dentry *dentry)
#ifdef CONFIG_SECURITY_PATH
	LSM_HOOK(int,0,path_unlink,const struct path *dir,struct dentry *dentry)
	LSM_HOOK(int,0,path_rmdir,const struct path *dir,struct dentry *dentry)
#endif
	#undef LSM_HOOK
};
#endif



static int __init m_recyle_lsm_init(void)
{
	security_add_hooks(m_recyle_lsm_hooks, ARRAY_SIZE(m_recyle_lsm_hooks), "m_recyle");
	pr_info("LSM support for m_recyle active\n");
	return 0;
}

int m_recyle_enable = 1;
DEFINE_LSM(m_recyle) = {
	.name = "m_recyle",
	.enabled = &m_recyle_enable,
	.init = m_recyle_lsm_init,
};
//MODULE_LICENSE("GPL");
