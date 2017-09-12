#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
 .name = KBUILD_MODNAME,
 .init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
 .exit = cleanup_module,
#endif
 .arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x14522340, "module_layout" },
	{ 0x199ed0cd, "net_disable_timestamp" },
	{ 0x5a34a45c, "__kmalloc" },
	{ 0x349cba85, "strchr" },
	{ 0x25ec1b28, "strlen" },
	{ 0x5929a6ea, "xt_register_matches" },
	{ 0xd691cba2, "malloc_sizes" },
	{ 0x52760ca9, "getnstimeofday" },
	{ 0x489a8c8b, "skb_copy" },
	{ 0x1a6d6e4f, "remove_proc_entry" },
	{ 0x85df9b6c, "strsep" },
	{ 0x3c2c5af5, "sprintf" },
	{ 0x7d11c268, "jiffies" },
	{ 0xe2d5255a, "strcmp" },
	{ 0xde0bdcff, "memset" },
	{ 0xed113e22, "proc_mkdir" },
	{ 0x8d3894f2, "_ctype" },
	{ 0xea147363, "printk" },
	{ 0x42224298, "sscanf" },
	{ 0x2fa5a500, "memcmp" },
	{ 0x85da6302, "xt_register_targets" },
	{ 0xaafdc258, "strcasecmp" },
	{ 0x7ec9bfbc, "strncpy" },
	{ 0xb4390f9a, "mcount" },
	{ 0x85abc85f, "strncmp" },
	{ 0x8e3c9cc3, "vprintk" },
	{ 0x1e6d26a8, "strstr" },
	{ 0xc740c64a, "memchr" },
	{ 0x373db350, "kstrtoint" },
	{ 0x9ca70c75, "xt_unregister_targets" },
	{ 0x9f984513, "strrchr" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x54e6fcdd, "net_enable_timestamp" },
	{ 0x3d75cbcf, "kfree_skb" },
	{ 0x6d6b15ff, "create_proc_entry" },
	{ 0x2276055c, "xt_unregister_matches" },
	{ 0x2044fa9e, "kmem_cache_alloc_trace" },
	{ 0x1d2e87c6, "do_gettimeofday" },
	{ 0x3aa1dbcf, "_spin_unlock_bh" },
	{ 0x37a0cba, "kfree" },
	{ 0x236c8c64, "memcpy" },
	{ 0x4a2ffd48, "nf_conntrack_untracked" },
	{ 0x9edbecae, "snprintf" },
	{ 0x93cbd1ec, "_spin_lock_bh" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=nf_conntrack";


MODULE_INFO(srcversion, "5BDC14C0B880D0568DDC629");

static const struct rheldata _rheldata __used
__attribute__((section(".rheldata"))) = {
	.rhel_major = 6,
	.rhel_minor = 5,
};
