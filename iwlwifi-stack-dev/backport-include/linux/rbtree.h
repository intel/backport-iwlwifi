/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2021 Intel Corporation
 */
#ifndef __BACKPORT_RBTREE_H
#define __BACKPORT_RBTREE_H
#include_next <linux/rbtree.h>

#if LINUX_VERSION_IS_LESS(4,14,0)
#define rb_root_cached rb_root
#define rb_first_cached rb_first
static inline void rb_insert_color_cached(struct rb_node *node,
					  struct rb_root_cached *root,
					  bool leftmost)
{
	rb_insert_color(node, root);
}
#define rb_erase_cached rb_erase
#define RB_ROOT_CACHED RB_ROOT
#define rb_root_node(root) (root)->rb_node
#else
#define rb_root_node(root) (root)->rb_root.rb_node
#endif

#endif /* __BACKPORT_RBTREE_H */
