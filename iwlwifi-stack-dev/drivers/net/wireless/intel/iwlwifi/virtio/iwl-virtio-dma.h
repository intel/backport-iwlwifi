/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/******************************************************************************
 *
 * Copyright(c) 2020 Intel Corporation
 *
 *****************************************************************************/
#ifndef _IWL_VIRTIO_DMA
#define _IWL_VIRTIO_DMA

#include <linux/slab.h> /* kmem_* */
#include <linux/types.h> /* dma_addr_t */
#include <asm/io.h> /* virt_to_phys */
#include <linux/dma-mapping.h> /* "dma_map_single" */
#define LINUX_DMAPOOL_H /* avoid conflicts with linux/dmapool.h file */

static inline struct kmem_cache *virtio_dmam_pool_create(const char *name,
							 struct device *dev,
							 size_t size,
							 size_t align)
{
	struct kmem_cache *cache;

	cache = kmem_cache_create(name, size, align, SLAB_HWCACHE_ALIGN, NULL);
	if (!cache)
		return NULL;

	if (devm_add_action_or_reset(dev, (void (*)(void *))kmem_cache_destroy, cache))
		return NULL;

	return cache;
}

#define dmam_pool_create(name, dev, size, align, allocation) \
	virtio_dmam_pool_create((name), dev, (size), (align))

#undef dma_map_single
#define dma_map_single(dev, tb1_addr, tb1_len, dir) \
	(dma_addr_t)(virt_to_phys(tb1_addr))

#undef dma_unmap_single
#define dma_unmap_single(dev, tb1_addr, tb1_len, dir)

#undef dma_mapping_error
#define dma_mapping_error(dev, tb1_addr) 0

static inline void *virtio_dma_alloc_coherent(struct device *dev, size_t size,
					      dma_addr_t *dma_handle,
					      gfp_t flags)
{
	void *va = kzalloc(size, flags);
	*dma_handle = (dma_addr_t)virt_to_phys(va);
	return va;
}

#define dma_alloc_coherent(dev, size, dma_handle, flags) \
virtio_dma_alloc_coherent((dev), (size), (dma_handle), (flags))

static inline void virtio_dma_free_coherent(struct device *dev, size_t size,
					    void *cpu_addr,
					    dma_addr_t dma_handle)
{
	kfree(cpu_addr);
}

#define dma_free_coherent(dev, tfd_sz, tfds, dma_addr) \
	virtio_dma_free_coherent((dev), (tfd_sz), (tfds), (dma_addr))

static inline void *virtio_dma_pool_alloc(struct kmem_cache *pool,
					  gfp_t mem_flags,
					  dma_addr_t *handle)
{
	void *va = kmem_cache_alloc(pool, mem_flags);
	*handle = (dma_addr_t)virt_to_phys(va);
	return va;
}

#define dma_pool_alloc(pool, flags, handle) \
	virtio_dma_pool_alloc((pool), (flags), (handle))

static inline void virtio_dma_pool_free(struct kmem_cache *pool, void *addr)
{
	kmem_cache_free(pool, addr);
}

#define dma_pool_free(pool, addr, dma) virtio_dma_pool_free((pool), (addr))
#define dma_pool kmem_cache
#endif /* _IWL_VIRTIO_DMA */
