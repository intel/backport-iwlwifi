#ifndef __BACKPORT_SCATTERLIST_H
#define __BACKPORT_SCATTERLIST_H
#include_next <linux/scatterlist.h>

#if LINUX_VERSION_IS_LESS(4, 17, 0)

#define sg_init_marker LINUX_BACKPORT(sg_init_marker)
/**
 * sg_init_marker - Initialize markers in sg table
 * @sgl:	   The SG table
 * @nents:	   Number of entries in table
 *
 **/
static inline void sg_init_marker(struct scatterlist *sgl,
				  unsigned int nents)
{
#ifdef CONFIG_DEBUG_SG
	unsigned int i;

	for (i = 0; i < nents; i++)
		sgl[i].sg_magic = SG_MAGIC;
#endif
	sg_mark_end(&sgl[nents - 1]);
}

#endif /* LINUX_VERSION_IS_LESS(4, 17, 0) */

#if LINUX_VERSION_IS_LESS(5, 4, 233)
#define for_each_sgtable_sg(sgt, sg, i)		\
	for_each_sg((sgt)->sgl, sg, (sgt)->orig_nents, i)

#define for_each_sgtable_dma_sg(sgt, sg, i)	\
	for_each_sg((sgt)->sgl, sg, (sgt)->nents, i)

#define for_each_sgtable_page(sgt, piter, pgoffset)	\
	for_each_sg_page((sgt)->sgl, piter, (sgt)->orig_nents, pgoffset)

#define for_each_sgtable_dma_page(sgt, dma_iter, pgoffset)	\
	for_each_sg_dma_page((sgt)->sgl, dma_iter, (sgt)->nents, pgoffset)

#endif /* LINUX_VERSION_IS_LESS(5, 4, 233) */

#endif /* __BACKPORT_SCATTERLIST_H */
