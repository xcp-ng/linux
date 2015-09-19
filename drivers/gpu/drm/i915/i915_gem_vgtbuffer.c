/*
 * Copyright © 2012 - 2015 Intel Corporation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 */

#include "i915_drv.h"
#include "intel_drv.h"

#include "gvt/gvt.h"

static int i915_gem_vgtbuffer_get_pages(struct drm_i915_gem_object *obj)
{
	BUG();
	return -EINVAL;
}

static void i915_gem_vgtbuffer_put_pages(struct drm_i915_gem_object *obj,
					 struct sg_table *st)
{
	/* like stolen memory, this should only be called during free
	 * after clearing pin count.
	 */
	sg_free_table(st);
	kfree(st);
}

static const struct drm_i915_gem_object_ops i915_gem_vgtbuffer_ops = {
	.get_pages = i915_gem_vgtbuffer_get_pages,
	.put_pages = i915_gem_vgtbuffer_put_pages,
};

#define GEN8_DECODE_PTE(pte) \
	((dma_addr_t)(((((u64)pte) >> 12) & 0x7ffffffULL) << 12))

#define GEN7_DECODE_PTE(pte) \
	((dma_addr_t)(((((u64)pte) & 0x7f0) << 28) | (u64)(pte & 0xfffff000)))

static struct sg_table *
i915_create_sg_pages_for_vgtbuffer(struct drm_device *dev,
				   u32 start, u32 num_pages)
{
	struct drm_i915_private *dev_priv = dev->dev_private;
	struct sg_table *st;
	struct scatterlist *sg;
	int i;

	st = kmalloc(sizeof(*st), GFP_KERNEL);
	if (st == NULL)
		return NULL;

	if (sg_alloc_table(st, num_pages, GFP_KERNEL)) {
		kfree(st);
		return NULL;
	}

	if (INTEL_INFO(dev_priv)->gen >= 8) {
		gen8_pte_t __iomem *gtt_entries =
			(gen8_pte_t __iomem *)dev_priv->ggtt.gsm +
			(start >> PAGE_SHIFT);
		for_each_sg(st->sgl, sg, num_pages, i) {
			sg->offset = 0;
			sg->length = PAGE_SIZE;
			sg_dma_address(sg) =
				GEN8_DECODE_PTE(readq(&gtt_entries[i]));
			sg_dma_len(sg) = PAGE_SIZE;
		}
	} else {
		gen6_pte_t __iomem *gtt_entries =
			(gen6_pte_t __iomem *)dev_priv->ggtt.gsm +
			(start >> PAGE_SHIFT);
		for_each_sg(st->sgl, sg, num_pages, i) {
			sg->offset = 0;
			sg->length = PAGE_SIZE;
			sg_dma_address(sg) =
				GEN7_DECODE_PTE(readq(&gtt_entries[i]));
			sg_dma_len(sg) = PAGE_SIZE;
		}
	}

	return st;
}

struct drm_i915_gem_object *
i915_gem_object_create_vgtbuffer(struct drm_device *dev,
				 u32 start, u32 num_pages)
{
	struct drm_i915_private *dev_priv = dev->dev_private;
	struct drm_i915_gem_object *obj;
	struct sg_table *st;

	obj = i915_gem_object_alloc(dev_priv);
	if (obj == NULL)
		return NULL;

	drm_gem_private_object_init(dev, &obj->base, num_pages << PAGE_SHIFT);
	i915_gem_object_init(obj, &i915_gem_vgtbuffer_ops);

	st = i915_create_sg_pages_for_vgtbuffer(dev, start, num_pages);
	if (st == NULL) {
		i915_gem_object_free(obj);
		return NULL;
	}

	__i915_gem_object_set_pages(obj, st, num_pages << PAGE_SHIFT);

	if (i915_gem_object_pin_pages(obj)) {
		i915_gem_object_free(obj);
		return NULL;
	}

	i915_gem_object_set_cache_coherency(obj, I915_CACHE_LLC);

	DRM_DEBUG_DRIVER("VGT_GEM: backing store base = 0x%x pages = 0x%x\n",
			 start, num_pages);
	return obj;
}

static u8 vgt_get_tiling_mode(struct drm_i915_private *dev_priv, u32 tiling)
{
	u8 tiling_mode = I915_TILING_NONE;

	if (IS_HASWELL(dev_priv) || IS_BROADWELL(dev_priv))
		tiling_mode = (tiling ? I915_TILING_X : I915_TILING_NONE);
	else if (IS_SKYLAKE(dev_priv)) {
		switch (tiling) {
		case PLANE_CTL_TILED_LINEAR:
			tiling_mode = I915_TILING_NONE;
			break;
		case PLANE_CTL_TILED_X:
			tiling_mode = I915_TILING_X;
			break;
		case PLANE_CTL_TILED_Y:
		case PLANE_CTL_TILED_YF:
			tiling_mode = I915_TILING_Y;
			break;
		default:
			DRM_DEBUG_DRIVER("VGT_GEM: unsupported tile format:%x\n",
					 tiling);
		}
	} else
		DRM_DEBUG_DRIVER("VGT_GEM: unsupported platform!\n");

	return tiling_mode;
}

static int vgt_decode_information(struct drm_device *dev,
				  struct intel_vgpu *vgpu,
				  struct drm_i915_gem_vgtbuffer *args)
{
	struct drm_i915_private *dev_priv = dev->dev_private;
	struct intel_vgpu_primary_plane_format p;
	struct intel_vgpu_cursor_plane_format c;
	u32 gtt_fbstart;
	int i, ret;
	u64 gtt_hash = 0;
	void __iomem *gtt_base = dev_priv->ggtt.gsm; /* mappable_base */

	if (args->plane_id == I915_VGT_PLANE_PRIMARY) {
		ret = intel_vgpu_decode_primary_plane(vgpu, &p);
		if (ret)
			return ret;

		args->enabled = p.enabled;
		args->x_offset = p.x_offset;
		args->y_offset = p.y_offset;
		args->start = p.base;
		args->width = p.width;
		args->height = p.height;
		args->stride = p.stride;
		args->bpp = p.bpp;
		args->hw_format = p.hw_format;
		args->drm_format = p.drm_format;
		args->tiled = vgt_get_tiling_mode(dev_priv, p.tiled);
		args->size = (p.stride * roundup(p.height, (args->tiled > I915_TILING_X) ? 32 : 8) +
			      (PAGE_SIZE - 1)) >> PAGE_SHIFT;
	} else if (args->plane_id == I915_VGT_PLANE_CURSOR) {
		ret = intel_vgpu_decode_cursor_plane(vgpu, &c);
		if (ret)
			return ret;

		args->enabled = c.enabled;
		args->x_offset = c.x_hot;
		args->y_offset = c.y_hot;
		args->x_pos = c.x_pos;
		args->y_pos = c.y_pos;
		args->start = c.base;
		args->width = c.width;
		args->height = c.height;
		args->stride = c.width * (c.bpp / 8);
		args->bpp = c.bpp;
		args->tiled = 0;
		args->size = (((c.width * c.height * c.bpp) / 8) +
			      (PAGE_SIZE - 1)) >> PAGE_SHIFT;
	} else {
		DRM_DEBUG_DRIVER("VGT_GEM: Invalid plaine_id: %d\n",
				 args->plane_id);
		return -EINVAL;
	}

	if (args->start & (PAGE_SIZE - 1)) {
		DRM_DEBUG_DRIVER("VGT_GEM: Not aligned fb start address: "
				 "0x%x\n", args->start);
		return -EINVAL;
	}

	if (((args->start >> PAGE_SHIFT) + args->size) >
	    ggtt_total_entries(&dev_priv->ggtt)) {
		DRM_DEBUG_DRIVER("VGT_GEM: Invalid GTT offset or size\n");
		return -EINVAL;
	}

	DRM_DEBUG_DRIVER("VGT_GEM: Surface size = %d\n",
			 (int)(args->size * PAGE_SIZE));

	gtt_fbstart = args->start >> PAGE_SHIFT;

	DRM_DEBUG_DRIVER("VGT_GEM: gtt start addr %p\n", gtt_base);
	DRM_DEBUG_DRIVER("VGT_GEM: fb start %x\n", gtt_fbstart);

	if (INTEL_INFO(dev_priv)->gen >= 8)
		gtt_base = (gen8_pte_t __iomem *)gtt_base + gtt_fbstart;
	else
		gtt_base = (gen6_pte_t __iomem *)gtt_base + gtt_fbstart;

	DRM_DEBUG_DRIVER("VGT_GEM: gtt + fb start %p\n", gtt_base);

	for (i = 0; i < args->size; i++) {
		u64 gtt_pte, overflow;

		if (INTEL_INFO(dev_priv)->gen >= 8)
			gtt_pte = readq((gen8_pte_t __iomem *)gtt_base + i);
		else
			gtt_pte = readl((gen8_pte_t __iomem *)gtt_base + i);

		gtt_hash = (gtt_hash << 4) + gtt_pte;
		overflow = gtt_hash & (0xffful << 32);
		if (overflow != 0) {
			gtt_hash ^= overflow >> 32;
			gtt_hash ^= overflow;
		}
	}

	DRM_DEBUG_DRIVER("VGT_GEM: gtt_hash=0x%lx\n", (unsigned long)gtt_hash);
	args->hash = gtt_hash;

	return 0;
}

/**
 * Creates a new mm object that wraps some user memory.
 */
int i915_gem_vgtbuffer_ioctl(struct drm_device *dev, void *data,
			     struct drm_file *file)
{
	struct drm_i915_gem_vgtbuffer *args = data;
	struct intel_vgpu *vgpu;
	struct drm_i915_gem_object *obj;
	u32 handle;
	int ret;

	if (INTEL_INFO(dev->dev_private)->gen < 7) {
		DRM_DEBUG_DRIVER("VGT_GEM: Unsupported architecture\n");
		return -EPERM;
	}

	if (!intel_gvt_active(dev->dev_private)) {
		DRM_DEBUG_DRIVER("VGT_GEM: GVT-g is not active\n");
		return -EPERM;
	}

	vgpu = intel_gvt_hypervisor_vgpu_from_vm_id(args->vmid);
	if (!vgpu) {
		DRM_DEBUG_DRIVER("VGT_GEM: No vgpu found for a given VM id\n");
		return -EINVAL;
	}

	ret = vgt_decode_information(dev, vgpu, args);
	if (ret)
		return ret;

	if (args->flags & I915_VGTBUFFER_QUERY_ONLY)
		return 0;

	obj = i915_gem_object_create_vgtbuffer(dev, args->start, args->size);
	if (!obj) {
		DRM_DEBUG_DRIVER("VGT_GEM: Failed to create gem object"
				 " for VM FB!\n");
		return -EINVAL;
	}

	obj->tiling_and_stride = args->tiled | args->stride;

	ret = drm_gem_handle_create(file, &obj->base, &handle);
	if (ret) {
		/* TODO: Double confirm the error handling path */
		i915_gem_object_unpin_pages(obj);
		i915_gem_object_free(obj);
		return ret;
	}

	/* drop reference from allocate - handle holds it now */
	drm_gem_object_unreference_unlocked(&obj->base);

	args->handle = handle;
	return 0;
}
