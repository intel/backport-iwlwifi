// SPDX-License-Identifier: GPL-2.0
/******************************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2019 - 2020 Intel Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *****************************************************************************/
#include <linux/module.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include "virtio_iwl.h"
#include "iwl-config.h"
#include "iwl-trans.h"
#include "iwl-op-mode.h"
#include "iwl-drv.h"
#include "iwl-devtrace-data.h"
#include "iwl-devtrace-iwlwifi.h"
#include "iwl-io.h"

struct iwl_virtqueue {
	struct virtqueue *vq;
	/* To protect the vq operations*/
	spinlock_t lock;
	u32 seq;
};

struct iwl_trans_virtio {
	struct iwl_trans *trans;

	/* Protect sending usim commands */
	struct mutex mutex;

	/* The virtio device we're associated with */
	struct virtio_device *vdev;

	struct iwl_trans_config trans_cfg;
	/*
	 * A couple of virtqueues for the host commands: one for
	 * guest->host transfers, one for host->guest transfers
	 */
	struct iwl_virtqueue h_ivq, h_ovq;

	/*
	 * Workqueue handlers where we process deferred work after
	 * notification
	 */
	struct work_struct control_work;

	struct {
		void *context;
		void (*cont)(const struct firmware *fw, void *context);
		/* Workqueue handlers for loading fw async */
		struct work_struct work;
	} fw_load;

	/*
	 * Workqueue handlers where we process deferred work after
	 * notification
	 */
	struct work_struct rxdef_work;

	/*
	 * A control packet buffer for guest->host requests, protected
	 * by c_ovq_lock.
	 */
	struct virtio_iwl_control_hdr cpkt;

	/* usim contole queus used for fw alive and reset */
	struct iwl_virtqueue c_ivq, c_ovq;

	/*
	 * devide id should be like an ID of PCI
	 */
	u16 id;

	u16 nr_queues;

	const struct iwl_cfg *cfg;

	/*
	 * wait queue for sync commands
	 */
	wait_queue_head_t wait_command_queue;

	/* tx sync cmd waiting for reqspond */
	struct iwl_host_cmd *tx_sync;
};

enum iwl_buf_type {
	IWL_BUF_TYPE_VA,
	IWL_BUF_TYPE_PAGE,
};

static inline struct iwl_trans_virtio *
IWL_TRANS_GET_VIRTIO_TRANS(struct iwl_trans *trans)
{
	return (void *)trans->trans_specific;
}

static struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_IWL, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static unsigned int features[] = {
	VIRTIO_IWL_F_ID,
};

static u32 iwl_trans_page_order(struct iwl_trans *trans)
{
	/* get from config page order */
	return 0;
}

/*
 * iwl_pcie_rx_alloc_page - allocates and returns a page.
 *
 */
static struct page *iwl_virtio_rx_alloc_page(struct iwl_trans *trans,
					     gfp_t priority)
{
	struct page *page;
	gfp_t gfp_mask = priority;
	u32 order = iwl_trans_page_order(trans);

	if (order > 0)
		gfp_mask |= __GFP_COMP;

	/* Alloc a new receive buffer */
	page = alloc_pages(gfp_mask, order);
	if (!page) {
		if (net_ratelimit())
			IWL_DEBUG_INFO(trans, "alloc_pages failed, order: %d\n",
				       order);
		/*
		 * Issue an error if we don't have enough pre-allocated
		  * buffers.
		 */
		if (!(gfp_mask & __GFP_NOWARN) && net_ratelimit())
			IWL_CRIT(trans,
				 "Failed to alloc_pages\n");
		return NULL;
	}
	return page;
}

static void in_intr(struct virtqueue *vq)
{
	struct iwl_trans_virtio *trans_virtio;
	static int stat;

	trans_virtio = vq->vdev->priv;
	IWL_DEBUG_ISR(trans_virtio->trans,
		      "got on vq %d count %d\n", vq->index, stat++);

	schedule_work(&trans_virtio->rxdef_work);
}

static void out_intr(struct virtqueue *vq)
{
	static int stat;
	struct iwl_trans_virtio *trans_virtio = vq->vdev->priv;

	IWL_DEBUG_ISR(trans_virtio->trans,
		      "got on vq %d count %d\n", vq->index, stat++);
}

static void control_intr(struct virtqueue *vq)
{
	struct iwl_trans_virtio *trans_virtio;
	static int stat;

	trans_virtio = vq->vdev->priv;
	trans_virtio = vq->vdev->priv;
	IWL_DEBUG_ISR(trans_virtio->trans,
		      "got on vq %d count %d\n", vq->index, stat++);

	schedule_work(&trans_virtio->control_work);
}

static int add_inbuf(struct virtqueue *vq, void *data, char *buf, size_t size);

/*TODO: should we have dynamic size for rx data */
#define IWL_BUF_SIZE PAGE_SIZE

static void control_work_handler(struct work_struct *work)
{
	struct iwl_trans_virtio *trans_virtio;
	struct virtqueue *vq;
	struct virtio_iwl_control_hdr *ctr;
	int len;

	trans_virtio = container_of(work, struct iwl_trans_virtio,
				    control_work);
	vq = trans_virtio->c_ivq.vq;

	spin_lock(&trans_virtio->c_ivq.lock);
	while ((ctr = virtqueue_get_buf(vq, &len))) {
		spin_unlock(&trans_virtio->c_ivq.lock);

		/* TODO: add this function for doing the logic
		 *	handle_control_message(vq->vdev, buf);
		 */
		IWL_DEBUG_INFO(trans_virtio->trans,
			       "got contole message event %d value %d\n",
			       le32_to_cpu(ctr->event),
			       le32_to_cpu(ctr->flags));

		spin_lock(&trans_virtio->c_ivq.lock);
		if (add_inbuf(trans_virtio->c_ivq.vq,
			      ctr, (char *)ctr, IWL_BUF_SIZE) < 0) {
			IWL_WARN(trans_virtio->trans,
				 "Error adding buffer to queue\n");
			kfree(ctr);
		}
	}
	spin_unlock(&trans_virtio->c_ivq.lock);
}

/*
 * iwl_virtio_hcmd_complete - Pull unused buffers off the queue and reclaim them
 * @rxb: Rx buffer to reclaim
 */
static void *_iwl_virtio_dequeue_cmd(struct iwl_virtqueue *iwl_q, u32 *size);
void iwl_virtio_hcmd_complete(struct iwl_trans *trans,
			      struct iwl_rx_cmd_buffer *rxb)
{
	struct iwl_rx_packet *pkt = rxb_addr(rxb);
	u16 rx_id = WIDE_ID(pkt->hdr.group_id, pkt->hdr.cmd);
	u8 group_id;
	u32 cmd_id;
	u32 cmd_size;
	struct iwl_trans_virtio *trans_virtio =
		IWL_TRANS_GET_VIRTIO_TRANS(trans);
	struct iwl_virtqueue *hcmd_q = &trans_virtio->h_ovq;
	struct page *page;
	char *tx_address;
	struct iwl_cmd_header_wide *tx_hdr;
	struct iwl_host_cmd *tx_s = trans_virtio->tx_sync;
	bool is_sync_respond = false;

	page = _iwl_virtio_dequeue_cmd(hcmd_q, &cmd_size);
	WARN(!page, "Got host rx without no tx complete in queue");
	tx_address = page_address(page);
	tx_hdr = (struct iwl_cmd_header_wide *)(tx_address + 4);

	group_id = tx_hdr->group_id;
	cmd_id = iwl_cmd_id(tx_hdr->cmd, group_id, 0);
	WARN(cmd_id != rx_id,
	     "received out of order host cmd txed: %d rxed %d\n",
	     cmd_id, rx_id);

	/* Check if this rx is a respond for a sync command */
	is_sync_respond = tx_s && tx_s->id == rx_id;

	/* Input error checking is done when commands are added to queue. */
	if (is_sync_respond && tx_s->flags & CMD_WANT_SKB) {
		struct page *p = rxb_steal_page(rxb);

		tx_s->resp_pkt = pkt;
		tx_s->_rx_page_addr = (unsigned long)page_address(p);
		tx_s->_rx_page_order = iwl_trans_page_order(trans);
	}

	/*TODO: need to add a dequeu callbacks remember for every tx */
	/*
	if (meta->flags & CMD_WANT_ASYNC_CALLBACK)
		iwl_op_mode_async_cb(trans->op_mode,
				     (struct iwl_device_cmd *)tx_hdr);
				     */

	if (is_sync_respond) {
		if (!test_bit(STATUS_SYNC_HCMD_ACTIVE, &trans->status)) {
			IWL_WARN(trans,
				 "HCMD_ACTIVE already clear for command %s\n",
				 iwl_get_cmd_string(trans, cmd_id));
		}
		trans_virtio->tx_sync = NULL;
		clear_bit(STATUS_SYNC_HCMD_ACTIVE, &trans->status);
		IWL_DEBUG_INFO(trans, "Clearing HCMD_ACTIVE for command %s\n",
			       iwl_get_cmd_string(trans, cmd_id));
		wake_up(&trans_virtio->wait_command_queue);
	}

	/* TODO: do this as one in reclaim logic */
	__free_pages(page, iwl_trans_page_order(trans));
}

static bool iwl_virtio_def_rx(struct iwl_trans_virtio *trans_virtio,
			      u32 q_idx, struct page *page, size_t len)
{
	struct iwl_trans *trans = trans_virtio->trans;
	u32 order = iwl_trans_page_order(trans_virtio->trans);
	struct iwl_trans_config *cfg = &trans_virtio->trans_cfg;

	struct iwl_rx_packet *pkt;
	bool reclaim;

	struct iwl_rx_cmd_buffer rxcb = {
		._offset = 0,
		._rx_page_order = order,
		._page = page,
		._page_stolen = false,
		.truesize = PAGE_SIZE << order,
	};

	pkt = rxb_addr(&rxcb);

	if (pkt->len_n_flags == cpu_to_le32(FH_RSCSR_FRAME_INVALID)) {
		IWL_DEBUG_RX(trans,
			     "Q %d: RB end marker at offset %d\n",
			     q_idx, 0);
		return false;
	}

	/* TODO: make sure mapping queue index to umac index
	WARN((le32_to_cpu(pkt->len_n_flags) & FH_RSCSR_RXQ_MASK) >>
		FH_RSCSR_RXQ_POS != q_idx,
	     "frame on invalid queue - is on %d and indicates %d\n",
	     q_idx,
	     (le32_to_cpu(pkt->len_n_flags) & FH_RSCSR_RXQ_MASK) >>
		FH_RSCSR_RXQ_POS);
	*/

	IWL_DEBUG_RX(trans,
		     "Q %d: cmd at offset %d: %s (%.2x.%2x, seq 0x%x)\n",
		     q_idx, 0,
		     iwl_get_cmd_string(trans,
					iwl_cmd_id(pkt->hdr.cmd,
						   pkt->hdr.group_id,
						   0)),
		     pkt->hdr.group_id, pkt->hdr.cmd,
		     le16_to_cpu(pkt->hdr.sequence));

	len = iwl_rx_packet_len(pkt);
	len += sizeof(u32); /* account for status word */
	trace_iwlwifi_dev_rx(trans->dev, trans, pkt, len);
	trace_iwlwifi_dev_rx_data(trans->dev, trans, pkt, len);

	/* Reclaim a command buffer only if this packet is a response
	 *   to a (driver-originated) command.
	 * If the packet (e.g. Rx frame) originated from uCode,
	 *   there is no command buffer to reclaim.
	 * Ucode should set SEQ_RX_FRAME bit if ucode-originated,
	 *   but apparently a few don't get set; catch them here. */
	reclaim = !(pkt->hdr.sequence & SEQ_RX_FRAME);
	if (reclaim && !pkt->hdr.group_id) {
		int i;

		for (i = 0; i < cfg->n_no_reclaim_cmds; i++) {
			if (cfg->no_reclaim_cmds[i] ==
						pkt->hdr.cmd) {
				reclaim = false;
				break;
			}
		}
	}

	local_bh_disable();
	iwl_op_mode_rx(trans->op_mode, NULL, &rxcb);
	local_bh_enable();

	/*
	 * After here, we should always check rxcb._page_stolen,
	 * if it is true then one of the handlers took the page.
	 */

	if (reclaim) {
		/* Invoke any callbacks, transfer the buffer to caller,
		 * and fire off the (possibly) blocking
		 * iwl_trans_send_cmd()
		 * as we reclaim the driver command queue */
		if (!rxcb._page_stolen)
			iwl_virtio_hcmd_complete(trans, &rxcb);
		else
			IWL_WARN(trans, "Claim null rxb?\n");
	}

	if (rxcb._page_stolen)
		__free_pages(page, order);

	return rxcb._page_stolen;
}

static void rxdef_work_handler(struct work_struct *work)
{
	struct iwl_trans_virtio *trans_virtio;
	struct virtqueue *vq;
	struct page *page;
	int len;
	u32 order;

	/* current queue lock */
	spinlock_t *lock;

	trans_virtio = container_of(work, struct iwl_trans_virtio,
				    rxdef_work);
	order = iwl_trans_page_order(trans_virtio->trans);
	vq = trans_virtio->h_ivq.vq;
	lock = &trans_virtio->h_ivq.lock;

	spin_lock(lock);
	while ((page = virtqueue_get_buf(vq, &len))) {
		spin_unlock(lock);

		IWL_DEBUG_RX(trans_virtio->trans,
			     "handle new rx event %pK\n", page);

		/* don't requeu stolen pages */
		if (iwl_virtio_def_rx(trans_virtio, vq->index, page, len)) {
			page = iwl_virtio_rx_alloc_page(trans_virtio->trans,
							GFP_ATOMIC);
		}

		spin_lock(lock);
		if (add_inbuf(vq, page, page_address(page),
			      PAGE_SIZE << order) < 0) {
			IWL_WARN(trans_virtio->trans,
				 "Error adding buffer to queue\n");
			__free_pages(page, order);
		}
	}
	spin_unlock(lock);
}

static size_t _iwl_virtio_enqueue_cmd(struct iwl_virtqueue *iwl_q,
				      struct page *page,
				      char *buf, size_t size)
{
	struct scatterlist sg[1];
	int ret = 0;

	sg_init_one(sg, buf, size);

	spin_lock(&iwl_q->lock);
	if (virtqueue_add_outbuf(iwl_q->vq, sg, 1, page, GFP_ATOMIC) == 0)
		virtqueue_kick(iwl_q->vq);
	else
		ret = -ENOSPC;

	spin_unlock(&iwl_q->lock);

	return ret;
}

static void *_iwl_virtio_dequeue_cmd(struct iwl_virtqueue *iwl_q, u32 *size)
{
	void *buf;

	spin_lock(&iwl_q->lock);
	buf = virtqueue_get_buf(iwl_q->vq, size);
	spin_unlock(&iwl_q->lock);

	return buf;
}

/* send control message to usim
 *	for now we block this all until we get respond so it's ok to use stack
 *	memory
 * event - see VIRTIO_E_*
 * value - depends on the event e.g for read/write this is the address
 * flags - r/w
 * buf - buffer to r/w
 * len - buf len
 */
static int _send_control_msg(struct iwl_trans_virtio *trans_virtio,
			     u32 event, u32 flags, u32 value,
			     void *buf, u32 len)
{
	struct scatterlist sgs[VIRTIO_IWL_NR_SGS];
	struct scatterlist *sgs_list[VIRTIO_IWL_NR_SGS];

	unsigned int num_in = 0;
	struct virtqueue *vq;
	unsigned int in_len;
	int i;
	struct virtio_iwl_control_hdr *cpkt_hdr =
		kzalloc(sizeof(struct virtio_iwl_control_hdr) + 4,
			GFP_KERNEL);

	if (!cpkt_hdr)
		return -ENOMEM;

	lockdep_assert_held(&trans_virtio->mutex);

	vq = trans_virtio->c_ovq.vq;

	cpkt_hdr->event = cpu_to_le32(event);
	cpkt_hdr->flags = cpu_to_le32(flags);
	cpkt_hdr->value = cpu_to_le32(value);
	cpkt_hdr->len = cpu_to_le32(len);

	sg_init_one(&sgs[0], cpkt_hdr, sizeof(struct virtio_iwl_control_hdr));
	sg_init_one(&sgs[1], buf, len);
	sg_init_one(&sgs[2], cpkt_hdr + 1, 4);

	for (i = 0; i < VIRTIO_IWL_NR_SGS; i++)
		sgs_list[i] = &sgs[i];

	spin_lock(&trans_virtio->c_ovq.lock);

	/* for status we always have at least one */
	num_in = 1;
	num_in += (flags & VIRTIO_IWL_F_DIR_IN) ? 1 : 0;
	if (virtqueue_add_sgs(vq, sgs_list, VIRTIO_IWL_NR_SGS - num_in, num_in,
			      cpkt_hdr, GFP_ATOMIC) == 0) {
		virtqueue_kick(vq);
		while (!virtqueue_get_buf(vq, &in_len) &&
		       !virtqueue_is_broken(vq))
			udelay(1);
	}
	kfree(cpkt_hdr);

	spin_unlock(&trans_virtio->c_ovq.lock);
	return 0;
}

static ssize_t send_control_msg(struct iwl_trans_virtio *trans_virtio,
				u32 event, u32 flags, u32 value,
				void *buf, u32 len)
{
	int ret;

	mutex_lock(&trans_virtio->mutex);
	ret = _send_control_msg(trans_virtio, event, flags, value, buf, len);
	mutex_unlock(&trans_virtio->mutex);
	return ret;
}

/*
 * Create a scatter-gather list representing one buffer and put
 * it in the queue.
 *
 * Callers should take appropriate locks.
 */
static int add_inbuf(struct virtqueue *vq, void *data, char *buf, size_t size)
{
	struct scatterlist sg[1];
	int ret;

	sg_init_one(sg, buf, size);

	ret = virtqueue_add_inbuf(vq, sg, 1, data, GFP_ATOMIC);
	virtqueue_kick(vq);
	if (!ret)
		ret = vq->num_free;
	return ret;
}

static unsigned int fill_queue(struct iwl_trans_virtio *virtio_trans,
			       struct virtqueue *vq, spinlock_t *lock,
			       enum iwl_buf_type type)
{
	void *data;
	char *buf;
	unsigned int nr_added_bufs;
	int ret;
	size_t size;

	if (type == IWL_BUF_TYPE_VA)
		size = IWL_BUF_SIZE;
	else
		size = PAGE_SIZE << iwl_trans_page_order(virtio_trans->trans);

	nr_added_bufs = 0;
	do {
		if (type == IWL_BUF_TYPE_VA) {
			data = kzalloc(size, GFP_KERNEL);
			buf = (char *)data;
		} else {
			data = iwl_virtio_rx_alloc_page(virtio_trans->trans,
							GFP_KERNEL);
			buf = (char *)page_address((struct page *)data);
		}

		if (!buf)
			break;

		spin_lock_irq(lock);
		ret = add_inbuf(vq, data, buf, size);
		if (ret < 0) {
			spin_unlock_irq(lock);
			if (type == IWL_BUF_TYPE_VA) {
				kfree(buf);
			} else {
				__free_pages((struct page *)data,
					     size >> PAGE_SHIFT);
			}
			break;
		}
		nr_added_bufs++;
		spin_unlock_irq(lock);
	} while (ret > 0);

	return nr_added_bufs;
}

static int init_vqs(struct iwl_trans_virtio *trans_virtio)
{
	vq_callback_t **io_callbacks;
	char **io_names;
	struct virtqueue **vqs;
	u32 nr_queues = trans_virtio->nr_queues;
	int ret = 0;
	int nr_added_bufs;

	if (WARN_ON(nr_queues > VIRTIO_IWL_Q_MAX))
		return -EINVAL;

	vqs = kmalloc_array(nr_queues, sizeof(struct virtqueue *), GFP_KERNEL);
	io_callbacks = kmalloc_array(nr_queues, sizeof(vq_callback_t *),
				     GFP_KERNEL |  __GFP_ZERO);
	io_names = kmalloc_array(nr_queues, sizeof(char *),
				 GFP_KERNEL |  __GFP_ZERO);

	if (!vqs || !io_callbacks || !io_names) {
		ret = -ENOMEM;
		goto free;
	}

	// setup usim contole queus
	io_callbacks[VIRTIO_IWL_Q_CONTROL_I] = control_intr;
	io_names[VIRTIO_IWL_Q_CONTROL_I] = "control_input";

	io_callbacks[VIRTIO_IWL_Q_CONTROL_O] = NULL;
	io_names[VIRTIO_IWL_Q_CONTROL_O] = "control_output";

	// setup host command queus
	io_callbacks[VIRTIO_IWL_Q_DEF_RX_I] = in_intr;
	io_names[VIRTIO_IWL_Q_DEF_RX_I] = "h_cmd_input";
	io_callbacks[VIRTIO_IWL_Q_HCMD_O] = out_intr;
	io_names[VIRTIO_IWL_Q_HCMD_O] = "h_cmd_output";

	ret = virtio_find_vqs(trans_virtio->vdev, nr_queues, vqs,
			      io_callbacks,
			      (const char **)io_names, NULL);
	if (ret)
		goto free;

	trans_virtio->c_ivq.vq = vqs[VIRTIO_IWL_Q_CONTROL_I];
	trans_virtio->c_ovq.vq = vqs[VIRTIO_IWL_Q_CONTROL_O];

	/* Fill the in_vq with buffers so the host can send us data. */
	nr_added_bufs = fill_queue(trans_virtio, trans_virtio->c_ivq.vq,
				   &trans_virtio->c_ivq.lock, IWL_BUF_TYPE_VA);

	trans_virtio->h_ivq.vq = vqs[VIRTIO_IWL_Q_DEF_RX_I];
	trans_virtio->h_ovq.vq = vqs[VIRTIO_IWL_Q_HCMD_O];
	nr_added_bufs = fill_queue(trans_virtio, trans_virtio->h_ivq.vq,
				   &trans_virtio->h_ivq.lock,
				   IWL_BUF_TYPE_PAGE);
	if (!nr_added_bufs) {
		ret = -ENOMEM;
		goto free;
	}

free:
	kfree(io_names);
	kfree(io_callbacks);
	kfree(vqs);
	return ret;
}

static void flush_bufs(struct iwl_trans_virtio *trans_virtio,
		       struct virtqueue *vq)
{
	void *buf;
	unsigned int len;
	u32 order = iwl_trans_page_order(trans_virtio->trans);

	while ((buf = virtqueue_get_buf(vq, &len)))
		if (vq->index == VIRTIO_IWL_Q_CONTROL_I)
			kfree(buf);
		else
			__free_pages(buf, order);
}

static void remove_vqs(struct iwl_trans_virtio *trans_virtio)
{
	struct virtqueue *vq;
	u32 order = iwl_trans_page_order(trans_virtio->trans);

	virtio_device_for_each_vq(trans_virtio->vdev, vq) {
		char *buf;

		flush_bufs(trans_virtio, vq);
		while ((buf = virtqueue_detach_unused_buf(vq)))
			if (vq->index == VIRTIO_IWL_Q_CONTROL_I)
				kfree(buf);
			else
				__free_pages((struct page *)buf, order);
	}

	trans_virtio->vdev->config->del_vqs(trans_virtio->vdev);
}

struct id_cfg {
	const u16 id;
	const struct iwl_cfg *cfg;
};

const struct id_cfg cfgid_table[] = {
#if IS_ENABLED(CPTCFG_IWLMVM) || IS_ENABLED(CPTCFG_IWLFMAC)
	// dont' use id 0! enable catching initialled IDs.
	{.id = 1, .cfg = &iwlax211_2ax_cfg_so_gf_a0},
#endif /* CPTCFG_IWLMVM || CPTCFG_IWLFMAC */
};

const static struct iwl_cfg *virtio_iwl_id_to_cfg(u16 id)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(cfgid_table); i++) {
		if (cfgid_table[i].id == id)
			return cfgid_table[i].cfg;
	}
	return NULL;
}

static void iwl_trans_virtio_configure(struct iwl_trans *trans,
				       const struct iwl_trans_config *trans_cfg)
{
	struct iwl_trans_virtio *trans_virtio =
		IWL_TRANS_GET_VIRTIO_TRANS(trans);

	trans_virtio->trans_cfg = *trans_cfg;
	trans->command_groups = trans_cfg->command_groups;
	trans->command_groups_size = trans_cfg->command_groups_size;
}

static int iwl_trans_virtio_start_hw(struct iwl_trans *trans)
{
	struct iwl_trans_virtio *trans_virtio =
		IWL_TRANS_GET_VIRTIO_TRANS(trans);
	u32 buf;

	send_control_msg(trans_virtio, VIRTIO_IWL_E_HW_START, 0, 0, &buf, 4);
	return 0;
}

static int iwl_trans_virtio_start_fw(struct iwl_trans *trans,
				     const struct fw_img *fw,
				     bool run_in_rfkill)
{
	struct iwl_trans_virtio *trans_virtio =
		IWL_TRANS_GET_VIRTIO_TRANS(trans);
	u32 buf;

	send_control_msg(trans_virtio, VIRTIO_IWL_E_FW_START, 0, 0, &buf, 4);
	set_bit(STATUS_DEVICE_ENABLED, &trans->status);
	return 0;
}

static void iwl_trans_virtio_write8(struct iwl_trans *trans, u32 ofs, u8 val)
{
	struct iwl_trans_virtio *trans_virtio =
		IWL_TRANS_GET_VIRTIO_TRANS(trans);
	send_control_msg(trans_virtio, VIRTIO_IWL_E_CONST_SIZE,
			 0, ofs, &val, 1);
}

static void iwl_trans_virtio_write32(struct iwl_trans *trans, u32 ofs, u32 val)
{
	struct iwl_trans_virtio *trans_virtio =
		IWL_TRANS_GET_VIRTIO_TRANS(trans);
	send_control_msg(trans_virtio, VIRTIO_IWL_E_CONST_SIZE,
			 0, ofs, &val, 4);
}

static u32 iwl_trans_virtio_read32(struct iwl_trans *trans, u32 ofs)
{
	struct iwl_trans_virtio *trans_virtio =
		IWL_TRANS_GET_VIRTIO_TRANS(trans);
	u32 val;

	send_control_msg(trans_virtio, VIRTIO_IWL_E_CONST_SIZE,
			 VIRTIO_IWL_F_DIR_IN, ofs, &val, 4);
	return val;
}

static void iwl_trans_virtio_write_prph(struct iwl_trans *trans,
					u32 ofs, u32 val)
{
	struct iwl_trans_virtio *trans_virtio =
		IWL_TRANS_GET_VIRTIO_TRANS(trans);
	send_control_msg(trans_virtio, VIRTIO_IWL_E_PRPH,
			 0, ofs, &val, 4);
}

static u32 iwl_trans_virtio_read_prph(struct iwl_trans *trans, u32 ofs)
{
	struct iwl_trans_virtio *trans_virtio =
		IWL_TRANS_GET_VIRTIO_TRANS(trans);
	u32 val;

	send_control_msg(trans_virtio, VIRTIO_IWL_E_PRPH,
			 VIRTIO_IWL_F_DIR_IN, ofs, &val, 4);
	return val;
}

static int iwl_trans_virtio_write_mem(struct iwl_trans *trans, u32 addr,
				      const void *buf, int dwords)
{
	return 0;
}

static int iwl_trans_virtio_read_mem(struct iwl_trans *trans, u32 addr,
				     void *buf, int dwords)
{
	return 0;
}

static int iwl_trans_virtio_wait_txq_empty(struct iwl_trans *trans, int txq_idx)
{
	/* TODO: map txq_idx to virtio index */
	return 0;
}

static void iwl_trans_virtio_fw_alive(struct iwl_trans *trans, u32 scd_addr)
{
	struct iwl_trans_virtio *trans_virtio =
		IWL_TRANS_GET_VIRTIO_TRANS(trans);
	u32 buf;

	send_control_msg(trans_virtio, 10, 0, 0, &buf, 4);
}

int iwl_trans_validate_hcmd(struct iwl_host_cmd *cmd)
{
	u16 copy_size, cmd_size;
	u16 cmdlen[IWL_MAX_CMD_TBS_PER_TFD];
	int i;
	bool had_nocopy = false;
	bool dup_buf = false;

	copy_size = sizeof(struct iwl_cmd_header_wide);
	cmd_size = sizeof(struct iwl_cmd_header_wide);

	/* This code is added only for checking the upper layer
	 * But we just copy all to one buffer
	 */
	for (i = 0; i < IWL_MAX_CMD_TBS_PER_TFD; i++) {
		if (!cmd->len[i])
			continue;

		if (cmd->dataflags[i] & IWL_HCMD_DFL_NOCOPY) {
			had_nocopy = true;
			if (WARN_ON(cmd->dataflags[i] & IWL_HCMD_DFL_DUP))
				return -EINVAL;

		} else if (cmd->dataflags[i] & IWL_HCMD_DFL_DUP) {
			/*
			 * This is also a chunk that isn't copied
			 * to the static buffer so set had_nocopy.
			 */
			had_nocopy = true;

			/* only allowed once */
			if (WARN_ON(dup_buf))
				return -EINVAL;

		} else {
			/* NOCOPY must not be followed by normal! */
			if (WARN_ON(had_nocopy))
				return -EINVAL;

			dup_buf = true;
			copy_size += cmdlen[i];
		}
		cmd_size += cmd->len[i];
	}
	return 0;
}

/* This is what HOST SIM puts in the fhd field */
#define TFD_INFO_SCHD_1ST_TIME_MSK   0x00000800
int iwl_trans_virtio_send_hcmd(struct iwl_trans *trans,
			       struct iwl_host_cmd *cmd)
{
	struct iwl_trans_virtio *trans_virtio =
		IWL_TRANS_GET_VIRTIO_TRANS(trans);

	u8 group_id = iwl_cmd_groupid(cmd->id);
	char *buf, *orig_buf;
	int i;
	u32 order = iwl_trans_page_order(trans);
	u32 max_size = PAGE_SIZE << order;
	u16 cmd_size;
	int ret;
	struct page *page;
	struct iwl_cmd_header_wide *hdr_wide;
	struct iwl_virtqueue *iwl_q = &trans_virtio->h_ovq;

	ret = iwl_trans_validate_hcmd(cmd);
	if (ret)
		goto error;

	/* To make life simple we copy the cmd to one buffer */
	page = iwl_virtio_rx_alloc_page(trans, GFP_KERNEL);
	if (!page) {
		ret = -ENOMEM;
		goto free;
	}

	orig_buf = page_address(page);
	buf = orig_buf;

	/* Put tfdInfo constent */
	*(u32 *)buf = cpu_to_le32(TFD_INFO_SCHD_1ST_TIME_MSK);
	buf += 4;

	/* kip room for command header */
	hdr_wide = (struct iwl_cmd_header_wide *)buf;
	buf += sizeof(struct iwl_cmd_header_wide);

	for (i = 0; i < IWL_MAX_CMD_TBS_PER_TFD; i++) {
		if (!cmd->len[i])
			continue;

		if (WARN_ON(cmd->len[i] + (u32)(buf - orig_buf) > max_size)) {
			ret = -EINVAL;
			goto free;
		}

		memcpy(buf, cmd->data[i], cmd->len[i]);
		buf += cmd->len[i];
	}

	cmd_size = (u16)(buf - orig_buf);

	/* set up the header */
	hdr_wide->cmd = iwl_cmd_opcode(cmd->id);
	hdr_wide->group_id = group_id;
	hdr_wide->version = iwl_cmd_version(cmd->id);
	hdr_wide->length =
		cpu_to_le16(cmd_size - sizeof(struct iwl_cmd_header_wide) - 4);
	hdr_wide->reserved = 0;
	hdr_wide->sequence = cpu_to_le16(iwl_q->seq++);

	IWL_DEBUG_HC(trans, "Sending command %s (%.2x.%.2x), seq: 0x%04X\n",
		     iwl_get_cmd_string(trans, cmd->id), group_id,
		     hdr_wide->cmd, le16_to_cpu(hdr_wide->sequence));
	trace_iwlwifi_dev_hcmd(trans->dev, cmd, cmd_size, hdr_wide);
	ret = _iwl_virtio_enqueue_cmd(&trans_virtio->h_ovq, page, orig_buf,
				      cmd_size);
	if (ret)
		goto free;

	return 0;
free:
	__free_pages(page, order);
error:
	WARN_ON(ret);
	return ret;
}

static inline void iwl_disable_interrupts(struct iwl_trans *trans)
{
	/* TODO: disable callbacks on virt queues */
}

static inline void iwl_enable_interrupts(struct iwl_trans *trans)
{
	/* TODO: enable callbacks on virt queues */
}

void iwl_trans_virtio_sync_nmi(struct iwl_trans *trans)
{
	unsigned long timeout = jiffies + IWL_TRANS_NMI_TIMEOUT;
	bool interrupts_enabled = test_bit(STATUS_INT_ENABLED, &trans->status);
	/* TODO: add in usim interrupt register address
	 * for now all reads/writes do nothing so we can init it to 0 with no
	 * harm
	 */
	u32 inta_addr = 0, sw_err_bit = 0;

	/* if the interrupts were already disabled, there is no point in
	 * calling iwl_disable_interrupts
	 */
	if (interrupts_enabled)
		iwl_disable_interrupts(trans);

	iwl_force_nmi(trans);
	while (time_after(timeout, jiffies)) {
		u32 inta_hw = iwl_read32(trans, inta_addr);

		/* Error detected by uCode */
		if (inta_hw & sw_err_bit) {
			/* Clear causes register */
			iwl_write32(trans, inta_addr, inta_hw & sw_err_bit);
			break;
		}

		mdelay(1);
	}

	/* enable interrupts only if there were already enabled before this
	 * function to avoid a case were the driver enable interrupts before
	 * proper configurations were made
	 */
	if (interrupts_enabled)
		iwl_enable_interrupts(trans);

	iwl_trans_fw_error(trans);
}

#define HOST_COMPLETE_TIMEOUT	(2 * HZ * CPTCFG_IWL_TIMEOUT_FACTOR)

static int iwl_trans_virtio_send_hcmd_sync(struct iwl_trans *trans,
					   struct iwl_host_cmd *cmd)
{
	struct iwl_trans_virtio *trans_virtio =
			IWL_TRANS_GET_VIRTIO_TRANS(trans);
	const char *cmd_str = iwl_get_cmd_string(trans, cmd->id);
	//struct iwl_txq *txq = trans_pcie->txq[trans_pcie->cmd_queue];
	int cmd_idx;
	int ret;

	IWL_DEBUG_INFO(trans, "Attempting to send sync command %s\n", cmd_str);

	if (WARN(test_and_set_bit(STATUS_SYNC_HCMD_ACTIVE,
				  &trans->status),
		 "Command %s: a command is already active!\n", cmd_str))
		return -EIO;

	/* This is double check if we past the STATUS_SYNC_HCMD_ACTIVE
	 * tx_sync should alway be NULL
	 */
	if (WARN(trans_virtio->tx_sync,
		 "Command %s: tx_sync is in use!\n", cmd_str))
		return -EIO;

	IWL_DEBUG_INFO(trans, "Setting HCMD_ACTIVE for command %s\n", cmd_str);

	trans_virtio->tx_sync = cmd;
	cmd_idx = iwl_trans_virtio_send_hcmd(trans, cmd);
	if (cmd_idx) {
		ret = cmd_idx;
		trans_virtio->tx_sync = NULL;
		clear_bit(STATUS_SYNC_HCMD_ACTIVE, &trans->status);
		IWL_ERR(trans, "Error sending %s: enqueue_hcmd failed: %d\n",
			cmd_str, ret);
		return ret;
	}

	ret = wait_event_timeout(trans_virtio->wait_command_queue,
				 !test_bit(STATUS_SYNC_HCMD_ACTIVE,
					   &trans->status),
				 HOST_COMPLETE_TIMEOUT);
	if (!ret) {
		IWL_ERR(trans, "Error sending %s: time out after %dms.\n",
			cmd_str, jiffies_to_msecs(HOST_COMPLETE_TIMEOUT));

		trans_virtio->tx_sync = NULL;
		clear_bit(STATUS_SYNC_HCMD_ACTIVE, &trans->status);
		IWL_DEBUG_INFO(trans, "Clearing HCMD_ACTIVE for command %s\n",
			       cmd_str);
		ret = -ETIMEDOUT;

		iwl_trans_virtio_sync_nmi(trans);
		goto cancel;
	}

	if (test_bit(STATUS_FW_ERROR, &trans->status)) {
		IWL_ERR(trans, "FW error in SYNC CMD %s\n", cmd_str);
		dump_stack();
		ret = -EIO;
		goto cancel;
	}

	if (!(cmd->flags & CMD_SEND_IN_RFKILL) &&
	    test_bit(STATUS_RFKILL_OPMODE, &trans->status)) {
		IWL_DEBUG_RF_KILL(trans, "RFKILL in SYNC CMD... no rsp\n");
		ret = -ERFKILL;
		goto cancel;
	}

	if ((cmd->flags & CMD_WANT_SKB) && !cmd->resp_pkt) {
		IWL_ERR(trans, "Error: Response NULL in '%s'\n", cmd_str);
		ret = -EIO;
		goto cancel;
	}

	return 0;

cancel:
	if (cmd->flags & CMD_WANT_SKB) {
		/*
		 * Cancel the CMD_WANT_SKB flag for the cmd in the
		 * TX cmd queue. Otherwise in case the cmd comes
		 * in later, it will possibly set an invalid
		 * address (cmd->meta.source).
		 */
		//txq->entries[cmd_idx].meta.flags &= ~CMD_WANT_SKB;
	}

	if (cmd->resp_pkt) {
		iwl_free_resp(cmd);
		cmd->resp_pkt = NULL;
	}

	return ret;
}

int iwl_trans_virtio_send_cmd(struct iwl_trans *trans,
			      struct iwl_host_cmd *cmd)
{
	if (!(cmd->flags & CMD_SEND_IN_RFKILL) &&
	    test_bit(STATUS_RFKILL_OPMODE, &trans->status)) {
		IWL_DEBUG_RF_KILL(trans, "Dropping CMD 0x%x: RF KILL\n",
				  cmd->id);
		return -ERFKILL;
	}

	if (cmd->flags & CMD_ASYNC) {
		int ret;

		/* An asynchronous command can not expect an SKB to be set. */
		if (WARN_ON(cmd->flags & CMD_WANT_SKB))
			return -EINVAL;

		ret = iwl_trans_virtio_send_hcmd(trans, cmd);
		if (ret < 0) {
			IWL_ERR(trans,
				"Error sending %s: enqueue_hcmd failed: %d\n",
				iwl_get_cmd_string(trans, cmd->id), ret);
			return ret;
		}
		return 0;
	}

	return iwl_trans_virtio_send_hcmd_sync(trans, cmd);
}

static void iwl_trans_virtio_stop_device(struct iwl_trans *trans)
{
	struct iwl_trans_virtio *trans_virtio =
		IWL_TRANS_GET_VIRTIO_TRANS(trans);
	u32 val;

	clear_bit(STATUS_DEVICE_ENABLED, &trans->status);
	send_control_msg(trans_virtio, VIRTIO_IWL_E_STOP_DEVICE,
			 0, 0, &val, 4);
}

static bool iwl_trans_virtio_grab_nic_access(struct iwl_trans *trans,
					     unsigned long *flags)
{
	/*TODO: maybe simulate this */
	return true;
}

static void iwl_trans_virtio_release_nic_access(struct iwl_trans *trans,
						unsigned long *flags)
{
}

static void iwl_trans_virtio_debugfs_cleanup(struct iwl_trans *trans)
{
}

static int iwl_trans_virtio_rxq_dma_data(struct iwl_trans *trans, int queue,
					 struct iwl_trans_rxq_dma_data *data)
{
	if (queue != 1)
		return -EINVAL;

	/* this just exists to make the firmware happy - for now at least */
	*data = (struct iwl_trans_rxq_dma_data){};

	return 0;
}

static void fw_load_work_handler(struct work_struct *work)
{
	struct iwl_trans_virtio *trans_virtio;
	__le32 image_size = 0;
	size_t size;
	struct virtio_iwl_fw_image *fw_image;
	u8 *vdata;
	void *context;
	void (*cont)(const struct firmware *fw, void *context);
	struct firmware *fw;
	int ret;

	trans_virtio = container_of(work, struct iwl_trans_virtio,
				    fw_load.work);

	ret = send_control_msg(trans_virtio, VIRTIO_IWL_E_GET_FW_SIZE,
			       VIRTIO_IWL_F_DIR_IN, 0,
			       &image_size, sizeof(image_size));

	if (ret || !le32_to_cpu(image_size)) {
		IWL_ERR(trans_virtio->trans, "failed to get image size\n");
		return;
	}

	size = le32_to_cpu(image_size);

	/* keep aside for more calls */
	context = trans_virtio->fw_load.context;
	cont = trans_virtio->fw_load.cont;
	trans_virtio->fw_load.cont = NULL;

	if (WARN(!cont, "no callback function set\n"))
		return;

	fw = kzalloc(sizeof(*fw), GFP_KERNEL);
	fw_image = kzalloc(size, GFP_KERNEL);
	if (!fw_image || !fw) {
		IWL_ERR(trans_virtio->trans, "no kmalloc memory\n");
		goto kfree;
	}

	vdata = vmalloc(size);
	if (!vdata) {
		IWL_ERR(trans_virtio->trans, "no vmalloc memory\n");
		goto kfree;
	}

	fw->data = vdata;

	ret = send_control_msg(trans_virtio, VIRTIO_IWL_E_GET_FW,
			       VIRTIO_IWL_F_DIR_IN, 0, fw_image, size);

	if (ret)
		goto err;

	fw->size = le32_to_cpu(fw_image->size);

	if (WARN_ON(fw->size > size))
		goto err;

	memset(vdata, 0, size);
	memcpy(vdata, fw_image->data, fw->size);

	if (WARN_ON(!cont))
		goto err;

	kfree(fw_image);
	/* fw, and vdata memory release happens in the callback */
	cont(fw, context);
	return;
err:
	vfree(vdata);
kfree:
	kfree(fw);
	kfree(fw_image);
}

static int iwl_trans_virtio_request_fw(struct iwl_trans *trans,
				       void *context,
				       void (*cont)(const struct firmware *fw,
						    void *context))
{
	struct iwl_trans_virtio *trans_virtio =
		IWL_TRANS_GET_VIRTIO_TRANS(trans);

	/* make sure we have a callback */
	if (WARN_ON(!cont))
		return -EINVAL;

	/* we don't support multi loading FW at the same time */
	if (WARN_ON(trans_virtio->fw_load.cont))
		return -EBUSY;

	trans_virtio->fw_load.context = context;
	trans_virtio->fw_load.cont = cont;
	schedule_work(&trans_virtio->fw_load.work);
	return 0;
}

int iwl_trans_virtio_tx(struct iwl_trans *trans, struct sk_buff *skb,
			struct iwl_device_tx_cmd *dev_cmd, int txq_id)
{
	return -EINVAL;
}

int iwl_trans_virtio_txq_alloc(struct iwl_trans *trans,
			       __le16 flags, u8 sta_id, u8 tid,
			       int cmd_id, int size,
			       unsigned int timeout)
{
	/*
	 * dummy: return in range [0, 512]
	 */
	return (sta_id + 1) * (tid + 1) - 1;
}

void iwl_trans_virtio_txq_free(struct iwl_trans *trans, int queue)
{
}

static const struct iwl_trans_ops trans_ops_virtio = {
	.configure = iwl_trans_virtio_configure,
	.start_hw = iwl_trans_virtio_start_hw,
	.start_fw = iwl_trans_virtio_start_fw,
	.fw_alive = iwl_trans_virtio_fw_alive,
	.stop_device = iwl_trans_virtio_stop_device,
	.send_cmd = iwl_trans_virtio_send_cmd,
	.write8 = iwl_trans_virtio_write8,
	.write32 = iwl_trans_virtio_write32,
	.read32 = iwl_trans_virtio_read32,
	.write_prph = iwl_trans_virtio_write_prph,
	.read_prph = iwl_trans_virtio_read_prph,
	.write_mem = iwl_trans_virtio_write_mem,
	.read_mem = iwl_trans_virtio_read_mem,
	.grab_nic_access = iwl_trans_virtio_grab_nic_access,
	.release_nic_access = iwl_trans_virtio_release_nic_access,
	.debugfs_cleanup = iwl_trans_virtio_debugfs_cleanup,
	.rxq_dma_data = iwl_trans_virtio_rxq_dma_data,
	.request_firmware = iwl_trans_virtio_request_fw,

	.tx = iwl_trans_virtio_tx,
	.txq_alloc = iwl_trans_virtio_txq_alloc,
	.txq_free = iwl_trans_virtio_txq_free,
/*
	.reclaim = iwl_trans_pcie_reclaim,
	.set_q_ptrs = iwl_trans_pcie_set_q_ptrs,

*/
	.wait_txq_empty = iwl_trans_virtio_wait_txq_empty,
};

struct iwl_trans *
iwl_trans_virtio_alloc(struct virtio_device *vdev,
		       const struct iwl_cfg_trans_params *cfg_trans)
{
	struct iwl_trans_virtio *trans_virtio;
	struct iwl_trans *trans;

	/* just use the old large allocation here - easier */
	trans = iwl_trans_alloc(sizeof(*trans_virtio),
				&vdev->dev, &trans_ops_virtio,
				sizeof(struct iwl_device_cmd),
				sizeof(void *));
	if (!trans)
		return ERR_PTR(-ENOMEM);

	trans_virtio =
		IWL_TRANS_GET_VIRTIO_TRANS(trans);

	trans_virtio->trans = trans;
	mutex_init(&trans_virtio->mutex);

	/* Initialize the wait queue for commands */
	init_waitqueue_head(&trans_virtio->wait_command_queue);

	iwl_dbg_tlv_init(trans);
	return trans;
}

static void iwl_trans_virtio_free(struct iwl_trans_virtio *trans_virtio)
{
	mutex_destroy(&trans_virtio->mutex);
	iwl_trans_free(trans_virtio->trans);
}

static int virtiwl_probe(struct virtio_device *vdev)
{
	struct iwl_trans_virtio *trans_virtio;
	struct iwl_trans *iwl_trans;
	const struct iwl_cfg *cfg;
	int err;
	u16 id;

	/*TODO: assume we have ths feature and only check the get */
	if (virtio_has_feature(vdev, VIRTIO_IWL_F_ID) && !vdev->config->get) {
		dev_err(&vdev->dev, "%s failure: config access disabled\n",
			__func__);
		return -EINVAL;
	}

	id = virtio_cread16(vdev, offsetof(struct virtio_iwl_config, id));
	cfg = virtio_iwl_id_to_cfg(id);

	if (!cfg) {
		dev_err(&vdev->dev, "invalid id: %d\n", id);
		return -EINVAL;
	}

	iwl_trans = iwl_trans_virtio_alloc(vdev, &cfg->trans);
	/* virtio work */
	if (IS_ERR(iwl_trans))
		return PTR_ERR(iwl_trans);

	trans_virtio =
		IWL_TRANS_GET_VIRTIO_TRANS(iwl_trans);

	vdev->priv = trans_virtio;
	iwl_trans->cfg = cfg;
	iwl_trans->trans_cfg = &cfg->trans;

	/* Attach this trans_virtio to this virtio_device, and vice-versa. */
	trans_virtio->vdev = vdev;

	iwl_trans->num_rx_queues = 2;

	spin_lock_init(&trans_virtio->c_ovq.lock);
	spin_lock_init(&trans_virtio->c_ivq.lock);
	spin_lock_init(&trans_virtio->h_ovq.lock);
	spin_lock_init(&trans_virtio->h_ivq.lock);

	INIT_WORK(&trans_virtio->control_work, &control_work_handler);
	INIT_WORK(&trans_virtio->fw_load.work, &fw_load_work_handler);
	INIT_WORK(&trans_virtio->rxdef_work, &rxdef_work_handler);

	/* TODO: maybe get this from config space */
	trans_virtio->nr_queues = VIRTIO_IWL_Q_MAX;
	err = init_vqs(trans_virtio);
	iwl_trans->drv = iwl_drv_start(iwl_trans);

	if (err)
		goto free_dev;

	return 0;

free_dev:
	iwl_trans_virtio_free(trans_virtio);
	return err;
}

static void virtiwl_remove(struct virtio_device *vdev)
{
	struct iwl_trans_virtio *trans_virtio =
		(struct iwl_trans_virtio *)vdev->priv;
	/* Disable interrupts for vqs */
	vdev->config->reset(vdev);

	iwl_drv_stop(trans_virtio->trans->drv);

	cancel_work_sync(&trans_virtio->control_work);
	cancel_work_sync(&trans_virtio->rxdef_work);
	cancel_work_sync(&trans_virtio->fw_load.work);
	remove_vqs(trans_virtio);
	iwl_trans_virtio_free(trans_virtio);
}

static struct virtio_driver virtio_iwl = {
	.feature_table			= features,
	.feature_table_size		= ARRAY_SIZE(features),
	.driver.name			= "iwlwifi-virtio",
	.driver.owner			= THIS_MODULE,
	.id_table			= id_table,
	.probe				= virtiwl_probe,
	.remove				= virtiwl_remove,
};

int __must_check iwl_virtio_register_driver(void)
{
	int error;

	error = register_virtio_driver(&virtio_iwl);
	if (error)
		return error;
	return 0;
}

void iwl_virtio_unregister_driver(void)
{
	unregister_virtio_driver(&virtio_iwl);
}

MODULE_DEVICE_TABLE(virtio, id_table);
