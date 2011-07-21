/* Copyright (c) 2009, Code Aurora Forum. All rights reserved.
 * Copyright (C) 2010 Sony Ericsson Mobile Communications AB.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 */
//FIXME: most allocations need not be GFP_ATOMIC
/* FIXME: management of mutexes */
/* FIXME: msm_pmem_region_lookup return values */
/* FIXME: way too many copy to/from user */
/* FIXME: does region->active mean free */
/* FIXME: check limits on command lenghts passed from userspace */
/* FIXME: __msm_release: which queues should we flush when opencnt != 0 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <mach/board.h>

#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/uaccess.h>
#include <linux/android_pmem.h>
#include <linux/poll.h>
//#include <media/msm_camera.h>
#include "camera.h"
DEFINE_MUTEX(hlist_mut);
DEFINE_MUTEX(pp_prev_lock);
DEFINE_MUTEX(pp_snap_lock);

#define MSM_MAX_CAMERA_SENSORS 5
#define CAMERA_STOP_SNAPSHOT 42

#define ERR_USER_COPY(to) pr_err("%s(%d): copy %s user\n", \
				__func__, __LINE__, ((to) ? "to" : "from"))
#define ERR_COPY_FROM_USER() ERR_USER_COPY(0)
#define ERR_COPY_TO_USER() ERR_USER_COPY(1)

#ifdef CDBG
#undef CDBG
#endif

#define CDBG(fmt, args...) printk(KERN_INFO "msm_camdrv: " fmt, ##args)

typedef int (*msm_camio_probe_on_type) (struct platform_device *);
typedef int (*msm_camio_probe_off_type) (struct platform_device *);
typedef void (*msm_camio_vfe_blk_reset_type) (void);
typedef void (*msm_camvfe_fn_init_type) (struct msm_camvfe_fn *, void *);

static msm_camio_probe_on_type msm_camio_probe_on_ax;
static msm_camio_probe_off_type msm_camio_probe_off_ax;
static msm_camio_vfe_blk_reset_type msm_camio_vfe_blk_reset_ax;
static msm_camvfe_fn_init_type msm_camvfe_fn_init_ax;

static inline void ax8camera_free_qcmd(struct msm_queue_cmd *qcmd)
{
	if (!qcmd || !qcmd->on_heap)
		return;
	if (!--qcmd->on_heap)
		kfree(qcmd);
}

static void ax8camera_msm_enqueue(struct msm_device_queue *queue,
		struct list_head *entry)
{
	unsigned long flags;
	spin_lock_irqsave(&queue->lock, flags);
	queue->len++;
	if (queue->len > queue->max) {
		queue->max = queue->len;
		pr_info("%s: queue %s new max is %d\n", __func__,
			queue->name, queue->max);
	}
	list_add_tail(entry, &queue->list);
	wake_up(&queue->wait);
	CDBG("%s: woke up %s\n", __func__, queue->name);
	spin_unlock_irqrestore(&queue->lock, flags);
}

#define ax8camera_msm_dequeue(queue, member) ({				\
	unsigned long flags;					\
	struct msm_device_queue *__q = (queue);			\
	struct msm_queue_cmd *qcmd = 0;				\
	spin_lock_irqsave(&__q->lock, flags);			\
	if (!list_empty(&__q->list)) {				\
		__q->len--;					\
		qcmd = list_first_entry(&__q->list,		\
				struct msm_queue_cmd, member);	\
		list_del_init(&qcmd->member);			\
	}							\
	spin_unlock_irqrestore(&__q->lock, flags);	\
	qcmd;							\
})


#define __CONTAINS(r, v, l, field) ({				\
	typeof(r) __r = r;					\
	typeof(v) __v = v;					\
	typeof(v) __e = __v + l;				\
	int res = __v >= __r->field &&				\
		__e <= __r->field + __r->len;			\
	res;							\
})

#define CONTAINS(r1, r2, field) ({				\
	typeof(r2) __r2 = r2;					\
	__CONTAINS(r1, __r2->field, __r2->len, field);		\
})

#define IN_RANGE(r, v, field) ({				\
	typeof(r) __r = r;					\
	typeof(v) __vv = v;					\
	int res = ((__vv >= __r->field) &&			\
		(__vv < (__r->field + __r->len)));		\
	res;							\
})

#define OVERLAPS(r1, r2, field) ({				\
	typeof(r1) __r1 = r1;					\
	typeof(r2) __r2 = r2;					\
	typeof(__r2->field) __v = __r2->field;			\
	typeof(__v) __e = __v + __r2->len - 1;			\
	int res = (IN_RANGE(__r1, __v, field) ||		\
		   IN_RANGE(__r1, __e, field));                 \
	res;							\
})


static int ax8camera_check_overlap(struct hlist_head *ptype,
			unsigned long paddr,
			unsigned long len)
{
	struct msm_pmem_region *region;
	struct msm_pmem_region t = { .paddr = paddr, .len = len };
	struct hlist_node *node;

	hlist_for_each_entry(region, node, ptype, list) {
		if (CONTAINS(region, &t, paddr) ||
				CONTAINS(&t, region, paddr) ||
				OVERLAPS(region, &t, paddr)) {
			CDBG(" region (PHYS %p len %ld)"
				" clashes with registered region"
				" (paddr %p len %ld)\n",
				(void *)t.paddr, t.len,
				(void *)region->paddr, region->len);
			return -1;
		}
	}

	return 0;
}

static int ax8camera_check_pmem_info(struct msm_pmem_info *info, int len)
{
	if (info->offset < len &&
	    info->offset + info->len <= len &&
	    info->y_off < len &&
	    info->cbcr_off < len)
		return 0;

	pr_err("%s: check failed: off %d len %d y %d cbcr %d (total len %d)\n",
		__func__,
		info->offset,
		info->len,
		info->y_off,
		info->cbcr_off,
		len);
	return -EINVAL;
}

static unsigned long ax8camera_msm_pmem_frame_vtop_lookup(struct msm_sync *sync,
		unsigned long buffer,
		uint32_t yoff, uint32_t cbcroff, int fd)
{
	struct msm_pmem_region *region;
	struct hlist_node *node, *n;
	unsigned long flags = 0;

	spin_lock_irqsave(&sync->pmem_frame_spinlock, flags);
	hlist_for_each_entry_safe(region,
		node, n, &sync->pmem_frames, list) {
		if (((unsigned long)(region->info.vaddr) == buffer) &&
				(region->info.y_off == yoff) &&
				(region->info.cbcr_off == cbcroff) &&
				(region->info.fd == fd) &&
				(region->info.active == 0)) {
			region->info.active = 1;
			spin_unlock_irqrestore(&sync->pmem_frame_spinlock,
				flags);
			return region->paddr;
		}
	}
	spin_unlock_irqrestore(&sync->pmem_frame_spinlock, flags);

	return 0;
}

static int ax8camera_msm_pmem_frame_ptov_lookup(struct msm_sync *sync,
		unsigned long pyaddr,
		unsigned long pcbcraddr,
		struct msm_pmem_info *pmem_info,
		int clear_active)
{
	struct msm_pmem_region *region;
	struct hlist_node *node, *n;
	unsigned long flags = 0;

	spin_lock_irqsave(&sync->pmem_frame_spinlock, flags);
	hlist_for_each_entry_safe(region, node, n, &sync->pmem_frames, list) {
		if (pyaddr == (region->paddr + region->info.y_off) &&
				pcbcraddr == (region->paddr +
						region->info.cbcr_off) &&
				region->info.active) {
			/* offset since we could pass vaddr inside
			 * a registerd pmem buffer
			 */
			memcpy(pmem_info, &region->info, sizeof(*pmem_info));
			if (clear_active)
				region->info.active = 0;
			spin_unlock_irqrestore(&sync->pmem_frame_spinlock,
				flags);
			return 0;
		}
	}

	spin_unlock_irqrestore(&sync->pmem_frame_spinlock, flags);
	return -EINVAL;
}

static int ax8camera_msm_unblock_poll_frame(struct msm_sync *sync)
{
	unsigned long flags;
	CDBG("%s\n", __func__);
	spin_lock_irqsave(&sync->frame_q.lock, flags);
	sync->unblock_poll_frame = 1;
	wake_up(&sync->frame_q.wait);
	spin_unlock_irqrestore(&sync->frame_q.lock, flags);
	return 0;
}

static struct msm_queue_cmd *ax8camera__msm_control(struct msm_sync *sync,
		struct msm_device_queue *queue,
		struct msm_queue_cmd *qcmd,
		int timeout)
{
	unsigned long flags;
	int rc;

	CDBG("Inside __msm_control\n");
	ax8camera_msm_enqueue(&sync->event_q, &qcmd->list_config);
	/* wake up config thread */

	if (!queue)
		return NULL;

	/* wait for config status */
	CDBG("Waiting for config status \n");
	rc = wait_event_interruptible_timeout(
			queue->wait,
			!list_empty_careful(&queue->list),
			timeout);
	CDBG("Waiting over for config status \n");
	if (list_empty_careful(&queue->list)) {
		if (!rc)
			rc = -ETIMEDOUT;
		if (rc < 0) {
			pr_err("%s: wait_event error %d\n", __func__, rc);
			spin_lock_irqsave(&(sync->event_q.lock), flags);
			list_del_init(&qcmd->list_config);
			spin_unlock_irqrestore(&(sync->event_q.lock), flags);
			return ERR_PTR(rc);
		}
	}
	qcmd = ax8camera_msm_dequeue(queue, list_control);
	BUG_ON(!qcmd);
	CDBG("__msm_control done \n");
	return qcmd;
}

static struct msm_queue_cmd *ax8camera__msm_control_nb(struct msm_sync *sync,
					struct msm_queue_cmd *qcmd_to_copy)
{
	/* Since this is a non-blocking command, we cannot use qcmd_to_copy and
	 * its data, since they are on the stack.  We replicate them on the heap
	 * and mark them on_heap so that they get freed when the config thread
	 * dequeues them.
	 */

	struct msm_ctrl_cmd *udata;
	struct msm_ctrl_cmd *udata_to_copy = qcmd_to_copy->command;

	struct msm_queue_cmd *qcmd =
			kmalloc(sizeof(*qcmd_to_copy) +
				sizeof(*udata_to_copy) +
				udata_to_copy->length,
				GFP_KERNEL);
	if (!qcmd) {
		pr_err("%s: out of memory\n", __func__);
		return ERR_PTR(-ENOMEM);
	}
	*qcmd = *qcmd_to_copy;
	udata = qcmd->command = qcmd + 1;
	memcpy(udata, udata_to_copy, sizeof(*udata));
	udata->value = udata + 1;
	memcpy(udata->value, udata_to_copy->value, udata_to_copy->length);

	qcmd->on_heap = 1;

	/* qcmd_resp will be set to NULL */
	return ax8camera__msm_control(sync, NULL, qcmd, 0);
}


static int ax8camera_msm_control(struct msm_control_device *ctrl_pmsm,
			int block,
			void __user *arg)
{
	int rc = 0;

	struct msm_sync *sync = ctrl_pmsm->pmsm->sync;
	void __user *uptr;
	struct msm_ctrl_cmd udata;
	struct msm_queue_cmd qcmd;
	struct msm_queue_cmd *qcmd_resp = NULL;
	uint8_t data[50];

	CDBG("Inside msm_control\n");
	if (copy_from_user(&udata, arg, sizeof(struct msm_ctrl_cmd))) {
		ERR_COPY_FROM_USER();
		rc = -EFAULT;
		goto end;
	}

	uptr = udata.value;
	udata.value = data;
	if (udata.type == CAMERA_STOP_SNAPSHOT)
		sync->get_pic_abort = 1;
	qcmd.on_heap = 0;
	qcmd.type = MSM_CAM_Q_CTRL;
	qcmd.command = &udata;

	if (udata.length) {
		if (udata.length > sizeof(data)) {
			pr_err("%s: user data too large (%d, max is %d)\n",
					__func__,
					udata.length,
					sizeof(data));
			rc = -EIO;
			goto end;
		}
		if (copy_from_user(udata.value, uptr, udata.length)) {
			ERR_COPY_FROM_USER();
			rc = -EFAULT;
			goto end;
		}
	}

	if (unlikely(!block)) {
		qcmd_resp = ax8camera__msm_control_nb(sync, &qcmd);
		if (!qcmd_resp || IS_ERR(qcmd_resp)) {
			rc = PTR_ERR(qcmd_resp);
			qcmd_resp = NULL;
		}
		goto end;
	}

	qcmd_resp = ax8camera__msm_control(sync,
				  &ctrl_pmsm->ctrl_q,
				  &qcmd, MAX_SCHEDULE_TIMEOUT);

	if (!qcmd_resp || IS_ERR(qcmd_resp)) {
		/* Do not free qcmd_resp here.  If the config thread read it,
		 * then it has already been freed, and we timed out because
		 * we did not receive a MSM_CAM_IOCTL_CTRL_CMD_DONE.  If the
		 * config thread itself is blocked and not dequeueing commands,
		 * then it will either eventually unblock and process them,
		 * or when it is killed, qcmd will be freed in
		 * msm_release_config.
		 */
		rc = PTR_ERR(qcmd_resp);
		qcmd_resp = NULL;
		goto end;
	}

	if (qcmd_resp->command) {
		udata = *(struct msm_ctrl_cmd *)qcmd_resp->command;
		if (udata.length > 0) {
			if (copy_to_user(uptr,
					 udata.value,
					 udata.length)) {
				ERR_COPY_TO_USER();
				rc = -EFAULT;
				goto end;
			}
		}
		udata.value = uptr;

		if (copy_to_user((void *)arg, &udata,
				sizeof(struct msm_ctrl_cmd))) {
			ERR_COPY_TO_USER();
			rc = -EFAULT;
			goto end;
		}
	}

end:
	ax8camera_free_qcmd(qcmd_resp);
	CDBG(" msm_control done\n");
	CDBG("%s: rc %d\n", __func__, rc);
	return rc;
}

static int ax8camera___msm_pmem_table_del(struct msm_sync *sync,
		struct msm_pmem_info *pinfo)
{
	int rc = 0;
	struct msm_pmem_region *region;
	struct hlist_node *node, *n;
	unsigned long flags = 0;

	switch (pinfo->type) {
	case MSM_PMEM_VIDEO:
	case MSM_PMEM_PREVIEW:
	case MSM_PMEM_THUMBNAIL:
	case MSM_PMEM_MAINIMG:
	case MSM_PMEM_RAW_MAINIMG:
		spin_lock_irqsave(&sync->pmem_frame_spinlock, flags);
		hlist_for_each_entry_safe(region, node, n,
			&sync->pmem_frames, list) {

			if (pinfo->type == region->info.type &&
					pinfo->vaddr == region->info.vaddr &&
					pinfo->fd == region->info.fd) {
				hlist_del(node);
				put_pmem_file(region->file);
				kfree(region);
			}
		}
		spin_unlock_irqrestore(&sync->pmem_frame_spinlock, flags);
		break;

	case MSM_PMEM_AEC_AWB:
	case MSM_PMEM_AF:
		spin_lock_irqsave(&sync->pmem_stats_spinlock, flags);
		hlist_for_each_entry_safe(region, node, n,
			&sync->pmem_stats, list) {

			if (pinfo->type == region->info.type &&
					pinfo->vaddr == region->info.vaddr &&
					pinfo->fd == region->info.fd) {
				hlist_del(node);
				put_pmem_file(region->file);
				kfree(region);
			}
		}
		spin_unlock_irqrestore(&sync->pmem_stats_spinlock, flags);
		break;

	default:
		rc = -EINVAL;
		break;
	}

	return rc;
}

static int ax8camera_msm_pmem_table_del(struct msm_sync *sync, void __user *arg)
{
	struct msm_pmem_info info;

	if (copy_from_user(&info, arg, sizeof(info))) {
		ERR_COPY_FROM_USER();
		return -EFAULT;
	}

	return ax8camera___msm_pmem_table_del(sync, &info);
}

static int ax8camera_msm_pmem_table_add(struct hlist_head *ptype,
	struct msm_pmem_info *info, spinlock_t* pmem_spinlock)
{
	struct file *file;
	unsigned long paddr;
	unsigned long kvstart;
	unsigned long len;
	int rc;
	struct msm_pmem_region *region;
	unsigned long flags;


	rc = get_pmem_file(info->fd, &paddr, &kvstart, &len, &file);
	if (rc < 0) {
		pr_err("%s: get_pmem_file fd %d error %d\n",
			__func__,
			info->fd, rc);
		return rc;
	}

	if (!info->len)
		info->len = len;

	rc = ax8camera_check_pmem_info(info, len);
	if (rc < 0)
		return rc;

	paddr += info->offset;
	len = info->len;

	spin_lock_irqsave(pmem_spinlock, flags);
	if (ax8camera_check_overlap(ptype, paddr, len) < 0) {
		spin_unlock_irqrestore(pmem_spinlock, flags);
		return -EINVAL;
	}
	spin_unlock_irqrestore(pmem_spinlock, flags);

	CDBG("%s: type %d, paddr 0x%lx, vaddr 0x%lx\n",
		__func__,
		info->type, paddr, (unsigned long)info->vaddr);

	region = kmalloc(sizeof(struct msm_pmem_region), GFP_KERNEL);
	if (!region)
		return -ENOMEM;

	spin_lock_irqsave(pmem_spinlock, flags);
	INIT_HLIST_NODE(&region->list);

	region->paddr = paddr;
	region->len = len;
	region->file = file;
	memcpy(&region->info, info, sizeof(region->info));

	hlist_add_head(&(region->list), ptype);
	spin_unlock_irqrestore(pmem_spinlock, flags);

	return 0;
}

static int ax8camera___msm_register_pmem(struct msm_sync *sync,
		struct msm_pmem_info *pinfo)
{
	int rc = 0;

	switch (pinfo->type) {
	case MSM_PMEM_VIDEO:
	case MSM_PMEM_PREVIEW:
	case MSM_PMEM_THUMBNAIL:
	case MSM_PMEM_MAINIMG:
	case MSM_PMEM_RAW_MAINIMG:
		rc = ax8camera_msm_pmem_table_add(&sync->pmem_frames, pinfo,
			&sync->pmem_frame_spinlock);
		break;

	case MSM_PMEM_AEC_AWB:
	case MSM_PMEM_AF:
	case MSM_PMEM_AEC:
	case MSM_PMEM_AWB:
	case MSM_PMEM_RS:
	case MSM_PMEM_CS:
	case MSM_PMEM_IHIST:
	case MSM_PMEM_SKIN:

		rc = ax8camera_msm_pmem_table_add(&sync->pmem_stats, pinfo,
			 &sync->pmem_stats_spinlock);
		break;

	default:
		rc = -EINVAL;
		break;
	}

	return rc;
}

static int ax8camera_msm_register_pmem(struct msm_sync *sync, void __user *arg)
{
	struct msm_pmem_info info;

	if (copy_from_user(&info, arg, sizeof(info))) {
		ERR_COPY_FROM_USER();
		return -EFAULT;
	}

	return ax8camera___msm_register_pmem(sync, &info);
}

static int ax8camera___msm_put_frame_buf(struct msm_sync *sync,
		struct msm_frame *pb)
{
	unsigned long pphy;
	struct msm_vfe_cfg_cmd cfgcmd;

	int rc = -EIO;

	pphy = ax8camera_msm_pmem_frame_vtop_lookup(sync,
		pb->buffer,
		pb->y_off, pb->cbcr_off, pb->fd);

	if (pphy != 0) {
		CDBG("%s: rel: vaddr %lx, paddr %lx\n",
			__func__,
			pb->buffer, pphy);
		cfgcmd.cmd_type = CMD_FRAME_BUF_RELEASE;
		cfgcmd.value    = (void *)pb;
		if (sync->vfefn.vfe_config)
			rc = sync->vfefn.vfe_config(&cfgcmd, &pphy);
	} else {
		pr_err("%s: msm_pmem_frame_vtop_lookup failed\n",
			__func__);
		rc = -EINVAL;
	}

	return rc;
}

static int ax8camera_msm_put_frame_buffer(struct msm_sync *sync, void __user *arg)
{
	struct msm_frame buf_t;

	if (copy_from_user(&buf_t,
				arg,
				sizeof(struct msm_frame))) {
		ERR_COPY_FROM_USER();
		return -EFAULT;
	}

	return ax8camera___msm_put_frame_buf(sync, &buf_t);
}

static long ax8camera_msm_ioctl_common(struct msm_device *pmsm,
		unsigned int cmd,
		void __user *argp)
{
	CDBG("%s\n", __func__);
	switch (cmd) {
	case MSM_CAM_IOCTL_REGISTER_PMEM:
		return ax8camera_msm_register_pmem(pmsm->sync, argp);
	case MSM_CAM_IOCTL_UNREGISTER_PMEM:
		return ax8camera_msm_pmem_table_del(pmsm->sync, argp);
	default:
		return -EINVAL;
	}
}

static int ax8camera_msm_get_sensor_info(struct msm_sync *sync, void __user *arg)
{
	int rc = 0;
	struct msm_camsensor_info info;
	struct msm_camera_sensor_info *sdata;

	if (copy_from_user(&info,
			arg,
			sizeof(struct msm_camsensor_info))) {
		ERR_COPY_FROM_USER();
		return -EFAULT;
	}

	sdata = sync->pdev->dev.platform_data;
	CDBG("%s: sensor_name %s\n", __func__, sdata->sensor_name);

	memcpy(&info.name[0],
		sdata->sensor_name,
		MAX_SENSOR_NAME);
	info.flash_enabled = sdata->flash_data->flash_type !=
		MSM_CAMERA_FLASH_NONE;

	/* copy back to user space */
	if (copy_to_user((void *)arg,
			&info,
			sizeof(struct msm_camsensor_info))) {
		ERR_COPY_TO_USER();
		rc = -EFAULT;
	}

	return rc;
}

static int ax8camera___msm_get_pic(struct msm_sync *sync, struct msm_ctrl_cmd *ctrl)
{
	int rc = 0;
	int tm;

	struct msm_queue_cmd *qcmd = NULL;

	tm = (int)ctrl->timeout_ms;

	rc = wait_event_interruptible_timeout(
			sync->pict_q.wait,
			!list_empty_careful(
				&sync->pict_q.list) || sync->get_pic_abort,
			msecs_to_jiffies(tm));

	if (sync->get_pic_abort == 1) {
		sync->get_pic_abort = 0;
		return -ENODATA;
	}
	if (list_empty_careful(&sync->pict_q.list)) {
		if (rc == 0)
			return -ETIMEDOUT;
		if (rc < 0) {
			pr_err("%s: rc %d\n", __func__, rc);
			return rc;
		}
	}

	rc = 0;

	qcmd = ax8camera_msm_dequeue(&sync->pict_q, list_pict);
	BUG_ON(!qcmd);

	if (qcmd->command != NULL) {
		struct msm_ctrl_cmd *q =
			(struct msm_ctrl_cmd *)qcmd->command;
		ctrl->type = q->type;
		ctrl->status = q->status;
	} else {
		ctrl->type = -1;
		ctrl->status = -1;
	}

	ax8camera_free_qcmd(qcmd);

	return rc;
}

static int ax8camera_msm_get_pic(struct msm_sync *sync, void __user *arg)
{
	struct msm_ctrl_cmd ctrlcmd_t;
	int rc;

	if (copy_from_user(&ctrlcmd_t,
				arg,
				sizeof(struct msm_ctrl_cmd))) {
		ERR_COPY_FROM_USER();
		return -EFAULT;
	}

	rc = ax8camera___msm_get_pic(sync, &ctrlcmd_t);
	if (rc < 0)
		return rc;

	if (sync->croplen) {
		if (ctrlcmd_t.length != sync->croplen) {
			pr_err("%s: invalid len %d < %d\n",
				__func__,
				ctrlcmd_t.length,
				sync->croplen);
			return -EINVAL;
		}
		if (copy_to_user(ctrlcmd_t.value,
				sync->cropinfo,
				sync->croplen)) {
			ERR_COPY_TO_USER();
			return -EFAULT;
		}
	}
	CDBG("%s: copy snapshot frame to user\n", __func__);
	if (copy_to_user((void *)arg,
		&ctrlcmd_t,
		sizeof(struct msm_ctrl_cmd))) {
		ERR_COPY_TO_USER();
		return -EFAULT;
	}
	return 0;
}

static int ax8camera_msm_ctrl_cmd_done(struct msm_control_device *ctrl_pmsm,
		void __user *arg)
{
	void __user *uptr;
	struct msm_queue_cmd *qcmd = &ctrl_pmsm->qcmd;
	struct msm_ctrl_cmd *command = &ctrl_pmsm->ctrl;

	if (copy_from_user(command, arg, sizeof(*command))) {
		ERR_COPY_FROM_USER();
		return -EFAULT;
	}

	qcmd->on_heap = 0;
	qcmd->command = command;
	uptr = command->value;

	if (command->length > 0) {
		command->value = ctrl_pmsm->ctrl_data;
		if (command->length > sizeof(ctrl_pmsm->ctrl_data)) {
			pr_err("%s: user data %d is too big (max %d)\n",
				__func__, command->length,
				sizeof(ctrl_pmsm->ctrl_data));
			return -EINVAL;
	}

		if (copy_from_user(command->value,
					uptr,
					command->length)) {
			ERR_COPY_FROM_USER();
			return -EFAULT;
		}
	} else
		command->value = NULL;


		/* wake up control thread */
	ax8camera_msm_enqueue(&ctrl_pmsm->ctrl_q, &qcmd->list_control);

	return 0;
}

static int ax8camera___msm_get_frame(struct msm_sync *sync,
		struct msm_frame *frame)
{
	int rc = 0;

	struct msm_pmem_info pmem_info;
	struct msm_queue_cmd *qcmd = NULL;
	struct msm_vfe_resp *vdata;
	struct msm_vfe_phy_info *pphy;

	qcmd = ax8camera_msm_dequeue(&sync->frame_q, list_frame);

	if (!qcmd) {
		pr_err("%s: no preview frame.\n", __func__);
		return -EAGAIN;
	}

	vdata = (struct msm_vfe_resp *)(qcmd->command);
	pphy = &vdata->phy;


	rc = ax8camera_msm_pmem_frame_ptov_lookup(sync,
			pphy->y_phy,
			pphy->cbcr_phy,
			&pmem_info,
			1); /* mark frame in use */

	if (rc < 0) {
		pr_err("%s: cannot get frame, invalid lookup address "
			"y %x cbcr %x\n",
			__func__,
			pphy->y_phy,
			pphy->cbcr_phy);
		goto err;
	}

	frame->buffer = (unsigned long)pmem_info.vaddr;
	frame->y_off = pmem_info.y_off;
	frame->cbcr_off = pmem_info.cbcr_off;
	frame->fd = pmem_info.fd;
	frame->path = vdata->phy.output_id;
	CDBG("%s: y %x, cbcr %x, qcmd %x, virt_addr %x\n",
		__func__,
		pphy->y_phy, pphy->cbcr_phy, (int) qcmd, (int) frame->buffer);

err:
	ax8camera_free_qcmd(qcmd);
	return rc;
}

static int ax8camera_msm_get_frame(struct msm_sync *sync, void __user *arg)
{
	int rc = 0;
	struct msm_frame frame;

	if (copy_from_user(&frame,
				arg,
				sizeof(struct msm_frame))) {
		ERR_COPY_FROM_USER();
		return -EFAULT;
	}

	rc = ax8camera___msm_get_frame(sync, &frame);
	if (rc < 0)
		return rc;

	/* read the frame after the status has been read */
	rmb();

	if (sync->croplen) {
		if (frame.croplen != sync->croplen) {
			pr_err("%s: invalid frame croplen %d,"
				"expecting %d\n",
				__func__,
				frame.croplen,
				sync->croplen);
			return -EINVAL;
		}

		if (copy_to_user((void *)frame.cropinfo,
				sync->cropinfo,
				sync->croplen)) {
			ERR_COPY_TO_USER();
			return -EFAULT;
		}
	}

	if (copy_to_user((void *)arg,
				&frame, sizeof(struct msm_frame))) {
		ERR_COPY_TO_USER();
		rc = -EFAULT;
	}

	CDBG("%s: got frame\n", __func__);

	return rc;
}

static long ax8camera_msm_ioctl_frame(struct file *filep, unsigned int cmd,
	unsigned long arg)
{
	int rc = -EINVAL;
	void __user *argp = (void __user *)arg;
	struct msm_device *pmsm = filep->private_data;


	switch (cmd) {
	case MSM_CAM_IOCTL_GETFRAME:
		/* Coming from frame thread to get frame
		 * after SELECT is done */
		rc = ax8camera_msm_get_frame(pmsm->sync, argp);
		break;
	case MSM_CAM_IOCTL_RELEASE_FRAME_BUFFER:
		rc = ax8camera_msm_put_frame_buffer(pmsm->sync, argp);
		break;
	case MSM_CAM_IOCTL_UNBLOCK_POLL_FRAME:
		rc = ax8camera_msm_unblock_poll_frame(pmsm->sync);
		break;
	default:
		break;
	}

	return rc;
}


static long ax8camera_msm_ioctl_control(struct file *filep, unsigned int cmd,
	unsigned long arg)
{
	int rc = -EINVAL;
	void __user *argp = (void __user *)arg;
	struct msm_control_device *ctrl_pmsm = filep->private_data;
	struct msm_device *pmsm = ctrl_pmsm->pmsm;

	switch (cmd) {
	case MSM_CAM_IOCTL_CTRL_COMMAND:
		/* Coming from control thread, may need to wait for
		 * command status */
		CDBG("calling msm_control kernel msm_ioctl_control\n");
		rc = ax8camera_msm_control(ctrl_pmsm, 1, argp);
		break;
	case MSM_CAM_IOCTL_CTRL_COMMAND_2:
		/* Sends a message, returns immediately */
		rc = ax8camera_msm_control(ctrl_pmsm, 0, argp);
		break;
	case MSM_CAM_IOCTL_CTRL_CMD_DONE:
		/* Config thread calls the control thread to notify it
		 * of the result of a MSM_CAM_IOCTL_CTRL_COMMAND.
		 */
		rc = ax8camera_msm_ctrl_cmd_done(ctrl_pmsm, argp);
		break;
	case MSM_CAM_IOCTL_GET_PICTURE:
		rc = ax8camera_msm_get_pic(pmsm->sync, argp);
		break;
	case MSM_CAM_IOCTL_GET_SENSOR_INFO:
		rc = ax8camera_msm_get_sensor_info(pmsm->sync, argp);
		break;
	default:
		rc = ax8camera_msm_ioctl_common(pmsm, cmd, argp);
		break;
	}

	return rc;
}





/*
 * This function executes in interrupt context.
 */

static void ax8camera_msm_vfe_sync(struct msm_vfe_resp *vdata,
		enum msm_queue qtype, void *syncdata,
		gfp_t gfp)
{
	struct msm_queue_cmd *qcmd = NULL;
	struct msm_sync *sync = (struct msm_sync *)syncdata;

	if (!sync) {
		pr_err("%s: no context in dsp callback.\n", __func__);
		return;
	}

	qcmd = ((struct msm_queue_cmd *)vdata) - 1;
	qcmd->type = qtype;
	qcmd->command = vdata;

	if (qtype != MSM_CAM_Q_VFE_MSG)
		goto for_config;

	CDBG("%s: vdata->type %d\n", __func__, vdata->type);
		switch (vdata->type) {
		case VFE_MSG_OUTPUT_P:
		if (sync->pp_mask & PP_PREV) {
			CDBG("%s: PP_PREV in progress: phy_y %x phy_cbcr %x\n",
				__func__,
				vdata->phy.y_phy,
				vdata->phy.cbcr_phy);
			mutex_lock(&pp_prev_lock);
			if (sync->pp_prev)
				pr_warning("%s: overwriting pp_prev!\n",
					__func__);
			pr_info("%s: sending preview to config\n", __func__);
			sync->pp_prev = qcmd;
			mutex_unlock(&pp_prev_lock);
				break;
			}
		CDBG("%s: msm_enqueue frame_q\n", __func__);
		ax8camera_msm_enqueue(&sync->frame_q, &qcmd->list_frame);
		if (qcmd->on_heap)
			qcmd->on_heap++;
		break;

		case VFE_MSG_OUTPUT_V:
		CDBG("%s: msm_enqueue video frame_q\n", __func__);
		ax8camera_msm_enqueue(&sync->frame_q, &qcmd->list_frame);
		if (qcmd->on_heap)
			qcmd->on_heap++;
		break;

		case VFE_MSG_SNAPSHOT:
		if (sync->pp_mask & (PP_SNAP | PP_RAW_SNAP)) {
			CDBG("%s: PP_SNAP in progress: pp_mask %x\n",
				__func__, sync->pp_mask);
			mutex_lock(&pp_snap_lock);
			if (sync->pp_snap)
				pr_warning("%s: overwriting pp_snap!\n",
					__func__);
			pr_info("%s: sending snapshot to config\n", __func__);
			sync->pp_snap = qcmd;
			mutex_unlock(&pp_snap_lock);
				break;
			}

		ax8camera_msm_enqueue(&sync->pict_q, &qcmd->list_pict);
		if (qcmd->on_heap)
			qcmd->on_heap++;
		break;

		case VFE_MSG_STATS_AWB:
		CDBG("%s: qtype %d, AWB stats, enqueue event_q.\n",
		     __func__, vdata->type);
		break;

		case VFE_MSG_STATS_AEC:
		CDBG("%s: qtype %d, AEC stats, enqueue event_q.\n",
		     __func__, vdata->type);
		break;

		case VFE_MSG_STATS_IHIST:
		CDBG("%s: qtype %d, ihist stats, enqueue event_q.\n",
		     __func__, vdata->type);
		break;

		case VFE_MSG_STATS_RS:
		CDBG("%s: qtype %d, rs stats, enqueue event_q.\n",
		     __func__, vdata->type);
		break;

		case VFE_MSG_STATS_CS:
		CDBG("%s: qtype %d, cs stats, enqueue event_q.\n",
		     __func__, vdata->type);
		break;


		case VFE_MSG_GENERAL:
		CDBG("%s: qtype %d, general msg, enqueue event_q.\n",
		    __func__, vdata->type);
		break;
		default:
		CDBG("%s: qtype %d not handled\n", __func__, vdata->type);
		/* fall through, send to config. */
	}

for_config:
	CDBG("%s: msm_enqueue event_q\n", __func__);
	ax8camera_msm_enqueue(&sync->event_q, &qcmd->list_config);
}
