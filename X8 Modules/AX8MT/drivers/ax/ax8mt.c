/*
 * Author: AnDyX <AnDyX at xda-developers>
 *
 *  This program is free software; you can redistribute  it and/or modify it
 *  under  the terms of  the GNU General  Public License as published by the
 *  Free Software Foundation;  either version 2 of the  License, or (at your
 *  option) any later version.
 *
 */

#include <linux/delay.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/input.h>
#include <linux/slab.h>
#include <linux/gpio.h>
#include <linux/irq.h>
#include <linux/interrupt.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <linux/byteorder/generic.h>
#include <linux/bitops.h>
#include <linux/earlysuspend.h>
#include <linux/cyttsp.h>
#include <linux/ctype.h>
#include <linux/i2c.h>
#include "cyttsp_core.h"

#define AX_MODULE_NAME 			"ax8mt"
#define AX_MODULE_VER			"v005"

#ifndef DBG
#define DBG(x)
#endif

#ifndef DBG2 
#define DBG2(x)   
#endif

#define DEVICE_NAME				"X8"
#define OFS_KALLSYMS_LOOKUP_NAME	0xC00B0654			// kallsyms_lookup_name

// for get proc address
typedef unsigned long (*kallsyms_lookup_name_type)(const char *name);
static kallsyms_lookup_name_type kallsyms_lookup_name_ax;

static void patch(unsigned int addr, unsigned int value) {
	*(unsigned int*)addr = value;
}

// patch to an jump obcode
static void patch_to_jmp(unsigned int addr, void * func) {
	int write_value;
	// calculate the offset
	write_value = ((((unsigned int)func - 8 - addr) >> 2) & 0x00FFFFFF);
	// add the unconditional jump opcode
	write_value |= 0xEA000000;
	// and patch it
	patch(addr, write_value);
}

struct cfg_value_map {
	const char* name;
	int value;
};

static int lookup_table(const struct cfg_value_map *t, const char* key)
{
	int len = strlen(key);

	if (!len)
		return -EINVAL;
	if (isspace(key[len-1]))
		--len;
	while (t->name) {
		if (!strncmp(t->name, key, len)) {
			DBG(printk(KERN_DEBUG "%s: %s -> %d\n",
					   __func__, t->name, t->value);)
			return t->value;
		}
		t++;
	}
	return -EINVAL;
}

/************** Cypress defs **************************/

/* maximum number of concurrent ST track IDs */
#define CY_NUM_ST_TCH_ID            2
/* maximum number of concurrent MT track IDs */
#define CY_NUM_MT_TCH_ID            4
/* maximum number of track IDs */
#define CY_NUM_TRK_ID               16

#define CY_NTCH                     0 /* lift off */
#define CY_TCH                      1 /* touch down */
#define CY_ST_FNGR1_IDX             0
#define CY_ST_FNGR2_IDX             1
#define CY_MT_TCH1_IDX              0
#define CY_MT_TCH2_IDX              1
#define CY_MT_TCH3_IDX              2
#define CY_MT_TCH4_IDX              3
#define CY_XPOS                     0
#define CY_YPOS                     1
#define CY_IGNR_TCH               (-1)
#define CY_SMALL_TOOL_WIDTH         10
#define CY_LARGE_TOOL_WIDTH         255
#define CY_MAXZ                     255

/************** Cypress structs **************************/
/* TrueTouch Standard Product Gen3 (Txx3xx) interface definition */
struct cyttsp_xydata {
	u8 hst_mode;
	u8 tt_mode;
	u8 tt_stat;
	u16 x1 __attribute__ ((packed));
	u16 y1 __attribute__ ((packed));
	u8 z1;
	u8 touch12_id;
	u16 x2 __attribute__ ((packed));
	u16 y2 __attribute__ ((packed));
	u8 z2;
	u8 gest_cnt;
	u8 gest_id;
	u16 x3 __attribute__ ((packed));
	u16 y3 __attribute__ ((packed));
	u8 z3;
	u8 touch34_id;
	u16 x4 __attribute__ ((packed));
	u16 y4 __attribute__ ((packed));
	u8 z4;
	u8 tt_undef[3];
	u8 gest_set;
	u8 tt_reserved;
};

/* TTSP System Information interface definition */
struct cyttsp_sysinfo_data {
	u8 hst_mode;
	u8 mfg_stat;
	u8 mfg_cmd;
	u8 cid[3];
	u8 tt_undef1;
	u8 uid[8];
	u8 bl_verh;
	u8 bl_verl;
	u8 tts_verh;
	u8 tts_verl;
	u8 app_idh;
	u8 app_idl;
	u8 app_verh;
	u8 app_verl;
	u8 tt_undef[6];
	u8 act_intrvl;
	u8 tch_tmout;
	u8 lp_intrvl;
};

/* TTSP Bootloader Register Map interface definition */
#define CY_BL_CHKSUM_OK 0x01
struct cyttsp_bootloader_data {
	u8 bl_file;
	u8 bl_status;
	u8 bl_error;
	u8 blver_hi;
	u8 blver_lo;
	u8 bld_blver_hi;
	u8 bld_blver_lo;
	u8 ttspver_hi;
	u8 ttspver_lo;
	u8 appid_hi;
	u8 appid_lo;
	u8 appver_hi;
	u8 appver_lo;
	u8 cid_0;
	u8 cid_1;
	u8 cid_2;
};

struct cyttsp {
	struct device *pdev;
	int irq;
	struct input_dev *input;
	struct work_struct work;
	struct timer_list timer;
	struct mutex mutex;
	struct early_suspend early_suspend;
	char phys[32];
	struct cyttsp_platform_data *platform_data;
	struct cyttsp_bootloader_data bl_data;
	struct cyttsp_sysinfo_data sysinfo_data;
	u8 num_prv_st_tch;
	u16 act_trk[CY_NUM_TRK_ID];
	u16 prv_mt_tch[CY_NUM_MT_TCH_ID];
	u16 prv_st_tch[CY_NUM_ST_TCH_ID];
	u16 prv_mt_pos[CY_NUM_TRK_ID][2];
	struct cyttsp_bus_ops *bus_ops;
	unsigned fw_loader_mode:1;
	unsigned suspended:1;
};


struct cyttsp_track_data {
	u8 prv_tch;
	u8 cur_tch;
	u16 tmp_trk[CY_NUM_MT_TCH_ID];
	u16 snd_trk[CY_NUM_MT_TCH_ID];
	u16 cur_trk[CY_NUM_TRK_ID];
	u16 cur_st_tch[CY_NUM_ST_TCH_ID];
	u16 cur_mt_tch[CY_NUM_MT_TCH_ID];
	/* if NOT CY_USE_TRACKING_ID then only */
	/* uses CY_NUM_MT_TCH_ID positions */
	u16 cur_mt_pos[CY_NUM_TRK_ID][2];
	/* if NOT CY_USE_TRACKING_ID then only */
	/* uses CY_NUM_MT_TCH_ID positions */
	u8 cur_mt_z[CY_NUM_TRK_ID];
	u8 tool_width;
	u16 st_x1;
	u16 st_y1;
	u8 st_z1;
	u16 st_x2;
	u16 st_y2;
	u8 st_z2;
};

struct cyttsp_i2c {
	struct cyttsp_bus_ops ops;
	struct i2c_client *client;
	void *ttsp_client;
};

/*********************************************************/
enum cyttsp_mode {
	CYTTSP_NORMAL,
	CYTTSP_NORMAL_TID,
	CYTTSP_ANDYX,
	CYTTSP_DESIRE
};

static int cyttsp_driver_mode = CYTTSP_ANDYX;

static const struct cfg_value_map cfg_mode_mapping_table[] = {
	{"original", CYTTSP_NORMAL},
	{"original_tid", CYTTSP_NORMAL_TID},
	{"andyx", CYTTSP_ANDYX},
	{"desire", CYTTSP_DESIRE},
	{NULL, 0},
};

static int ax8mt_cyttsp_inlist(u16 prev_track[], u8 cur_trk_id, u8 *prev_loc,
	u8 num_touches)
{
	u8 id = 0;

	DBG(printk(KERN_INFO"%s: IN p[%d]=%d c=%d n=%d loc=%d\n",
		__func__, id, prev_track[id], cur_trk_id,
		num_touches, *prev_loc);)

	for (*prev_loc = CY_IGNR_TCH; id < num_touches; id++) {
		DBG(printk(KERN_INFO"%s: p[%d]=%d c=%d n=%d loc=%d\n",
			__func__, id, prev_track[id], cur_trk_id,
				num_touches, *prev_loc);)
		if (prev_track[id] == cur_trk_id) {
			*prev_loc = id;
			break;
		}
	}
	DBG(printk(KERN_INFO"%s: OUT p[%d]=%d c=%d n=%d loc=%d\n", __func__,
		id, prev_track[id], cur_trk_id, num_touches, *prev_loc);)

	return *prev_loc < CY_NUM_TRK_ID;
}

static int ax8mt_cyttsp_next_avail_inlist(u16 cur_trk[], u8 *new_loc,
	u8 num_touches)
{
	u8 id = 0;
	DBG(printk(KERN_INFO"%s: Enter\n", __func__);)

	for (*new_loc = CY_IGNR_TCH; id < num_touches; id++) {
		if (cur_trk[id] > CY_NUM_TRK_ID) {
			*new_loc = id;
			break;
		}
	}
	return *new_loc < CY_NUM_TRK_ID;
}

static int ax8mt_cyttsp_setup_input_dev(struct cyttsp *ts)
{
	struct input_dev *input_device;
	/* Create the input device and register it. */
	input_device = input_allocate_device();
	if (!input_device) {
		dev_err(ts->pdev, "%s: Failed to allocate input device\n",
			__func__);
		return -ENODEV;
	}

	input_device->name = ts->platform_data->name;
	input_device->phys = ts->phys;
	input_device->dev.parent = ts->pdev;
	memset(ts->act_trk, CY_NTCH, sizeof(ts->act_trk));
	memset(ts->prv_mt_pos, CY_NTCH, sizeof(ts->prv_mt_pos));
	memset(ts->prv_mt_tch, CY_IGNR_TCH, sizeof(ts->prv_mt_tch));
	memset(ts->prv_st_tch, CY_IGNR_TCH, sizeof(ts->prv_st_tch));

	set_bit(EV_SYN, input_device->evbit);
	set_bit(EV_KEY, input_device->evbit);
	set_bit(EV_ABS, input_device->evbit);
	set_bit(BTN_TOUCH, input_device->keybit);
	set_bit(BTN_2, input_device->keybit);
	if (ts->platform_data->use_gestures)
		set_bit(BTN_3, input_device->keybit);

	input_set_abs_params(input_device, ABS_X, 0, ts->platform_data->maxx,
			     0, 0);
	input_set_abs_params(input_device, ABS_Y, 0, ts->platform_data->maxy,
			     0, 0);
	input_set_abs_params(input_device, ABS_TOOL_WIDTH, 0,
			     CY_LARGE_TOOL_WIDTH, 0, 0);
	input_set_abs_params(input_device, ABS_PRESSURE, 0, CY_MAXZ, 0, 0);
	input_set_abs_params(input_device, ABS_HAT0X, 0,
			     ts->platform_data->maxx, 0, 0);
	input_set_abs_params(input_device, ABS_HAT0Y, 0,
			     ts->platform_data->maxy, 0, 0);
	if (ts->platform_data->use_gestures) {
		input_set_abs_params(input_device, ABS_HAT1X, 0, CY_MAXZ,
				     0, 0);
		input_set_abs_params(input_device, ABS_HAT1Y, 0, CY_MAXZ,
				     0, 0);
	}
	if (ts->platform_data->use_mt) {
		input_set_abs_params(input_device, ABS_MT_POSITION_X, 0,
				     ts->platform_data->maxx, 0, 0);
		input_set_abs_params(input_device, ABS_MT_POSITION_Y, 0,
				     ts->platform_data->maxy, 0, 0);
		input_set_abs_params(input_device, ABS_MT_TOUCH_MAJOR, 0,
				     CY_MAXZ, 0, 0);
		input_set_abs_params(input_device, ABS_MT_WIDTH_MAJOR, 0,
				     CY_LARGE_TOOL_WIDTH, 0, 0);
		if (ts->platform_data->use_trk_id)
			input_set_abs_params(input_device, ABS_MT_TRACKING_ID,
					0, CY_NUM_TRK_ID, 0, 0);
	}

	if (ts->platform_data->use_virtual_keys)
		input_set_capability(input_device, EV_KEY, KEY_PROG1);

	if (input_register_device(input_device)) {
		dev_err(ts->pdev, "%s: Failed to register input device\n",
			__func__);
		input_free_device(input_device);
		return -ENODEV;
	}
	ts->input = input_device;
	dev_info(ts->pdev, "%s: Registered input device %s\n",
		   __func__, input_device->name);
	return 0;
}

#define IS_VALID_TRACK(x) ((x) != CY_IGNR_TCH && (x) < CY_NUM_TRK_ID)

void ax8mt_send_out_events_desire(struct cyttsp * ts)
{
	int valid1 = IS_VALID_TRACK(ts->prv_mt_tch[0]);
	int valid2 = IS_VALID_TRACK(ts->prv_mt_tch[1]);

	input_report_abs(ts->input, BTN_TOUCH, valid1 );
	input_report_abs(ts->input, BTN_2, valid2 );

	input_report_abs(ts->input, ABS_MT_TOUCH_MAJOR,
			valid1 ? ts->act_trk[0]/2 : CY_NTCH);

	input_report_abs(ts->input, ABS_MT_POSITION_X,
				ts->prv_mt_pos[0][CY_XPOS]);
	input_report_abs(ts->input, ABS_MT_POSITION_Y,
				ts->prv_mt_pos[0][CY_YPOS]);

	input_mt_sync(ts->input);

	if(valid2)
	{
		input_report_abs(ts->input, ABS_MT_POSITION_X,
				ts->prv_mt_pos[1][CY_XPOS]);
		input_report_abs(ts->input, ABS_MT_POSITION_Y,
				ts->prv_mt_pos[1][CY_YPOS]);
		input_report_abs(ts->input, ABS_MT_TOUCH_MAJOR,
			 ts->act_trk[1]/2);
		
		input_mt_sync(ts->input);
	}
}

void ax8mt_send_out_events_andyx(struct cyttsp * ts)
{
	if( IS_VALID_TRACK(ts->prv_mt_tch[0]) )
	{
		input_report_abs(ts->input, ABS_MT_TRACKING_ID, 0);

		input_report_abs(ts->input, ABS_MT_POSITION_X,
				ts->prv_mt_pos[0][CY_XPOS]);
		input_report_abs(ts->input, ABS_MT_POSITION_Y,
				ts->prv_mt_pos[0][CY_YPOS]);
		input_report_abs(ts->input, ABS_MT_TOUCH_MAJOR,
			ts->act_trk[0]/2 );

		input_report_abs(ts->input, BTN_TOUCH, 1 );
		input_report_abs(ts->input, BTN_2, 1 );

		input_mt_sync(ts->input);

		DBG2(printk(KERN_INFO"%s: MT1 -> TID:"
				"%3d X:%3d  Y:%3d  Z:%3d\n", __func__,
				ts->prv_mt_tch[0],
				ts->prv_mt_pos[0][CY_XPOS],
				ts->prv_mt_pos[0][CY_YPOS],
				ts->act_trk[0]);)

	}
	
	if( IS_VALID_TRACK(ts->prv_mt_tch[1]) )
	{
		input_report_abs(ts->input, ABS_MT_TRACKING_ID, 1);

		input_report_abs(ts->input, ABS_MT_POSITION_X,
				ts->prv_mt_pos[1][CY_XPOS]);
		input_report_abs(ts->input, ABS_MT_POSITION_Y,
				ts->prv_mt_pos[1][CY_YPOS]);
		input_report_abs(ts->input, ABS_MT_TOUCH_MAJOR,
			ts->act_trk[1]/2);
		
		input_mt_sync(ts->input);

		DBG2(printk(KERN_INFO"%s: MT2 -> TID:"
				"%3d X:%3d  Y:%3d  Z:%3d\n", __func__,
				ts->prv_mt_tch[1],
				ts->prv_mt_pos[1][CY_XPOS],
				ts->prv_mt_pos[1][CY_YPOS],
				ts->act_trk[1]);)
	}

	if( !IS_VALID_TRACK(ts->prv_mt_tch[0]) && !IS_VALID_TRACK(ts->prv_mt_tch[1]) )
	{
		input_mt_sync(ts->input);
		DBG2(printk(KERN_INFO"%s: MT3 -> no event\n", __func__	);)
	}
}

void ax8mt_handle_multi_touch_andyx(struct cyttsp_track_data *t, struct cyttsp *ts)
{
	int level = 0;

	//clean out previuos touches
	if(t->prv_tch > 0 && t->cur_tch > 0 )
	{
		switch(t->prv_tch)
		{	
			case 2:
				if(     IS_VALID_TRACK(ts->prv_mt_tch[1]) &&
					ts->prv_mt_tch[1] != t->cur_mt_tch[0] && 
					ts->prv_mt_tch[1] != t->cur_mt_tch[1] )
				{
					ts->prv_mt_tch[1] = CY_IGNR_TCH;
				}
			case 1:
				if(	IS_VALID_TRACK(ts->prv_mt_tch[0]) && 
					ts->prv_mt_tch[0] != t->cur_mt_tch[0] && 
					ts->prv_mt_tch[0] != t->cur_mt_tch[1])
				{
					ts->prv_mt_tch[0] = CY_IGNR_TCH;
				}
			break;
			case 0:
			ts->prv_mt_tch[1] = CY_IGNR_TCH;
			ts->prv_mt_tch[0] = CY_IGNR_TCH;
			break;
		}
	}

	// add new touches
	switch(t->cur_tch)
	{
		case 2:
			level = (ts->prv_mt_tch[0] == t->cur_mt_tch[1]) ? 0 : 
				(ts->prv_mt_tch[1] == t->cur_mt_tch[1]) ? 1 : 
				! IS_VALID_TRACK(ts->prv_mt_tch[0]) ?  0 : 1;

			ts->act_trk[level] = t->cur_mt_z[1];
			ts->prv_mt_pos[level][CY_XPOS] = t->cur_mt_pos[1][CY_XPOS];
			ts->prv_mt_pos[level][CY_YPOS] = t->cur_mt_pos[1][CY_YPOS];
			ts->prv_mt_tch[level] = t->cur_mt_tch[1];
		case 1:
			level = (ts->prv_mt_tch[0] == t->cur_mt_tch[0]) ? 0 : 
				(ts->prv_mt_tch[1] == t->cur_mt_tch[0]) ? 1 : 
				! IS_VALID_TRACK(ts->prv_mt_tch[0]) ?  0 : 1;

			ts->act_trk[level] = t->cur_mt_z[0];
			ts->prv_mt_pos[level][CY_XPOS] = t->cur_mt_pos[0][CY_XPOS];
			ts->prv_mt_pos[level][CY_YPOS] = t->cur_mt_pos[0][CY_YPOS];
			ts->prv_mt_tch[level] = t->cur_mt_tch[0];
		break;
		case 0:
			ts->prv_mt_tch[0] = CY_IGNR_TCH;
			ts->prv_mt_tch[1] = CY_IGNR_TCH;
		break;
	}

	if(cyttsp_driver_mode == CYTTSP_ANDYX)
		ax8mt_send_out_events_andyx(ts);
	else
		ax8mt_send_out_events_desire(ts);
}

void ax8mt_handle_multi_touch_original(struct cyttsp_track_data *t, struct cyttsp *ts)
{

	u8 id;
	u8 i, loc;
	void (*mt_sync_func)(struct input_dev *) = ts->platform_data->mt_sync;

	if (!ts->platform_data->use_trk_id)
		goto no_track_id;

	/* terminate any previous touch where the track
	 * is missing from the current event */
	for (id = 0; id < CY_NUM_TRK_ID; id++) {
		if ((ts->act_trk[id] == CY_NTCH) || (t->cur_trk[id] != CY_NTCH))
			continue;

		input_report_abs(ts->input, ABS_MT_TRACKING_ID, id);
		input_report_abs(ts->input, ABS_MT_TOUCH_MAJOR, CY_NTCH);
		input_report_abs(ts->input, ABS_MT_WIDTH_MAJOR, t->tool_width);
		input_report_abs(ts->input, ABS_MT_POSITION_X,
					ts->prv_mt_pos[id][CY_XPOS]);
		input_report_abs(ts->input, ABS_MT_POSITION_Y,
					ts->prv_mt_pos[id][CY_YPOS]);
		if (mt_sync_func)
			mt_sync_func(ts->input);
		ts->act_trk[id] = CY_NTCH;
		ts->prv_mt_pos[id][CY_XPOS] = 0;
		ts->prv_mt_pos[id][CY_YPOS] = 0;
	}
	/* set Multi-Touch current event signals */
	for (id = 0; id < CY_NUM_MT_TCH_ID; id++) {
		if (t->cur_mt_tch[id] >= CY_NUM_TRK_ID)
			continue;

		input_report_abs(ts->input, ABS_MT_TRACKING_ID,
						t->cur_mt_tch[id]);
		input_report_abs(ts->input, ABS_MT_TOUCH_MAJOR,
						t->cur_mt_z[id]);
		input_report_abs(ts->input, ABS_MT_WIDTH_MAJOR,
						t->tool_width);
		input_report_abs(ts->input, ABS_MT_POSITION_X,
						t->cur_mt_pos[id][CY_XPOS]);
		input_report_abs(ts->input, ABS_MT_POSITION_Y,
						t->cur_mt_pos[id][CY_YPOS]);
		if (mt_sync_func)
			mt_sync_func(ts->input);

		ts->act_trk[id] = CY_TCH;
		ts->prv_mt_pos[id][CY_XPOS] = t->cur_mt_pos[id][CY_XPOS];
		ts->prv_mt_pos[id][CY_YPOS] = t->cur_mt_pos[id][CY_YPOS];
	}
	return;
no_track_id:

	/* set temporary track array elements to voids */
	memset(t->tmp_trk, CY_IGNR_TCH, sizeof(t->tmp_trk));
	memset(t->snd_trk, CY_IGNR_TCH, sizeof(t->snd_trk));

	/* get what is currently active */
	for (i = id = 0; id < CY_NUM_TRK_ID && i < CY_NUM_MT_TCH_ID; id++) {
		if (t->cur_trk[id] == CY_TCH) {
			/* only incr counter if track found */
			t->tmp_trk[i] = id;
			i++;
		}
	}
	DBG(printk(KERN_INFO"%s: T1: t0=%d, t1=%d, t2=%d, t3=%d\n", __func__,
					t->tmp_trk[0], t->tmp_trk[1],
					t->tmp_trk[2], t->tmp_trk[3]);)
	DBG(printk(KERN_INFO"%s: T1: p0=%d, p1=%d, p2=%d, p3=%d\n", __func__,
					ts->prv_mt_tch[0], ts->prv_mt_tch[1],
					ts->prv_mt_tch[2], ts->prv_mt_tch[3]);)

	/* pack in still active previous touches */
	for (id = t->prv_tch = 0; id < CY_NUM_MT_TCH_ID; id++) {
		if (t->tmp_trk[id] >= CY_NUM_TRK_ID)
			continue;

		if (ax8mt_cyttsp_inlist(ts->prv_mt_tch, t->tmp_trk[id], &loc,
							CY_NUM_MT_TCH_ID)) {
			loc &= CY_NUM_MT_TCH_ID - 1;
			t->snd_trk[loc] = t->tmp_trk[id];
			t->prv_tch++;
			DBG(printk(KERN_INFO"%s: in list s[%d]=%d "
					"t[%d]=%d, loc=%d p=%d\n", __func__,
					loc, t->snd_trk[loc],
					id, t->tmp_trk[id],
					loc, t->prv_tch);)
		} else {
			DBG(printk(KERN_INFO"%s: is not in list s[%d]=%d"
					" t[%d]=%d loc=%d\n", __func__,
					id, t->snd_trk[id],
					id, t->tmp_trk[id],
					loc);)
		}
	}
	DBG(printk(KERN_INFO"%s: S1: s0=%d, s1=%d, s2=%d, s3=%d p=%d\n",
		   __func__,
		   t->snd_trk[0], t->snd_trk[1], t->snd_trk[2],
		   t->snd_trk[3], t->prv_tch);)

	/* pack in new touches */
	for (id = 0; id < CY_NUM_MT_TCH_ID; id++) {
		if (t->tmp_trk[id] >= CY_NUM_TRK_ID)
			continue;

		if (!ax8mt_cyttsp_inlist(t->snd_trk, t->tmp_trk[id], &loc,
							CY_NUM_MT_TCH_ID)) {

			DBG(
			printk(KERN_INFO"%s: not in list t[%d]=%d, loc=%d\n",
				   __func__,
				   id, t->tmp_trk[id], loc);)

			if (ax8mt_cyttsp_next_avail_inlist(t->snd_trk, &loc,
							CY_NUM_MT_TCH_ID)) {
				loc &= CY_NUM_MT_TCH_ID - 1;
				t->snd_trk[loc] = t->tmp_trk[id];
				DBG(printk(KERN_INFO "%s: put in list s[%d]=%d"
					" t[%d]=%d\n", __func__,
					loc,
					t->snd_trk[loc], id, t->tmp_trk[id]);
				    )
			}
		} else {
			DBG(printk(KERN_INFO"%s: is in list s[%d]=%d "
				"t[%d]=%d loc=%d\n", __func__,
				id, t->snd_trk[id], id, t->tmp_trk[id], loc);)
		}
	}
	DBG(printk(KERN_INFO"%s: S2: s0=%d, s1=%d, s2=%d, s3=%d\n", __func__,
			t->snd_trk[0], t->snd_trk[1],
			t->snd_trk[2], t->snd_trk[3]);)

	/* sync motion event signals for each current touch */
	for (id = 0; id < CY_NUM_MT_TCH_ID; id++) {
		/* z will either be 0 (NOTOUCH) or
		 * some pressure (TOUCH)
		 */
		DBG(printk(KERN_INFO "%s: MT0 prev[%d]=%d "
				"temp[%d]=%d send[%d]=%d\n",
				__func__, id, ts->prv_mt_tch[id],
				id, t->tmp_trk[id], id, t->snd_trk[id]);)

		if (t->snd_trk[id] < CY_NUM_TRK_ID) {
			input_report_abs(ts->input, ABS_MT_TOUCH_MAJOR,
					t->cur_mt_z[t->snd_trk[id]]);
			input_report_abs(ts->input, ABS_MT_WIDTH_MAJOR,
					t->tool_width);
			input_report_abs(ts->input, ABS_MT_POSITION_X,
					t->cur_mt_pos[t->snd_trk[id]][CY_XPOS]);
			input_report_abs(ts->input, ABS_MT_POSITION_Y,
					t->cur_mt_pos[t->snd_trk[id]][CY_YPOS]);
			if (mt_sync_func)
				mt_sync_func(ts->input);

			DBG(printk(KERN_INFO"%s: MT1 -> TID:"
				"%3d X:%3d  Y:%3d  Z:%3d\n", __func__,
				t->snd_trk[id],
				t->cur_mt_pos[t->snd_trk[id]][CY_XPOS],
				t->cur_mt_pos[t->snd_trk[id]][CY_YPOS],
				t->cur_mt_z[t->snd_trk[id]]);)

		} else if (ts->prv_mt_tch[id] < CY_NUM_TRK_ID) {
			/* void out this touch */
			input_report_abs(ts->input, ABS_MT_TOUCH_MAJOR,
							CY_NTCH);
			input_report_abs(ts->input, ABS_MT_WIDTH_MAJOR,
							t->tool_width);
			input_report_abs(ts->input, ABS_MT_POSITION_X,
				ts->prv_mt_pos[ts->prv_mt_tch[id]][CY_XPOS]);
			input_report_abs(ts->input, ABS_MT_POSITION_Y,
				ts->prv_mt_pos[ts->prv_mt_tch[id]][CY_YPOS]);

			if (mt_sync_func)
				mt_sync_func(ts->input);

			DBG(printk(KERN_INFO"%s: "
				"MT2->TID:%2d X:%3d Y:%3d Z:%3d liftoff-sent\n",
				__func__, ts->prv_mt_tch[id],
				ts->prv_mt_pos[ts->prv_mt_tch[id]][CY_XPOS],
				ts->prv_mt_pos[ts->prv_mt_tch[id]][CY_YPOS],
				CY_NTCH);)
		} else {
			/* do not stuff any signals for this
			 * previously and currently void touches
			 */
			DBG(printk(KERN_INFO"%s: "
				"MT3->send[%d]=%d - No touch - NOT sent\n",
				__func__, id, t->snd_trk[id]);)
		}
	}

	/* save current posted tracks to
	 * previous track memory */
	for (id = 0; id < CY_NUM_MT_TCH_ID; id++) {
		ts->prv_mt_tch[id] = t->snd_trk[id];
		if (t->snd_trk[id] < CY_NUM_TRK_ID) {
			ts->prv_mt_pos[t->snd_trk[id]][CY_XPOS] =
					t->cur_mt_pos[t->snd_trk[id]][CY_XPOS];
			ts->prv_mt_pos[t->snd_trk[id]][CY_YPOS] =
					t->cur_mt_pos[t->snd_trk[id]][CY_YPOS];
			DBG(printk(KERN_INFO"%s: "
				"MT4->TID:%2d X:%3d Y:%3d Z:%3d save for prv\n",
				__func__, t->snd_trk[id],
				ts->prv_mt_pos[t->snd_trk[id]][CY_XPOS],
				ts->prv_mt_pos[t->snd_trk[id]][CY_YPOS],
				CY_NTCH);)
		}
	}
	memset(ts->act_trk, CY_NTCH, sizeof(ts->act_trk));
	for (id = 0; id < CY_NUM_MT_TCH_ID; id++) {
		if (t->snd_trk[id] < CY_NUM_TRK_ID)
			ts->act_trk[t->snd_trk[id]] = CY_TCH;
	}
}

void ax8mt_handle_multi_touch(struct cyttsp_track_data *t, struct cyttsp *ts)
{
	switch(cyttsp_driver_mode)
	{
		case CYTTSP_ANDYX:
		case CYTTSP_DESIRE:
		ax8mt_handle_multi_touch_andyx(t, ts);		
		break;
		default:
		ax8mt_handle_multi_touch_original(t, ts);		
	}
}

static ssize_t attr_driver_mode(struct device *dev,
				   struct device_attribute *attr,
				   const char *buf, size_t size)
{
	struct cyttsp *ts;
	struct i2c_client * client;

	int mode = lookup_table(cfg_mode_mapping_table, buf);
	if (mode != -EINVAL)
	{
		client = to_i2c_client(dev);
		if( client == NULL )
			goto end_of_func;

		ts = i2c_get_clientdata(client);
		if( ts == NULL || ts->platform_data == NULL)
			goto end_of_func;
		
		switch(mode)
		{
			case CYTTSP_NORMAL:
			ts->platform_data->use_trk_id = 0;
			cyttsp_driver_mode = mode;
			break;
			case CYTTSP_NORMAL_TID:
			ts->platform_data->use_trk_id = 1;
			cyttsp_driver_mode = mode;
			break;
			case CYTTSP_ANDYX:
			ts->platform_data->use_trk_id = 1;
			cyttsp_driver_mode = mode;
			break;
			case CYTTSP_DESIRE:
			ts->platform_data->use_trk_id = 1;
			cyttsp_driver_mode = mode;
			break;
			default:
				goto end_of_func;
		}
		
		printk(KERN_INFO"%s: Mode switched to: %s \n", __func__, buf);
		
	}

end_of_func:

	return strlen(buf);
}

static struct device_attribute attributes[] = {
	__ATTR(mode, 0200, NULL, attr_driver_mode),
};

static int ax8mt_create_sysfs_interfaces(struct device *dev)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(attributes); i++)
		if (device_create_file(dev, attributes + i))
			goto error;
	return 0;
error:
	for (; i >=0; i--)
		device_remove_file(dev, attributes + i);
	printk(KERN_ERR "%s: %s Unable to create interface\n",
	       CY_I2C_NAME, __func__);
	return -1;
}

// our cypress device matcher
int ax8mt_cyttsp_device_match(struct device * dev, void* data)
{
	if (dev->driver && dev->driver->name && strcmp(dev->driver->name,CY_I2C_NAME) == 0 )
	{
		return 1;
	}
	return 0;
}


/********* Module methods *************/
// init module
static int __init ax8mt_init(void)
{
	int retVal = -1;
	struct device *cyttsp_device = NULL;
	struct i2c_client * client;
	struct cyttsp *ts;
	unsigned long handle_multi_touch_ax;

	cyttsp_device = bus_find_device(&i2c_bus_type, NULL, NULL, &ax8mt_cyttsp_device_match);

	if( cyttsp_device == NULL )
		goto end_of_init;

	client = to_i2c_client(cyttsp_device);
	if( client == NULL )
		goto end_of_init;

	ts = i2c_get_clientdata(client);
	if( ts == NULL || ts->input == NULL)
		goto end_of_init;

	printk(KERN_INFO AX_MODULE_NAME ": module " AX_MODULE_VER " loaded\n");

	DBG(printk(KERN_INFO"%s: Unregister old input device\n", __func__);)
	input_unregister_device(ts->input);
	
	DBG(printk(KERN_INFO"%s: Freeing old input device\n", __func__);)
	input_free_device(ts->input);
	
	ts->platform_data->use_st = 0;
	ts->platform_data->use_mt = 1;
	ts->platform_data->use_trk_id = 1;

	DBG(printk(KERN_INFO"%s: Register new input device\n", __func__);)
	ax8mt_cyttsp_setup_input_dev(ts);

	printk(KERN_INFO AX_MODULE_NAME ": Enjoy dual touch now :)\n");
	retVal = 0;

	ax8mt_create_sysfs_interfaces(cyttsp_device);

	printk(KERN_INFO"%s: Mode set to: andyx \n", __func__);

	// our 'GetProcAddress' :D
	kallsyms_lookup_name_ax = (void*) OFS_KALLSYMS_LOOKUP_NAME;
	handle_multi_touch_ax = kallsyms_lookup_name_ax("handle_multi_touch");

	if(handle_multi_touch_ax)
	{
		DBG(printk(KERN_INFO"%s: Patched\n", __func__);)
		patch_to_jmp(handle_multi_touch_ax, &ax8mt_handle_multi_touch);
	}

	end_of_init:

	return retVal;
}


module_init(ax8mt_init);

MODULE_DESCRIPTION("Multitouch enabler for Cypress module for X8");
MODULE_LICENSE("GPL");


