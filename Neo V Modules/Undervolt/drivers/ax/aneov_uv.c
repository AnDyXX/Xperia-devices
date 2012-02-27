/*
 * Author: doixanh <andyx at xda-developers>
 *
 *  This program is free software; you can redistribute  it and/or modify it
 *  under  the terms of  the GNU General  Public License as published by the
 *  Free Software Foundation;  either version 2 of the  License, or (at your
 *  option) any later version.
 *
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/cpu.h>


#define AX_MODULE_NAME 			"aneov_neo"
#define AX_MODULE_VER			"v001"

#define DEVICE_NAME			"Xperia Neo V"

//for 42 and 62 kernels
#define OFS_KALLSYMS_LOOKUP_NAME	0x801056F0			// kallsyms_lookup_name

// for get proc address
typedef unsigned long (*kallsyms_lookup_name_type)(const char *name);
static kallsyms_lookup_name_type kallsyms_lookup_name_ax;

/*********** from acpuclock-7x30.c ****************/
#define VREF_SEL     1	/* 0: 0.625V (50mV step), 1: 0.3125V (25mV step). */
#define V_STEP       (25 * (2 - VREF_SEL)) /* Minimum voltage step size. */
#define VREG_DATA    (VREG_CONFIG | (VREF_SEL << 5))
#define VREG_CONFIG  (BIT(7) | BIT(6)) /* Enable VREG, pull-down if disabled. */
/* Cause a compile error if the voltage is not a multiple of the step size. */
#define MV(mv)      ((mv) / (!((mv) % V_STEP)))
/* mv = (750mV + (raw * 25mV)) * (2 - VREF_SEL) */
#define VDD_RAW(mv) (((MV(mv) / V_STEP) - 30) | VREG_DATA)


struct clkctl_acpu_speed {
	unsigned int	acpu_clk_khz;
	int		src;
	unsigned int	acpu_src_sel;
	unsigned int	acpu_src_div;
	unsigned int	axi_clk_hz;
	unsigned int	vdd_mv;
	unsigned int	vdd_raw;
	unsigned long	lpj; /* loops_per_jiffy */
};

typedef int (*acpuclk_set_acpu_vdd_type)(struct clkctl_acpu_speed *s);
static acpuclk_set_acpu_vdd_type acpuclk_set_acpu_vdd_ax;

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

/***************************/

struct cpu_speed_vs_vdd {
	unsigned int	clk;
	unsigned int	vdd_raw;
};

struct cfg_value_map {
	const char* name;
	const int value;
	const struct cpu_speed_vs_vdd * vdd_profile;
};

static unsigned int lookup_voltage(const struct cpu_speed_vs_vdd *t, unsigned int clk)
{
	while (t->clk) {
		if (t->clk >= clk || t[1].clk == 0) {
			return t->vdd_raw;
		}
		t++;
	}
	return VDD_RAW(1200);
}

static const struct cfg_value_map * lookup_table(const struct cfg_value_map *t, const char* key, const int l)
{
	int len = (l > 0 ? l : strlen(key));

	if (!len)
		return NULL;

	while (t->name) {
		if (!strncmp(t->name, key, len)) {
			return t;
		}
		t++;
	}
	return NULL;
}

//profile modes
enum profile_mode {
	P_STOCK,
	P_25UV,
	P_50UV,
	P_PUV,
	P_PUVX,
	P_UUV
};

static int uv_profile_mode = P_STOCK;
const static struct cpu_speed_vs_vdd * uv_voltage_profile = NULL;

static const struct cfg_value_map cfg_profile_mapping_table[] = {
	{"stock", P_STOCK, NULL},
	{NULL, 0, NULL},
};


static ssize_t show_profile(struct sysdev_class *class, char *buf)
{
	const struct cfg_value_map * val = cfg_profile_mapping_table;
	const struct cfg_value_map * t = cfg_profile_mapping_table;
	
	while (t->name) {
		if (t->value == uv_profile_mode) {
			val = t;
			break;
		}
		t++;
	}

	return sprintf(buf, "%s\n", val->name);
}

static ssize_t __ref store_profile(struct sysdev_class * class, const char * buff, size_t s)
{
	if(buff)
	{
		const struct cfg_value_map * profile = lookup_table(cfg_profile_mapping_table, buff, s);
		if (profile)	
		{
			uv_profile_mode = profile->value;
			uv_voltage_profile = profile->vdd_profile;
			printk(KERN_INFO"%s: Mode switched to: %s \n", __func__, profile->name);	
		}
	}
	
	return 0;
}

static SYSDEV_CLASS_ATTR(profile, 0644, show_profile, store_profile);


static int ax_acpuclk_set_acpu_vdd(struct clkctl_acpu_speed *s)
{
	int vdd = 0;
	if(uv_voltage_profile)
	{
		vdd = lookup_voltage(uv_voltage_profile, s->acpu_clk_khz);
	}
	printk(KERN_INFO"%s: Current %d, to set: %d\n", __func__, s->vdd_raw, vdd); 
	return acpuclk_set_acpu_vdd_ax(s);	
}


// init module
static int __init aneov_uv_init(void)
{
	int retVal = -1;

	printk(KERN_INFO AX_MODULE_NAME ": module " AX_MODULE_VER " for device " DEVICE_NAME " loaded\n");

	// our 'GetProcAddress' :D
	kallsyms_lookup_name_ax = (void*) OFS_KALLSYMS_LOOKUP_NAME;

	acpuclk_set_acpu_vdd_ax = (void*) kallsyms_lookup_name_ax("acpuclk_set_acpu_vdd");

	if (!acpuclk_set_acpu_vdd_ax)
		goto end_of_init;

	if(!sysdev_class_create_file(&cpu_sysdev_class, &attr_profile)){}
//		goto end_of_init;
		
	patch_to_jmp((unsigned int)acpuclk_set_acpu_vdd_ax, &ax_acpuclk_set_acpu_vdd);

	printk(KERN_INFO AX_MODULE_NAME ": Now set profile and enjoy better battery life.\n");
	retVal = 0;

	end_of_init:
	
	return retVal;
}


// exit module - will most likely not be called
static void __exit aneov_uv_exit(void)
{
	printk(KERN_INFO AX_MODULE_NAME ": module unloaded\n");
}

module_init(aneov_uv_init);
module_exit(aneov_uv_exit);

MODULE_DESCRIPTION("Undervoltage module for " DEVICE_NAME);
MODULE_LICENSE("GPL");
