/*
 * Author: AnDyX <andyx at xda-developers>
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


#define AX_MODULE_NAME 			"aneov_uv"
#define AX_MODULE_VER			"v001"

#define DEVICE_NAME			"Xperia Neo V"

//for 42 and 62 kernels
#define OFS_KALLSYMS_LOOKUP_NAME	0x801056F0			// kallsyms_lookup_name

/****************** PATCHING STUFF *********************/

// for get proc address
typedef unsigned long (*kallsyms_lookup_name_type)(const char *name);
static kallsyms_lookup_name_type kallsyms_lookup_name_ax;

//struct for holding patched func
struct patched_func {
	void * original_func_address;
	char original_code[8];
};

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

static unsigned int patch_func(unsigned int addr, void * func, struct patched_func * orig_func)
{
	unsigned int original_value;

	//hold original value
	original_value = *(unsigned int*)addr;

	//store in code
	patch((unsigned int) orig_func->original_code, original_value);
	
	//add jump to original code
	patch_to_jmp(orig_func->original_code[4], (void *)(addr + 4));

	//patch original func
	patch_to_jmp(addr, func);

	return (unsigned int) orig_func->original_code;
}

/******************************************************/

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

static struct patched_func patched_acpuclk_set_acpu_vdd_ax; 

/******************************************************/

static int ax_acpuclk_set_acpu_vdd(struct clkctl_acpu_speed *s)
{
	int vdd = 0;
	printk(KERN_INFO"%s: Current %d, to set: %d\n", __func__, s->vdd_raw, vdd); 
	return acpuclk_set_acpu_vdd_ax(s);	
}

/*****************************************************/
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

	acpuclk_set_acpu_vdd_ax = (void*) patch_func((unsigned int)acpuclk_set_acpu_vdd_ax , ax_acpuclk_set_acpu_vdd, &patched_acpuclk_set_acpu_vdd_ax);

	retVal = 0;

	printk(KERN_INFO AX_MODULE_NAME ": Now set profile and enjoy better battery life.\n");

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
