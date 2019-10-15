/*
 * Author: Nandhakumar Rangasamy <nandhakumar.x.rangasamy@sonymobile.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 */
/*
 * Copyright (C) 2017 Sony Mobile Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/of_platform.h>
#include <linux/debugfs.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <asm/setup.h>
#include <soc/qcom/security_status.h>
#include <soc/qcom/scm.h>

#define SECURITY_ENABLED 0x2

static int security_status = -1;

static int __init security_config_setup(char *p)
{
	unsigned long res;

	if (!p || !*p)
		return -EINVAL;

	if (!kstrtoul(p, 0, &res)) {
		if (res & SECURITY_ENABLED)
			security_status = SECURITY_ON;
		else
			security_status = SECURITY_OFF;
	}

	pr_info("system booted with SECURITY_STATUS : %s\n",
		security_status ? "ON" : "OFF");
	return 0;
}
early_param("oemandroidboot.securityflags", security_config_setup);

int get_security_status(int *status)
{
	if (security_status == -1)
		return -EINVAL;
	else {
		*status = security_status;
		return 0;
	}
}

static ssize_t sec_status_read(struct file *file, char __user *buf,
						size_t len, loff_t *offp)
{
	bool status;
	int ret;
	char status_buf[3];

	if (*offp > 0) {
		return 0;
	}
	status = scm_is_secure_device();
	ret = snprintf(status_buf, sizeof(status_buf), "%d\n", !status);

	return simple_read_from_buffer(buf, len, offp, status_buf, ret);
}

static const struct file_operations sec_status_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = sec_status_read,
};

static int __init sec_status_init(void)
{
	struct dentry *sec_status;

	sec_status = debugfs_create_file("security_status", 0664, NULL, NULL,
							&sec_status_fops);
	if (sec_status == NULL) {
		pr_err("error creating 'security_status' debug node\n");
		return -ENOMEM;
	}
	return 0;
}
module_init(sec_status_init);
MODULE_DESCRIPTION("device sec_status read module");
MODULE_LICENSE("GPL v2");
