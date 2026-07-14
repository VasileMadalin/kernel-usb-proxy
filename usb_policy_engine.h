// SPDX-License-Identifier: GPL-2.0
/*
 * USB Policy Engine
 *
 * Public kernel interface for the USB policy engine.
 * Declares the functions required for descriptor analysis
 * and policy enforcement.
 *
 * Copyright (c) 2026 Madalin Vasile
 * Author: Madalin Vasile
 */

#ifndef USB_PROXY_POLICY_H
#define USB_PROXY_POLICY_H

#include <linux/usb.h>
#include <linux/device.h>

int usb_proxy_check_policy(struct usb_device *udev, struct device *dev);
int usb_proxy_policy_init(void);
void usb_proxy_policy_exit(void);

#endif