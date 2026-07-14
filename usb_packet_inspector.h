// SPDX-License-Identifier: GPL-2.0
/*
 * USB Packet Inspector
 *
 * Public kernel interface for the USB packet inspection module.
 * Declares the functions used to inspect and filter USB packets
 * exchanged through the kernel-level USB proxy.
 *
 * Copyright (c) 2026 Madalin Vasile
 * Author: Madalin Vasile
 */

#ifndef USB_PACKET_INSPECTOR_H
#define USB_PACKET_INSPECTOR_H

#include <linux/types.h>

int inspect_usb_out_packet(const void *buf, int len, u8 xfer_type);

int inspect_interrupt_out_packet(const void *buf, int len);

int usb_packet_inspector_sysfs_init(void);
void usb_packet_inspector_sysfs_exit(void);

#endif