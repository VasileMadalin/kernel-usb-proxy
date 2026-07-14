/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Kernel-only API for USB Raw Gadget
 *
 * This header exposes an in-kernel interface to the modified USB Raw Gadget
 * implementation used by the kernel-level USB proxy.
 *
 * It provides the internal API required for forwarding USB requests and
 * exchanging data between the USB proxy module and the adapted Raw Gadget
 * implementation.
 *
 * This header is intended for kernel-space use only and must not be included
 * by userspace applications.
 *
 * Copyright (c) 2026 Madalin Vasile
 */

#ifndef _RAW_GADGET_KAPI_H_
#define _RAW_GADGET_KAPI_H_

#include <linux/slab.h>
#include <linux/types.h>
#include <linux/usb/ch9.h>

#include "raw_gadget.h"

struct raw_dev;

struct raw_dev *usb_raw_open_k(void);
void usb_raw_close_k(struct raw_dev *dev);

int usb_raw_init_k(struct raw_dev *dev,
		   enum usb_device_speed speed,
		   const char *driver,
		   const char *device);

int usb_raw_run_k(struct raw_dev *dev);

int usb_raw_event_fetch_k(struct raw_dev *dev,
			  struct usb_raw_event *event);

static inline struct usb_raw_ep_io *usb_raw_io_alloc(u32 len, gfp_t gfp)
{
	return kzalloc(sizeof(struct usb_raw_ep_io) + len, gfp);
}

static inline void *usb_raw_io_data(struct usb_raw_ep_io *io)
{
	return (void *)((u8 *)io + sizeof(*io));
}

static inline void usb_raw_io_free(struct usb_raw_ep_io *io)
{
	kfree(io);
}

int usb_raw_ep0_read_k(struct raw_dev *dev,
		       struct usb_raw_ep_io *io);

int usb_raw_ep0_write_k(struct raw_dev *dev,
			struct usb_raw_ep_io *io);

int usb_raw_ep0_stall_k(struct raw_dev *dev);

int usb_raw_ep_enable_k(struct raw_dev *dev,
			const struct usb_endpoint_descriptor *desc);

int usb_raw_ep_disable_k(struct raw_dev *dev,
			 u32 handle);

int usb_raw_ep_read_k(struct raw_dev *dev,
		      struct usb_raw_ep_io *io);

int usb_raw_ep_write_k(struct raw_dev *dev,
		       struct usb_raw_ep_io *io);

int usb_raw_ep_set_halt_k(struct raw_dev *dev,
			  u32 handle);

int usb_raw_ep_clear_halt_k(struct raw_dev *dev,
			    u32 handle);

int usb_raw_ep_set_wedge_k(struct raw_dev *dev,
			   u32 handle);

int usb_raw_configure_k(struct raw_dev *dev);

int usb_raw_vbus_draw_k(struct raw_dev *dev,
			u32 power_2mA_units);

int usb_raw_eps_info_k(struct raw_dev *dev,
		       struct usb_raw_eps_info *info);

#endif /* _RAW_GADGET_KAPI_H_ */
