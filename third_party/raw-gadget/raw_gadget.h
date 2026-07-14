/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * USB Raw Gadget driver.
 *
 * See Documentation/usb/raw-gadget.rst for more details.
 *
 * NOTE (kernel-friendly):
 *  - This header is primarily UAPI, but it is safe to include from kernel.
 *  - Ioctl numbers are exposed ONLY to userspace (not needed in-kernel).
 */

#ifndef _UAPI__LINUX_USB_RAW_GADGET_H
#define _UAPI__LINUX_USB_RAW_GADGET_H

#include <linux/types.h>
#include <linux/usb/ch9.h>

#ifndef __KERNEL__
#include <asm/ioctl.h>
#endif

/* Maximum length of driver_name/device_name in the usb_raw_init struct. */
#define UDC_NAME_LENGTH_MAX 128

/*
 * struct usb_raw_init - argument for USB_RAW_IOCTL_INIT ioctl.
 */
struct usb_raw_init {
	__u8	driver_name[UDC_NAME_LENGTH_MAX];
	__u8	device_name[UDC_NAME_LENGTH_MAX];
	__u8	speed;
};

/* The type of event fetched with the USB_RAW_IOCTL_EVENT_FETCH ioctl. */
enum usb_raw_event_type {
	USB_RAW_EVENT_INVALID = 0,
	USB_RAW_EVENT_CONNECT = 1,
	USB_RAW_EVENT_CONTROL = 2,
	USB_RAW_EVENT_SUSPEND = 3,
	USB_RAW_EVENT_RESUME = 4,
	USB_RAW_EVENT_RESET = 5,
	USB_RAW_EVENT_DISCONNECT = 6,
	/* The list might grow in the future. */
};

/*
 * struct usb_raw_event - argument for USB_RAW_IOCTL_EVENT_FETCH ioctl.
 */
struct usb_raw_event {
	__u32		type;
	__u32		length;
	__u8		data[];
};

#define USB_RAW_IO_FLAGS_ZERO	0x0001
#define USB_RAW_IO_FLAGS_MASK	0x0001

static inline int usb_raw_io_flags_valid(__u16 flags)
{
	return (flags & ~USB_RAW_IO_FLAGS_MASK) == 0;
}

static inline int usb_raw_io_flags_zero(__u16 flags)
{
	return (flags & USB_RAW_IO_FLAGS_ZERO);
}

/*
 * struct usb_raw_ep_io - argument for USB_RAW_IOCTL_EP0/EP_WRITE/READ ioctls.
 */
struct usb_raw_ep_io {
	__u16		ep;
	__u16		flags;
	__u32		length;
	__u8		data[];
};

/* Maximum number of non-control endpoints in struct usb_raw_eps_info. */
#define USB_RAW_EPS_NUM_MAX	30

/* Maximum length of UDC endpoint name in struct usb_raw_ep_info. */
#define USB_RAW_EP_NAME_MAX	16

/* Used as addr in struct usb_raw_ep_info if endpoint accepts any address. */
#define USB_RAW_EP_ADDR_ANY	0xff

struct usb_raw_ep_caps {
	__u32	type_control	: 1;
	__u32	type_iso	: 1;
	__u32	type_bulk	: 1;
	__u32	type_int	: 1;
	__u32	dir_in		: 1;
	__u32	dir_out		: 1;
};

struct usb_raw_ep_limits {
	__u16	maxpacket_limit;
	__u16	max_streams;
	__u32	reserved;
};

struct usb_raw_ep_info {
	__u8				name[USB_RAW_EP_NAME_MAX];
	__u32				addr;
	struct usb_raw_ep_caps		caps;
	struct usb_raw_ep_limits	limits;
};

struct usb_raw_eps_info {
	struct usb_raw_ep_info	eps[USB_RAW_EPS_NUM_MAX];
};

enum usb_raw_timeout_type {
	USB_RAW_TIMEOUT_INVALID = 0,
	USB_RAW_TIMEOUT_EVENT_FETCH = 1,
	USB_RAW_TIMEOUT_EP0_IO = 2,
	USB_RAW_TIMEOUT_EP_IO = 3,
	/* The list might grow in the future. */
};

struct usb_raw_timeout {
	__u32	type;
	__u32	param;
	__u32	timeout;
};

#ifndef __KERNEL__
/*
 * Ioctls are userspace-only; kernel code should not depend on these.
 */

#define USB_RAW_IOCTL_INIT		_IOW('U', 0, struct usb_raw_init)
#define USB_RAW_IOCTL_RUN		_IO('U', 1)
#define USB_RAW_IOCTL_EVENT_FETCH	_IOR('U', 2, struct usb_raw_event)

#define USB_RAW_IOCTL_EP0_WRITE		_IOW('U', 3, struct usb_raw_ep_io)
#define USB_RAW_IOCTL_EP0_READ		_IOWR('U', 4, struct usb_raw_ep_io)

#define USB_RAW_IOCTL_EP_ENABLE		_IOW('U', 5, struct usb_endpoint_descriptor)
#define USB_RAW_IOCTL_EP_DISABLE	_IOW('U', 6, __u32)

#define USB_RAW_IOCTL_EP_WRITE		_IOW('U', 7, struct usb_raw_ep_io)
#define USB_RAW_IOCTL_EP_READ		_IOWR('U', 8, struct usb_raw_ep_io)

#define USB_RAW_IOCTL_CONFIGURE		_IO('U', 9)
#define USB_RAW_IOCTL_VBUS_DRAW		_IOW('U', 10, __u32)
#define USB_RAW_IOCTL_EPS_INFO		_IOR('U', 11, struct usb_raw_eps_info)

#define USB_RAW_IOCTL_EP0_STALL		_IO('U', 12)

#define USB_RAW_IOCTL_EP_SET_HALT	_IOW('U', 13, __u32)
#define USB_RAW_IOCTL_EP_CLEAR_HALT	_IOW('U', 14, __u32)
#define USB_RAW_IOCTL_EP_SET_WEDGE	_IOW('U', 15, __u32)

#define USB_RAW_IOCTL_SET_TIMEOUT	_IOW('U', 16, struct usb_raw_timeout)
#endif /* !__KERNEL__ */

#endif /* _UAPI__LINUX_USB_RAW_GADGET_H */
