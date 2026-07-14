// SPDX-License-Identifier: GPL-2.0
/*
 * USB Raw Gadget driver.
 * See Documentation/usb/raw-gadget.rst for more details.
 *
 * Original implementation:
 * Copyright (c) 2020 Google, Inc.
 * Author: Andrey Konovalov <andreyknvl@gmail.com>
 *
 * Modified for the kernel-level USB proxy project.
 * Modifications include adapting selected Raw Gadget functionality for
 * direct in-kernel use, replacing user-space IOCTL-based interactions,
 * and integrating the driver with the USB proxy forwarding architecture.
 *
 * Modifications Copyright (c) 2026 Madalin Vasile
 * Modified by: Madalin Vasile <madalin.vasile2806@stud.acs.upb.ro>
 */

#include <linux/compiler.h>
#include <linux/ctype.h>
#include <linux/debugfs.h>
#include <linux/delay.h>
#include <linux/idr.h>
#include <linux/kref.h>
#include <linux/module.h>
#include <linux/semaphore.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/wait.h>

#include <linux/usb.h>
#include <linux/usb/ch9.h>
#include <linux/usb/ch11.h>
#include <linux/usb/gadget.h>
#include <linux/usb/composite.h>

#include "raw_gadget.h"

#define	DRIVER_DESC "USB Raw Gadget"
#define DRIVER_NAME "raw-gadget"

MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_AUTHOR("Andrey Konovalov");
MODULE_LICENSE("GPL");

/*----------------------------------------------------------------------*/

static DEFINE_IDA(driver_id_numbers);
#define DRIVER_DRIVER_NAME_LENGTH_MAX	32

#define RAW_EVENT_QUEUE_SIZE	16

struct raw_event_queue {
	spinlock_t		lock;
	struct semaphore	sema;
	struct usb_raw_event	*events[RAW_EVENT_QUEUE_SIZE];
	int			size;
};

static inline void *io_data_ptr(struct usb_raw_ep_io *io)
{
	return (void *)((u8 *)io + sizeof(*io));
}

static void raw_event_queue_init(struct raw_event_queue *queue)
{
	spin_lock_init(&queue->lock);
	sema_init(&queue->sema, 0);
	queue->size = 0;
}

static int raw_event_queue_add(struct raw_event_queue *queue,
	enum usb_raw_event_type type, size_t length, const void *data)
{
	unsigned long flags;
	struct usb_raw_event *event;

	spin_lock_irqsave(&queue->lock, flags);
	if (queue->size >= RAW_EVENT_QUEUE_SIZE) {
		spin_unlock_irqrestore(&queue->lock, flags);
		return -ENOMEM;
	}
	event = kmalloc(sizeof(*event) + length, GFP_ATOMIC);
	if (!event) {
		spin_unlock_irqrestore(&queue->lock, flags);
		return -ENOMEM;
	}
	event->type = type;
	event->length = length;
	if (event->length)
		memcpy(&event->data[0], data, length);
	queue->events[queue->size] = event;
	queue->size++;
	up(&queue->sema);
	spin_unlock_irqrestore(&queue->lock, flags);
	return 0;
}

static struct usb_raw_event *raw_event_queue_fetch(
				struct raw_event_queue *queue)
{
	int ret;
	unsigned long flags;
	struct usb_raw_event *event;

	ret = down_interruptible(&queue->sema);
	if (ret)
		return ERR_PTR(ret);

	if (WARN_ON(!queue->size)) {
		spin_unlock_irqrestore(&queue->lock, flags);
		return ERR_PTR(-ENODEV);
	}
	event = queue->events[0];
	queue->size--;
	memmove(&queue->events[0], &queue->events[1],
			queue->size * sizeof(queue->events[0]));
	spin_unlock_irqrestore(&queue->lock, flags);
	return event;
}

static void raw_event_queue_destroy(struct raw_event_queue *queue)
{
	int i;

	for (i = 0; i < queue->size; i++)
		kfree(queue->events[i]);
	queue->size = 0;
}

/*----------------------------------------------------------------------*/

struct raw_dev;

enum ep_state {
	STATE_EP_DISABLED,
	STATE_EP_ENABLED,
};

struct raw_ep {
	struct raw_dev		*dev;
	enum ep_state		state;
	struct usb_ep		*ep;
	u8			addr;
	struct usb_request	*req;
	bool			urb_queued;
	bool			disabling;
	ssize_t			status;
};

enum dev_state {
	STATE_DEV_INVALID = 0,
	STATE_DEV_OPENED,
	STATE_DEV_INITIALIZED,
	STATE_DEV_REGISTERING,
	STATE_DEV_RUNNING,
	STATE_DEV_CLOSED,
	STATE_DEV_FAILED
};

struct raw_dev {
	struct kref			count;
	spinlock_t			lock;

	const char			*udc_name;
	struct usb_gadget_driver	driver;

	struct device			*dev;

	int				driver_id_number;

	enum dev_state			state;
	bool				gadget_registered;
	struct usb_gadget		*gadget;
	struct usb_request		*req;
	bool				ep0_in_pending;
	bool				ep0_out_pending;
	bool				ep0_urb_queued;
	ssize_t				ep0_status;
	struct raw_ep			eps[USB_RAW_EPS_NUM_MAX];
	int				eps_num;

	struct completion		ep0_done;
	struct raw_event_queue		queue;
};

static struct raw_dev *dev_new(void)
{
	struct raw_dev *dev;

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return NULL;
	kref_init(&dev->count);
	spin_lock_init(&dev->lock);
	init_completion(&dev->ep0_done);
	raw_event_queue_init(&dev->queue);
	dev->driver_id_number = -1;
	return dev;
}

static void dev_free(struct kref *kref)
{
	struct raw_dev *dev = container_of(kref, struct raw_dev, count);
	int i;

	kfree(dev->udc_name);
	kfree(dev->driver.udc_name);
	kfree(dev->driver.driver.name);
	if (dev->driver_id_number >= 0)
		ida_free(&driver_id_numbers, dev->driver_id_number);
	if (dev->req) {
		if (dev->ep0_urb_queued)
			usb_ep_dequeue(dev->gadget->ep0, dev->req);
		usb_ep_free_request(dev->gadget->ep0, dev->req);
	}
	raw_event_queue_destroy(&dev->queue);
	for (i = 0; i < dev->eps_num; i++) {
		if (dev->eps[i].state == STATE_EP_DISABLED)
			continue;
		usb_ep_disable(dev->eps[i].ep);
		usb_ep_free_request(dev->eps[i].ep, dev->eps[i].req);
		kfree(dev->eps[i].ep->desc);
		dev->eps[i].state = STATE_EP_DISABLED;
	}
	kfree(dev);
}

/*----------------------------------------------------------------------*/

static int raw_queue_event(struct raw_dev *dev,
	enum usb_raw_event_type type, size_t length, const void *data)
{
	int ret = 0;
	unsigned long flags;

	ret = raw_event_queue_add(&dev->queue, type, length, data);
	if (ret < 0) {
		spin_lock_irqsave(&dev->lock, flags);
		dev->state = STATE_DEV_FAILED;
		spin_unlock_irqrestore(&dev->lock, flags);
	}
	return ret;
}

static void gadget_ep0_complete(struct usb_ep *ep, struct usb_request *req)
{
	struct raw_dev *dev = req->context;
	unsigned long flags;

	spin_lock_irqsave(&dev->lock, flags);
	if (req->status)
		dev->ep0_status = req->status;
	else
		dev->ep0_status = req->actual;
	if (dev->ep0_in_pending)
		dev->ep0_in_pending = false;
	else
		dev->ep0_out_pending = false;
	spin_unlock_irqrestore(&dev->lock, flags);

	complete(&dev->ep0_done);
}

static u8 get_ep_addr(const char *name)
{
	if (isdigit(name[2]))
		return simple_strtoul(&name[2], NULL, 10);
	return USB_RAW_EP_ADDR_ANY;
}

static int gadget_bind(struct usb_gadget *gadget,
			struct usb_gadget_driver *driver)
{
	int ret = 0, i = 0;
	struct raw_dev *dev = container_of(driver, struct raw_dev, driver);
	struct usb_request *req;
	struct usb_ep *ep;
	unsigned long flags;

	if (strcmp(gadget->name, dev->udc_name) != 0)
		return -ENODEV;

	set_gadget_data(gadget, dev);
	req = usb_ep_alloc_request(gadget->ep0, GFP_KERNEL);
	if (!req) {
		dev_err(&gadget->dev, "usb_ep_alloc_request failed\n");
		set_gadget_data(gadget, NULL);
		return -ENOMEM;
	}

	spin_lock_irqsave(&dev->lock, flags);
	dev->req = req;
	dev->req->context = dev;
	dev->req->complete = gadget_ep0_complete;
	dev->gadget = gadget;
	gadget_for_each_ep(ep, dev->gadget) {
		dev->eps[i].ep = ep;
		dev->eps[i].addr = get_ep_addr(ep->name);
		dev->eps[i].state = STATE_EP_DISABLED;
		i++;
	}
	dev->eps_num = i;
	spin_unlock_irqrestore(&dev->lock, flags);

	pr_debug("gadget connected\n");
	ret = raw_queue_event(dev, USB_RAW_EVENT_CONNECT, 0, NULL);
	if (ret < 0) {
		dev_err(&gadget->dev, "failed to queue connect event\n");
		set_gadget_data(gadget, NULL);
		return ret;
	}

	kref_get(&dev->count);
	return ret;
}

static void gadget_unbind(struct usb_gadget *gadget)
{
	struct raw_dev *dev = get_gadget_data(gadget);

	set_gadget_data(gadget, NULL);
	kref_put(&dev->count, dev_free);
}

static int gadget_setup(struct usb_gadget *gadget,
			const struct usb_ctrlrequest *ctrl)
{
	int ret = 0;
	struct raw_dev *dev = get_gadget_data(gadget);
	unsigned long flags;

	spin_lock_irqsave(&dev->lock, flags);
	if (dev->state != STATE_DEV_RUNNING) {
		dev_err(&gadget->dev, "ignoring, device is not running\n");
		ret = -ENODEV;
		goto out_unlock;
	}
	if (dev->ep0_in_pending || dev->ep0_out_pending) {
		pr_debug("stalling, request already pending\n");
		ret = -EBUSY;
		goto out_unlock;
	}
	if ((ctrl->bRequestType & USB_DIR_IN) && ctrl->wLength)
		dev->ep0_in_pending = true;
	else
		dev->ep0_out_pending = true;
	spin_unlock_irqrestore(&dev->lock, flags);

	ret = raw_queue_event(dev, USB_RAW_EVENT_CONTROL, sizeof(*ctrl), ctrl);
	if (ret < 0)
		dev_err(&gadget->dev, "failed to queue control event\n");
	goto out;

out_unlock:
	spin_unlock_irqrestore(&dev->lock, flags);
out:
	if (ret == 0 && ctrl->wLength == 0) {
		return USB_GADGET_DELAYED_STATUS;
	}
	return ret;
}

static void gadget_disconnect(struct usb_gadget *gadget)
{
	struct raw_dev *dev = get_gadget_data(gadget);
	int ret;

	pr_debug("gadget disconnected\n");
	ret = raw_queue_event(dev, USB_RAW_EVENT_DISCONNECT, 0, NULL);
	if (ret < 0)
		dev_err(&gadget->dev, "failed to queue disconnect event\n");
}
static void gadget_suspend(struct usb_gadget *gadget)
{
	struct raw_dev *dev = get_gadget_data(gadget);
	int ret;

	pr_debug("gadget suspended\n");
	ret = raw_queue_event(dev, USB_RAW_EVENT_SUSPEND, 0, NULL);
	if (ret < 0)
		dev_err(&gadget->dev, "failed to queue suspend event\n");
}
static void gadget_resume(struct usb_gadget *gadget)
{
	struct raw_dev *dev = get_gadget_data(gadget);
	int ret;

	pr_debug("gadget resumed\n");
	ret = raw_queue_event(dev, USB_RAW_EVENT_RESUME, 0, NULL);
	if (ret < 0)
		dev_err(&gadget->dev, "failed to queue resume event\n");
}
static void gadget_reset(struct usb_gadget *gadget)
{
	struct raw_dev *dev = get_gadget_data(gadget);
	int ret;

	pr_debug("gadget reset\n");
	ret = raw_queue_event(dev, USB_RAW_EVENT_RESET, 0, NULL);
	if (ret < 0)
		dev_err(&gadget->dev, "failed to queue reset event\n");
}

/*----------------------------------------------------------------------*/

struct raw_dev *usb_raw_open_k(void)
{
	struct raw_dev *dev = dev_new();
	if (!dev)
		return NULL;

	dev->state = STATE_DEV_OPENED;

	dev->dev = NULL;

	return dev;
}

void usb_raw_close_k(struct raw_dev *dev)
{
	unsigned long flags;
	bool unregister = false;

	if (!dev)
		return;

	spin_lock_irqsave(&dev->lock, flags);
	dev->state = STATE_DEV_CLOSED;

	if (dev->gadget && dev->gadget_registered) {
		unregister = true;
		dev->gadget_registered = false;
	}
	spin_unlock_irqrestore(&dev->lock, flags);

	if (unregister) {
		int ret = usb_gadget_unregister_driver(&dev->driver);
		if (ret)
			pr_err("raw_gadget: usb_gadget_unregister_driver failed %d\n", ret);

		kref_put(&dev->count, dev_free);
	}

	kref_put(&dev->count, dev_free);
}

/*----------------------------------------------------------------------*/

int usb_raw_init_k(struct raw_dev *dev, enum usb_device_speed speed,
		   const char *driver, const char *device)
{
	int ret = 0;
	int driver_id_number;
	char *udc_driver_name;
	char *udc_device_name;
	char *driver_driver_name;
	unsigned long flags;

	switch (speed) {
	case USB_SPEED_UNKNOWN:
		speed = USB_SPEED_HIGH;
		break;
	case USB_SPEED_LOW:
	case USB_SPEED_FULL:
	case USB_SPEED_HIGH:
	case USB_SPEED_SUPER:
		break;
	default:
		return -EINVAL;
	}

	driver_id_number = ida_alloc(&driver_id_numbers, GFP_KERNEL);
	if (driver_id_number < 0)
		return driver_id_number;

	driver_driver_name = kmalloc(DRIVER_DRIVER_NAME_LENGTH_MAX, GFP_KERNEL);
	if (!driver_driver_name) {
		ret = -ENOMEM;
		goto out_free_driver_id_number;
	}
	snprintf(driver_driver_name, DRIVER_DRIVER_NAME_LENGTH_MAX,
		 DRIVER_NAME ".%d", driver_id_number);

	udc_driver_name = kmalloc(UDC_NAME_LENGTH_MAX, GFP_KERNEL);
	if (!udc_driver_name) {
		ret = -ENOMEM;
		goto out_free_driver_driver_name;
	}
	ret = strscpy(udc_driver_name, driver, UDC_NAME_LENGTH_MAX);
	if (ret < 0)
		goto out_free_udc_driver_name;
	ret = 0;

	udc_device_name = kmalloc(UDC_NAME_LENGTH_MAX, GFP_KERNEL);
	if (!udc_device_name) {
		ret = -ENOMEM;
		goto out_free_udc_driver_name;
	}
	ret = strscpy(udc_device_name, device, UDC_NAME_LENGTH_MAX);
	if (ret < 0)
		goto out_free_udc_device_name;
	ret = 0;

	spin_lock_irqsave(&dev->lock, flags);
	if (dev->state != STATE_DEV_OPENED) {
		pr_debug("raw_gadget: fail, device is not opened\n");
		ret = -EINVAL;
		goto out_unlock;
	}
	dev->udc_name = udc_driver_name;

	dev->driver.function = DRIVER_DESC;
	dev->driver.max_speed = speed;
	dev->driver.setup = gadget_setup;
	dev->driver.disconnect = gadget_disconnect;
	dev->driver.bind = gadget_bind;
	dev->driver.unbind = gadget_unbind;
	dev->driver.suspend = gadget_suspend;
	dev->driver.resume = gadget_resume;
	dev->driver.reset = gadget_reset;
	dev->driver.driver.name = driver_driver_name;
	dev->driver.udc_name = udc_device_name;
	dev->driver.match_existing_only = 1;
	dev->driver_id_number = driver_id_number;

	dev->state = STATE_DEV_INITIALIZED;
	spin_unlock_irqrestore(&dev->lock, flags);
	return 0;

out_unlock:
	spin_unlock_irqrestore(&dev->lock, flags);
out_free_udc_device_name:
	kfree(udc_device_name);
out_free_udc_driver_name:
	kfree(udc_driver_name);
out_free_driver_driver_name:
	kfree(driver_driver_name);
out_free_driver_id_number:
	ida_free(&driver_id_numbers, driver_id_number);
	return ret;
}

int usb_raw_run_k(struct raw_dev *dev)
{
	int ret;
	unsigned long flags;

	spin_lock_irqsave(&dev->lock, flags);
	if (dev->state != STATE_DEV_INITIALIZED) {
		pr_debug("raw_gadget: fail, device is not initialized\n");
		ret = -EINVAL;
		goto out_unlock;
	}
	dev->state = STATE_DEV_REGISTERING;
	spin_unlock_irqrestore(&dev->lock, flags);

	ret = usb_gadget_register_driver(&dev->driver);

	spin_lock_irqsave(&dev->lock, flags);
	if (ret) {
		pr_err("raw_gadget: fail, usb_gadget_register_driver returned %d\n", ret);
		dev->state = STATE_DEV_FAILED;
		goto out_unlock;
	}
	dev->gadget_registered = true;
	dev->state = STATE_DEV_RUNNING;
	kref_get(&dev->count); /* release/close */
out_unlock:
	spin_unlock_irqrestore(&dev->lock, flags);
	return ret;
}

int usb_raw_event_fetch_k(struct raw_dev *dev, struct usb_raw_event *arg)
{
	unsigned long flags;
	struct usb_raw_event *event;
	u32 length;

	if (!arg)
		return -EINVAL;

	spin_lock_irqsave(&dev->lock, flags);
	if (dev->state != STATE_DEV_RUNNING) {
		pr_debug("raw_gadget: fail, device is not running\n");
		spin_unlock_irqrestore(&dev->lock, flags);
		return -EINVAL;
	}
	if (!dev->gadget) {
		pr_debug("raw_gadget: fail, gadget is not bound\n");
		spin_unlock_irqrestore(&dev->lock, flags);
		return -EBUSY;
	}
	spin_unlock_irqrestore(&dev->lock, flags);

	event = raw_event_queue_fetch(&dev->queue);

	if (IS_ERR(event)) {
		int err = PTR_ERR(event);

		if (err == -EINTR)
			return -EINTR;

		pr_err("raw_gadget: failed to fetch event (%d)\n", err);
		spin_lock_irqsave(&dev->lock, flags);
		dev->state = STATE_DEV_FAILED;
		spin_unlock_irqrestore(&dev->lock, flags);
		return -ENODEV;
	}

	length = min(arg->length, event->length);

	arg->type = event->type;
	arg->length = event->length;
	if (length)
		memcpy(&arg->data[0], &event->data[0], length);

	kfree(event);
	return 0;
}

static int raw_process_ep0_io(struct raw_dev *dev, struct usb_raw_ep_io *io,
				void *data, bool in)
{
	int ret = 0;
	unsigned long flags;

	if (!io)
		return -EINVAL;
	if (io->length > PAGE_SIZE)
		return -EINVAL;
	if (!usb_raw_io_flags_valid(io->flags))
		return -EINVAL;

	spin_lock_irqsave(&dev->lock, flags);
	if (dev->state != STATE_DEV_RUNNING) {
		pr_debug("raw_gadget: fail, device is not running\n");
		ret = -EINVAL;
		goto out_unlock;
	}
	if (!dev->gadget) {
		pr_debug("raw_gadget: fail, gadget is not bound\n");
		ret = -EBUSY;
		goto out_unlock;
	}
	if (dev->ep0_urb_queued) {
		pr_debug("raw_gadget: fail, urb already queued\n");
		ret = -EBUSY;
		goto out_unlock;
	}
	if ((in && !dev->ep0_in_pending) ||
			(!in && !dev->ep0_out_pending)) {
		pr_debug("raw_gadget: fail, wrong direction\n");
		ret = -EBUSY;
		goto out_unlock;
	}
	if (WARN_ON(in && dev->ep0_out_pending)) {
		ret = -ENODEV;
		dev->state = STATE_DEV_FAILED;
		goto out_unlock;
	}
	if (WARN_ON(!in && dev->ep0_in_pending)) {
		ret = -ENODEV;
		dev->state = STATE_DEV_FAILED;
		goto out_unlock;
	}

	dev->req->buf = data;
	dev->req->length = io->length;
	dev->req->zero = usb_raw_io_flags_zero(io->flags);
	dev->ep0_urb_queued = true;
	spin_unlock_irqrestore(&dev->lock, flags);

	ret = usb_ep_queue(dev->gadget->ep0, dev->req, GFP_KERNEL);
	if (ret) {
		pr_debug("raw_gadget: fail, usb_ep_queue returned\n");
		spin_lock_irqsave(&dev->lock, flags);
		goto out_queue_failed;
	}

	ret = wait_for_completion_interruptible(&dev->ep0_done);
	if (ret) {
		pr_debug("raw_gadget: fail, wait interrupted\n");
		usb_ep_dequeue(dev->gadget->ep0, dev->req);
		wait_for_completion(&dev->ep0_done);
		spin_lock_irqsave(&dev->lock, flags);
		if (dev->ep0_status == -ECONNRESET)
			dev->ep0_status = -EINTR;
		goto out_interrupted;
	}

	spin_lock_irqsave(&dev->lock, flags);

out_interrupted:
	ret = dev->ep0_status;
out_queue_failed:
	dev->ep0_urb_queued = false;
out_unlock:
	spin_unlock_irqrestore(&dev->lock, flags);
	return ret;
}

int usb_raw_ep0_write_k(struct raw_dev *dev, struct usb_raw_ep_io *io)
{
	if (!io)
		return -EINVAL;
	if (io->length > PAGE_SIZE)
		return -EINVAL;
	if (!usb_raw_io_flags_valid(io->flags))
		return -EINVAL;

	return raw_process_ep0_io(dev, io, io_data_ptr(io), true);
}


int usb_raw_ep0_read_k(struct raw_dev *dev, struct usb_raw_ep_io *io)
{
	int ret;

	if (!io)
		return -EINVAL;
	if (io->length > PAGE_SIZE)
		return -EINVAL;
	if (!usb_raw_io_flags_valid(io->flags))
		return -EINVAL;

	ret = raw_process_ep0_io(dev, io, io_data_ptr(io), false);
	if (ret < 0)
		return ret;
	return min_t(u32, io->length, ret);
}


int usb_raw_ep0_stall_k(struct raw_dev *dev)
{
    int ret;
    unsigned long flags;

    spin_lock_irqsave(&dev->lock, flags);
    if (dev->state != STATE_DEV_RUNNING) { ret = -EINVAL; goto out_unlock; }
    if (!dev->gadget) { ret = -EBUSY; goto out_unlock; }
    if (dev->ep0_urb_queued) { ret = -EBUSY; goto out_unlock; }
    if (!dev->ep0_in_pending && !dev->ep0_out_pending) { ret = -EBUSY; goto out_unlock; }

    ret = usb_ep_set_halt(dev->gadget->ep0);
    if (ret < 0)
        dev_err(&dev->gadget->dev, "usb_ep_set_halt returned %d\n", ret);

    if (dev->ep0_in_pending) dev->ep0_in_pending = false;
    else dev->ep0_out_pending = false;

out_unlock:
    spin_unlock_irqrestore(&dev->lock, flags);
    return ret;
}

int usb_raw_ep_enable_k(struct raw_dev *dev,
			const struct usb_endpoint_descriptor *desc_in)
{
	int ret = 0, i;
	unsigned long flags;
	struct usb_endpoint_descriptor *desc;
	struct raw_ep *ep;
	bool ep_props_matched = false;

	if (!desc_in)
		return -EINVAL;

	desc = kmemdup(desc_in, sizeof(*desc), GFP_KERNEL);
	if (!desc)
		return -ENOMEM;

	if (usb_endpoint_maxp(desc) == 0) {
		pr_debug("raw_gadget: fail, bad endpoint maxpacket\n");
		kfree(desc);
		return -EINVAL;
	}

	spin_lock_irqsave(&dev->lock, flags);
	if (dev->state != STATE_DEV_RUNNING) {
		pr_debug("raw_gadget: fail, device is not running\n");
		ret = -EINVAL;
		goto out_free_unlock;
	}
	if (!dev->gadget) {
		pr_debug("raw_gadget: fail, gadget is not bound\n");
		ret = -EBUSY;
		goto out_free_unlock;
	}

	for (i = 0; i < dev->eps_num; i++) {
		ep = &dev->eps[i];

		if (ep->addr != usb_endpoint_num(desc) &&
		    ep->addr != USB_RAW_EP_ADDR_ANY)
			continue;

		if (!usb_gadget_ep_match_desc(dev->gadget, ep->ep, desc, NULL))
			continue;

		ep_props_matched = true;

		if (ep->state != STATE_EP_DISABLED)
			continue;

		ep->ep->desc = desc;

		ret = usb_ep_enable(ep->ep);
		if (ret < 0) {
			dev_err(&dev->gadget->dev,
				"raw_gadget: usb_ep_enable returned %d\n", ret);
			goto out_free_desc_unlock;
		}

		ep->req = usb_ep_alloc_request(ep->ep, GFP_ATOMIC);
		if (!ep->req) {
			dev_err(&dev->gadget->dev,
				"raw_gadget: usb_ep_alloc_request failed\n");
			usb_ep_disable(ep->ep);
			ret = -ENOMEM;
			goto out_free_desc_unlock;
		}

		ep->state = STATE_EP_ENABLED;
		ep->ep->driver_data = ep;

		spin_unlock_irqrestore(&dev->lock, flags);
		return i; /* handle = index */
	}

	if (!ep_props_matched) {
		pr_debug("raw_gadget: bad endpoint descriptor\n");
		ret = -EINVAL;
	} else {
		pr_debug("raw_gadget: no endpoints available\n");
		ret = -EBUSY;
	}

out_free_unlock:
	spin_unlock_irqrestore(&dev->lock, flags);
	kfree(desc);
	return ret;

out_free_desc_unlock:
	ep->ep->desc = NULL;
	spin_unlock_irqrestore(&dev->lock, flags);
	kfree(desc);
	return ret;
}

int usb_raw_ep_disable_k(struct raw_dev *dev, u32 handle)
{
	int ret = 0;
	int i = (int)handle;
	unsigned long flags;

	spin_lock_irqsave(&dev->lock, flags);

	if (dev->state != STATE_DEV_RUNNING) {
		pr_debug("raw_gadget: fail, device is not running\n");
		ret = -EINVAL;
		goto out_unlock;
	}

	if (!dev->gadget) {
		pr_debug("raw_gadget: fail, gadget is not bound\n");
		ret = -EBUSY;
		goto out_unlock;
	}

	if (i < 0 || i >= dev->eps_num) {
		pr_debug("raw_gadget: fail, invalid endpoint\n");
		ret = -EBUSY;
		goto out_unlock;
	}

	if (dev->eps[i].state == STATE_EP_DISABLED) {
		pr_debug("raw_gadget: endpoint is not enabled\n");
		ret = -EINVAL;
		goto out_unlock;
	}

	if (dev->eps[i].disabling) {
		pr_debug("raw_gadget: disable already in progress\n");
		ret = -EINVAL;
		goto out_unlock;
	}

	if (dev->eps[i].urb_queued) {
		pr_debug("raw_gadget: waiting for urb completion\n");
		ret = -EINVAL;
		goto out_unlock;
	}

	dev->eps[i].disabling = true;
	spin_unlock_irqrestore(&dev->lock, flags);

	usb_ep_disable(dev->eps[i].ep);

	spin_lock_irqsave(&dev->lock, flags);

	usb_ep_free_request(dev->eps[i].ep, dev->eps[i].req);
	dev->eps[i].req = NULL;

	kfree(dev->eps[i].ep->desc);
	dev->eps[i].ep->desc = NULL;

	dev->eps[i].state = STATE_EP_DISABLED;
	dev->eps[i].disabling = false;

out_unlock:
	spin_unlock_irqrestore(&dev->lock, flags);
	return ret;
}

int usb_raw_ep_set_clear_halt_wedge_k(struct raw_dev *dev, u32 handle, bool set, bool halt)
{
	int ret = 0;
	int i = (int)handle;
	unsigned long flags;

	spin_lock_irqsave(&dev->lock, flags);

	if (dev->state != STATE_DEV_RUNNING) { pr_debug("raw_gadget: device not running\n"); ret = -EINVAL; goto out_unlock; }
	if (!dev->gadget) { pr_debug("raw_gadget: gadget not bound\n"); ret = -EBUSY; goto out_unlock; }
	if (i < 0 || i >= dev->eps_num) { pr_debug("raw_gadget: invalid endpoint\n"); ret = -EBUSY; goto out_unlock; }
	if (dev->eps[i].state == STATE_EP_DISABLED) { pr_debug("raw_gadget: endpoint not enabled\n"); ret = -EINVAL; goto out_unlock; }
	if (dev->eps[i].disabling) { pr_debug("raw_gadget: disable in progress\n"); ret = -EINVAL; goto out_unlock; }
	if (dev->eps[i].urb_queued) { pr_debug("raw_gadget: waiting urb completion\n"); ret = -EINVAL; goto out_unlock; }
	if (usb_endpoint_xfer_isoc(dev->eps[i].ep->desc)) { pr_debug("raw_gadget: can't halt/wedge ISO\n"); ret = -EINVAL; goto out_unlock; }

	if (set && halt) {
		ret = usb_ep_set_halt(dev->eps[i].ep);
	} else if (!set && halt) {
		ret = usb_ep_clear_halt(dev->eps[i].ep);
	} else if (set && !halt) {
		ret = usb_ep_set_wedge(dev->eps[i].ep);
	}

out_unlock:
	spin_unlock_irqrestore(&dev->lock, flags);
	return ret;
}

int usb_raw_ep_set_halt_k(struct raw_dev *dev, u32 handle)
{
	return usb_raw_ep_set_clear_halt_wedge_k(dev, handle, true, true);
}
int usb_raw_ep_clear_halt_k(struct raw_dev *dev, u32 handle)
{
	return usb_raw_ep_set_clear_halt_wedge_k(dev, handle, false, true);
}
int usb_raw_ep_set_wedge_k(struct raw_dev *dev, u32 handle)
{
	return usb_raw_ep_set_clear_halt_wedge_k(dev, handle, true, false);
}


static void gadget_ep_complete(struct usb_ep *ep, struct usb_request *req)
{
	struct raw_ep *r_ep = (struct raw_ep *)ep->driver_data;
	struct raw_dev *dev = r_ep->dev;
	unsigned long flags;

	spin_lock_irqsave(&dev->lock, flags);
	if (req->status)
		r_ep->status = req->status;
	else
		r_ep->status = req->actual;
	spin_unlock_irqrestore(&dev->lock, flags);

	complete((struct completion *)req->context);
}

static int raw_process_ep_io(struct raw_dev *dev, struct usb_raw_ep_io *io,
				void *data, bool in)
{
	int ret = 0;
	unsigned long flags;
	struct raw_ep *ep;
	DECLARE_COMPLETION_ONSTACK(done);

	if (!io)
		return -EINVAL;
	if (io->ep >= USB_RAW_EPS_NUM_MAX)
		return -EINVAL;
	if (io->length > PAGE_SIZE)
		return -EINVAL;
	if (!usb_raw_io_flags_valid(io->flags))
		return -EINVAL;

	spin_lock_irqsave(&dev->lock, flags);
	if (dev->state != STATE_DEV_RUNNING) {
		pr_debug("raw_gadget: fail, device is not running\n");
		ret = -EINVAL;
		goto out_unlock;
	}
	if (!dev->gadget) {
		pr_debug("raw_gadget: fail, gadget is not bound\n");
		ret = -EBUSY;
		goto out_unlock;
	}
	if (io->ep >= dev->eps_num) {
		pr_debug("raw_gadget: fail, invalid endpoint\n");
		ret = -EINVAL;
		goto out_unlock;
	}
	ep = &dev->eps[io->ep];
	if (ep->state != STATE_EP_ENABLED) {
		pr_debug("raw_gadget: fail, endpoint is not enabled\n");
		ret = -EBUSY;
		goto out_unlock;
	}
	if (ep->disabling) {
		pr_debug("raw_gadget: fail, endpoint is already being disabled\n");
		ret = -EBUSY;
		goto out_unlock;
	}
	if (ep->urb_queued) {
		pr_debug("raw_gadget: fail, urb already queued\n");
		ret = -EBUSY;
		goto out_unlock;
	}
	if (in != usb_endpoint_dir_in(ep->ep->desc)) {
		pr_debug("raw_gadget: fail, wrong direction\n");
		ret = -EINVAL;
		goto out_unlock;
	}

	ep->dev = dev;
	ep->req->context = &done;
	ep->req->complete = gadget_ep_complete;
	ep->req->buf = data;
	ep->req->length = io->length;
	ep->req->zero = usb_raw_io_flags_zero(io->flags);
	ep->urb_queued = true;
	spin_unlock_irqrestore(&dev->lock, flags);

	ret = usb_ep_queue(ep->ep, ep->req, GFP_KERNEL);
	if (ret) {
		dev_err(&dev->gadget->dev,
				"fail, usb_ep_queue returned %d\n", ret);
		spin_lock_irqsave(&dev->lock, flags);
		goto out_queue_failed;
	}

	ret = wait_for_completion_interruptible(&done);
	if (ret) {
		pr_debug("wait interrupted\n");
		usb_ep_dequeue(ep->ep, ep->req);
		wait_for_completion(&done);
		spin_lock_irqsave(&dev->lock, flags);
		if (ep->status == -ECONNRESET)
			ep->status = -EINTR;
		goto out_interrupted;
	}

	spin_lock_irqsave(&dev->lock, flags);

out_interrupted:
	ret = ep->status;
out_queue_failed:
	ep->urb_queued = false;
out_unlock:
	spin_unlock_irqrestore(&dev->lock, flags);
	return ret;
}

int usb_raw_ep_write_k(struct raw_dev *dev, struct usb_raw_ep_io *io)
{
	if (!io)
		return -EINVAL;
	if (io->ep >= USB_RAW_EPS_NUM_MAX)
		return -EINVAL;
	if (io->length > PAGE_SIZE)
		return -EINVAL;
	if (!usb_raw_io_flags_valid(io->flags))
		return -EINVAL;

	return raw_process_ep_io(dev, io, io_data_ptr(io), true);
}

int usb_raw_ep_read_k(struct raw_dev *dev, struct usb_raw_ep_io *io)
{
	int ret;

	if (!io)
		return -EINVAL;
	if (io->ep >= USB_RAW_EPS_NUM_MAX)
		return -EINVAL;
	if (io->length > PAGE_SIZE)
		return -EINVAL;
	if (!usb_raw_io_flags_valid(io->flags))
		return -EINVAL;

	ret = raw_process_ep_io(dev, io, io_data_ptr(io), false);
	if (ret < 0)
		return ret;
	return min_t(u32, io->length, ret);
}

int usb_raw_configure_k(struct raw_dev *dev)
{
	int ret = 0;
	unsigned long flags;

	spin_lock_irqsave(&dev->lock, flags);
	if (dev->state != STATE_DEV_RUNNING) { pr_debug("raw_gadget: device not running\n"); ret = -EINVAL; goto out_unlock; }
	if (!dev->gadget) { pr_debug("raw_gadget: gadget not bound\n"); ret = -EBUSY; goto out_unlock; }

	usb_gadget_set_state(dev->gadget, USB_STATE_CONFIGURED);

out_unlock:
	spin_unlock_irqrestore(&dev->lock, flags);
	return ret;
}


int usb_raw_vbus_draw_k(struct raw_dev *dev, u32 power_2mA_units)
{
	int ret = 0;
	unsigned long flags;

	spin_lock_irqsave(&dev->lock, flags);
	if (dev->state != STATE_DEV_RUNNING) { pr_debug("raw_gadget: device not running\n"); ret = -EINVAL; goto out_unlock; }
	if (!dev->gadget) { pr_debug("raw_gadget: gadget not bound\n"); ret = -EBUSY; goto out_unlock; }

	usb_gadget_vbus_draw(dev->gadget, 2 * power_2mA_units);

out_unlock:
	spin_unlock_irqrestore(&dev->lock, flags);
	return ret;
}


static void fill_ep_caps(struct usb_ep_caps *caps,
				struct usb_raw_ep_caps *raw_caps)
{
	raw_caps->type_control = caps->type_control;
	raw_caps->type_iso = caps->type_iso;
	raw_caps->type_bulk = caps->type_bulk;
	raw_caps->type_int = caps->type_int;
	raw_caps->dir_in = caps->dir_in;
	raw_caps->dir_out = caps->dir_out;
}

static void fill_ep_limits(struct usb_ep *ep, struct usb_raw_ep_limits *limits)
{
	limits->maxpacket_limit = ep->maxpacket_limit;
	limits->max_streams = ep->max_streams;
}

int usb_raw_eps_info_k(struct raw_dev *dev, struct usb_raw_eps_info *info)
{
	int ret = 0, i;
	unsigned long flags;
	struct raw_ep *ep;

	if (!info)
		return -EINVAL;

	memset(info, 0, sizeof(*info));

	spin_lock_irqsave(&dev->lock, flags);
	if (dev->state != STATE_DEV_RUNNING) { pr_debug("raw_gadget: device not running\n"); ret = -EINVAL; goto out_unlock; }
	if (!dev->gadget) { pr_debug("raw_gadget: gadget not bound\n"); ret = -EBUSY; goto out_unlock; }

	for (i = 0; i < dev->eps_num; i++) {
		ep = &dev->eps[i];
		strscpy(&info->eps[i].name[0], ep->ep->name, USB_RAW_EP_NAME_MAX);
		info->eps[i].addr = ep->addr;
		fill_ep_caps(&ep->ep->caps, &info->eps[i].caps);
		fill_ep_limits(ep->ep, &info->eps[i].limits);
	}
	ret = dev->eps_num;

out_unlock:
	spin_unlock_irqrestore(&dev->lock, flags);
	return ret;
}