// SPDX-License-Identifier: GPL-2.0
/*
 * USB Proxy Control
 *
 * Implements the main control logic for the kernel-level USB proxy,
 * including device initialization, forwarding control, and interaction
 * with the packet inspection and policy engine modules.
 *
 * Copyright (c) 2026 Madalin Vasile
 * Author: Madalin Vasile
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/usb.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/mutex.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/ctype.h>
#include <linux/usb/ch9.h>
#include <linux/printk.h>
#include "raw_gadget_kapi.h"
#include <linux/kthread.h>
#include <linux/delay.h>
#include <asm/unaligned.h>
#include <linux/miscdevice.h>
#include "usb_packet_inspector.h"
#include "usb_policy_engine.h"

#define DEVNODE_NAME "usb_proxy"
#define CLASS_NAME   "usb_proxy"

static ushort vid = 0;
static ushort pid = 0;

module_param(vid, ushort, 0444);
module_param(pid, ushort, 0444);

MODULE_PARM_DESC(vid, "Target USB Vendor ID (hex)");
MODULE_PARM_DESC(pid, "Target USB Product ID (hex)");

static char *udc_name = NULL;
module_param(udc_name, charp, 0444);
MODULE_PARM_DESC(udc_name, "UDC name from /sys/class/udc (e.g. 1000480000.usb)");

#define USB_REQUEST_TIMEOUT_MS 1000
#define MAX_ATTEMPTS 5
#define RG_MAX_EPS   8
#define RG_QUEUE_DEPTH 32

struct rg_slot {
    u32 len;
    u8  *buf;
};

struct rg_queue {
    u16 head, tail, count;
    spinlock_t lock;
    wait_queue_head_t wq;
    struct rg_slot slot[RG_QUEUE_DEPTH];
};

struct usb_proxy_ep {
    struct raw_dev *rg;
    struct usb_device *real;
    struct usb_proxy_dev *mdev;

    struct usb_endpoint_descriptor ep_desc;

    u8  real_ep_addr;
    u8  real_ep_num;
    bool dir_in;

    u8  xfer_type;
    u16 interval; 

    int ep_handle;

    struct task_struct *tx_thread;
    struct task_struct *rx_thread;

    atomic_t running;

    struct rg_queue queue;
};


struct usb_proxy_dev {
    struct usb_device    *udev;
    struct usb_interface *intf;

    /* raw gadget side */
    struct raw_dev *rg;
    struct task_struct *rg_thread;
    u8 rg_address;
    u8 rg_config;
    bool rg_running;
    bool config_locked;

    /* endpoints*/

    struct usb_proxy_ep eps[RG_MAX_EPS];
    int num_eps;

    struct mutex stop_lock;
    bool eps_stopped;
};

static void rg_stop_all_eps(struct usb_proxy_dev *mdev);

static DEFINE_MUTEX(lock);
static struct usb_proxy_dev *g_dev;

static int rg_queue_init(struct rg_queue *q)
{
    int i;
    memset(q, 0, sizeof(*q));
    spin_lock_init(&q->lock);
    init_waitqueue_head(&q->wq);

    for (i = 0; i < RG_QUEUE_DEPTH; i++) {
        q->slot[i].buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
        if (!q->slot[i].buf)
            return -ENOMEM;
        q->slot[i].len = 0;
    }
    return 0;
}

static void rg_queue_free(struct rg_queue *q)
{
    int i;
    for (i = 0; i < RG_QUEUE_DEPTH; i++) {
        kfree(q->slot[i].buf);
        q->slot[i].buf = NULL;
        q->slot[i].len = 0;
    }
}

static int rg_queue_push(struct rg_queue *q, const u8 *data, u32 len)
{
    unsigned long flags;
    u16 idx;

    if (len > PAGE_SIZE)
        return -EINVAL;

    spin_lock_irqsave(&q->lock, flags);
    if (q->count == RG_QUEUE_DEPTH) {
        spin_unlock_irqrestore(&q->lock, flags);
        return -ENOSPC;
    }

    idx = q->tail;

    memcpy(q->slot[idx].buf, data, len);
    q->slot[idx].len = len;

    q->tail = (q->tail + 1) % RG_QUEUE_DEPTH;
    q->count++;

    spin_unlock_irqrestore(&q->lock, flags);

    wake_up(&q->wq);
    return 0;
}

static int do_get_device_descriptor(struct usb_device *udev)
{
    int ret;
    unsigned char *buf;

    buf = kmalloc(18, GFP_KERNEL);
    if (!buf)
        return -ENOMEM;

    /*
     * Standard GET_DESCRIPTOR(Device)
     * bmRequestType: 0x80 (IN, standard, device)
     * bRequest:      0x06 (GET_DESCRIPTOR)
     * wValue:        (DEVICE << 8) | 0
     * wIndex:        0
     * wLength:       18
     */
    ret = usb_control_msg(udev,
                          usb_rcvctrlpipe(udev, 0),
                          USB_REQ_GET_DESCRIPTOR,
                          USB_DIR_IN | USB_TYPE_STANDARD | USB_RECIP_DEVICE,
                          (USB_DT_DEVICE << 8) | 0,
                          0,
                          buf,
                          18,
                          1000);

    if (ret < 0) {
        pr_err("usb_proxy: GET_DESCRIPTOR(Device) failed: %d\n", ret);
        kfree(buf);
        return ret;
    }

    pr_info("usb_proxy: ===== GET_DESCRIPTOR(Device) RAW =====\n");
    pr_info("usb_proxy: bLength=%u bDescriptorType=%u bcdUSB=%02x%02x\n",
            buf[0], buf[1], buf[3], buf[2]);
    pr_info("usb_proxy: bDeviceClass=%02x bDeviceSubClass=%02x bDeviceProtocol=%02x\n",
            buf[4], buf[5], buf[6]);
    pr_info("usb_proxy: idVendor=%02x%02x idProduct=%02x%02x\n",
            buf[9], buf[8], buf[11], buf[10]);
    pr_info("usb_proxy: bNumConfigurations=%u\n", buf[17]);

    kfree(buf);
    return 0;
}

static void dump_cached_kernel_desc(struct usb_proxy_dev *dev)
{
    struct usb_device *udev;

    if (!dev || !dev->udev) {
        pr_info("usb_proxy: no device captured yet (probe not called)\n");
        return;
    }

    udev = dev->udev;

    pr_info("usb_proxy: ===== KERNEL CACHED DESCRIPTOR =====\n");
    pr_info("usb_proxy: VID=%04x PID=%04x bcdDevice=%04x\n",
            le16_to_cpu(udev->descriptor.idVendor),
            le16_to_cpu(udev->descriptor.idProduct),
            le16_to_cpu(udev->descriptor.bcdDevice));
    pr_info("usb_proxy: Class=%02x SubClass=%02x Protocol=%02x NumCfg=%u\n",
            udev->descriptor.bDeviceClass,
            udev->descriptor.bDeviceSubClass,
            udev->descriptor.bDeviceProtocol,
            udev->descriptor.bNumConfigurations);
}

static int parse_u16_hex(const char *s, u16 *out)
{
    unsigned long v;
    if (kstrtoul(s, 0, &v))
        return -EINVAL;
    if (v > 0xffff)
        return -ERANGE;
    *out = (u16)v;
    return 0;
}

static int parse_u8_hex(const char *s, u8 *out)
{
    unsigned long v;
    if (kstrtoul(s, 0, &v))
        return -EINVAL;
    if (v > 0xff)
        return -ERANGE;
    *out = (u8)v;
    return 0;
}

static void dump_bytes(const char *prefix, const u8 *buf, int len)
{
    if (len <= 0 || !buf) {
        pr_info("%s <no data>\n", prefix);
        return;
    }

    print_hex_dump(KERN_INFO, prefix, DUMP_PREFIX_OFFSET, 16, 1,
                   buf, len, false);
}

static int do_user_control(struct usb_device *udev, char *args)
{
    char *tok;
    u8 bmReq, bReq;
    u16 wValue, wIndex, wLen;
    int ret, i = 0;
    u8 *buf = NULL;
    bool is_in;

    /* 1) bmRequestType */
    tok = strsep(&args, " \t");
    if (!tok || !*tok) return -EINVAL;
    ret = parse_u8_hex(tok, &bmReq);
    if (ret) return ret;

    /* 2) bRequest */
    tok = strsep(&args, " \t");
    if (!tok || !*tok) return -EINVAL;
    ret = parse_u8_hex(tok, &bReq);
    if (ret) return ret;

    /* 3) wValue */
    tok = strsep(&args, " \t");
    if (!tok || !*tok) return -EINVAL;
    ret = parse_u16_hex(tok, &wValue);
    if (ret) return ret;

    /* 4) wIndex */
    tok = strsep(&args, " \t");
    if (!tok || !*tok) return -EINVAL;
    ret = parse_u16_hex(tok, &wIndex);
    if (ret) return ret;

    /* 5) wLength */
    tok = strsep(&args, " \t");
    if (!tok || !*tok) return -EINVAL;
    ret = parse_u16_hex(tok, &wLen);
    if (ret) return ret;

    is_in = !!(bmReq & USB_DIR_IN);

    if (wLen) {
        buf = kmalloc(wLen, GFP_KERNEL);
        if (!buf)
            return -ENOMEM;
        memset(buf, 0, wLen);
    }

    if (!is_in && wLen && args) {
        while ((tok = strsep(&args, " \t")) != NULL) {
            u8 b;
            if (!*tok)
                continue;
            if (i >= wLen)
                break;
            ret = parse_u8_hex(tok, &b);
            if (ret) {
                pr_err("usb_proxy: ctrl: bad data byte '%s'\n", tok);
                kfree(buf);
                return ret;
            }
            buf[i++] = b;
        }
        if (i < wLen) {
            pr_info("usb_proxy: ctrl: OUT payload shorter (%d) than wLen (%u)\n", i, wLen);
        }
    }

    pr_info("usb_proxy: ctrl: bmReq=%02x bReq=%02x wValue=%04x wIndex=%04x wLen=%u dir=%s\n",
            bmReq, bReq, wValue, wIndex, wLen, is_in ? "IN" : "OUT");

    if (!is_in)
        dump_bytes("usb_proxy: ctrl OUT data: ", buf, wLen);

    ret = usb_control_msg(udev,
                          is_in ? usb_rcvctrlpipe(udev, 0) : usb_sndctrlpipe(udev, 0),
                          bReq,
                          bmReq,
                          wValue,
                          wIndex,
                          buf,
                          wLen,
                          1000);

    if (ret < 0) {
        pr_err("usb_proxy: ctrl: usb_control_msg failed: %d\n", ret);
        kfree(buf);
        return ret;
    }

    if (is_in) {
        pr_info("usb_proxy: ctrl: IN received %d bytes\n", ret);
        dump_bytes("usb_proxy: ctrl IN data: ", buf, ret);
    } else {
        pr_info("usb_proxy: ctrl: OUT sent %d bytes\n", ret);
    }

    kfree(buf);
    return 0;
}

static ssize_t usb_proxydev_write(struct file *f, const char __user *ubuf,
                           size_t len, loff_t *off)
{
    char cmd[64];
    size_t n = min(len, sizeof(cmd) - 1);
    char *p, *op, *args;
    int ret = 0;

    if (n == 0)
        return 0;

    if (copy_from_user(cmd, ubuf, n))
        return -EFAULT;

    cmd[n] = '\0';

    p = strim(cmd);
    if (*p == '\0')
        return (ssize_t)len;

    op = strsep(&p, " \t");
    args = p;

    mutex_lock(&lock);

    if (!strcmp(op, "desc")) {
        if (!g_dev || !g_dev->udev) {
            pr_info("usb_proxy: desc: no device (not bound)\n");
            ret = -ENODEV;
        } else {
            dump_cached_kernel_desc(g_dev);
            ret = do_get_device_descriptor(g_dev->udev);
        }

    } else if (!strcmp(op, "status")) {
        pr_info("usb_proxy: status: bound=%s\n", g_dev ? "yes" : "no");
        if (g_dev && g_dev->udev) {
            pr_info("usb_proxy: current VID=%04x PID=%04x\n",
                    le16_to_cpu(g_dev->udev->descriptor.idVendor),
                    le16_to_cpu(g_dev->udev->descriptor.idProduct));
        }

    } else if (!strcmp(op, "ctrl")) {
        if (!g_dev || !g_dev->udev) {
            pr_info("usb_proxy: ctrl: no device (not bound)\n");
            ret = -ENODEV;
        } else if (!args || *strim(args) == '\0') {
            pr_info("usb_proxy: ctrl usage:\n");
            pr_info("usb_proxy:   ctrl bmReq bReq wValue wIndex wLen [data...]\n");
            pr_info("usb_proxy: example IN : ctrl 0x80 0x06 0x0100 0x0000 0x0012\n");
            pr_info("usb_proxy: example OUT: ctrl 0x40 0x01 0x0001 0x0000 0x0002 0xaa 0x55\n");
            ret = -EINVAL;
        } else {
            /* do_user_control */
            ret = do_user_control(g_dev->udev, strim(args));
        }

    } else {
        pr_info("usb_proxy: unknown cmd '%s' (use: desc|status|ctrl)\n", op);
        ret = -EINVAL;
    }

    mutex_unlock(&lock);

    return ret < 0 ? ret : (ssize_t)len;
}

static const struct file_operations usb_proxydev_fops = {
    .owner  = THIS_MODULE,
    .write  = usb_proxydev_write,
    .llseek = no_llseek,
};

static struct miscdevice usb_proxy_miscdev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = DEVNODE_NAME,
    .fops  = &usb_proxydev_fops,
    .mode  = 0666,
};

static int rg_ep0_ack_out0(struct raw_dev *rg)
{
    struct usb_raw_ep_io *io = usb_raw_io_alloc(0, GFP_KERNEL);
    int ret;

    if (!io)
        return -ENOMEM;

    io->ep = 0;
    io->flags = 0;
    io->length = 0;

    ret = usb_raw_ep0_read_k(rg, io);

    usb_raw_io_free(io);
    return ret;
}

static int rg_ep0_read_out(struct raw_dev *rg, void *buf, u32 len)
{
    struct usb_raw_ep_io *io;
    int ret;

    io = usb_raw_io_alloc(len, GFP_KERNEL);
    if (!io)
        return -ENOMEM;

    io->ep = 0;
    io->flags = 0;
    io->length = len;

    ret = usb_raw_ep0_read_k(rg, io);
    if (ret >= 0 && len)
        memcpy(buf, usb_raw_io_data(io), min_t(u32, len, (u32)ret));

    usb_raw_io_free(io);
    return ret;
}

static int rg_ep0_write_in(struct raw_dev *rg, const void *buf, u32 len)
{
    struct usb_raw_ep_io *io;
    int ret;

    io = usb_raw_io_alloc(len, GFP_KERNEL);
    if (!io)
        return -ENOMEM;

    io->ep = 0;
    io->flags = 0;
    io->length = len;

    if (len)
        memcpy(usb_raw_io_data(io), buf, len);

    ret = usb_raw_ep0_write_k(rg, io);

    usb_raw_io_free(io);
    return ret;
}

static inline int int_timeout_ms(const struct usb_proxy_ep *me)
{
    return 50;
}

static int k_send_xfer(struct usb_device *udev,
                       struct usb_proxy_ep *me,
                       void *buf,
                       int len)
{
    int pipe;
    int actual = 0;
    int ret;

    if (!udev || !me || !buf || len <= 0)
        return -EINVAL;

    if (me->xfer_type == USB_ENDPOINT_XFER_BULK ||
        me->xfer_type == USB_ENDPOINT_XFER_INT) {

        ret = inspect_usb_out_packet(buf, len, me->xfer_type);

        if (ret < 0) {
            pr_err("usb_proxy: packet blocked on EP%02x, type=%s, len=%d\n",
                   me->real_ep_addr,
                   me->xfer_type == USB_ENDPOINT_XFER_INT
                       ? "INTERRUPT OUT"
                       : "BULK OUT",
                   len);

            atomic_set(&me->running, 0);
            wake_up_all(&me->queue.wq);

            return -EPERM;
        }
    }

    if (me->xfer_type == USB_ENDPOINT_XFER_INT) {
        pipe = usb_sndintpipe(udev, me->real_ep_num);

        len = min_t(int,
                    len,
                    usb_endpoint_maxp(&me->ep_desc));

        ret = usb_interrupt_msg(udev,
                                pipe,
                                buf,
                                len,
                                &actual,
                                int_timeout_ms(me));

        if (ret == 0 && actual == len)
            return 0;

        if (ret == -EPIPE)
            usb_clear_halt(udev, pipe);

        return ret ? ret : -EIO;
    }

    if (me->xfer_type == USB_ENDPOINT_XFER_BULK) {
        pipe = usb_sndbulkpipe(udev, me->real_ep_num);

        ret = usb_bulk_msg(udev,
                           pipe,
                           buf,
                           len,
                           &actual,
                           USB_REQUEST_TIMEOUT_MS);

        if (ret == 0 && actual == len)
            return 0;

        if (ret == -EPIPE)
            usb_clear_halt(udev, pipe);

        return ret ? ret : -EIO;
    }

    return -EOPNOTSUPP;
}

static int k_recv_xfer(struct usb_device *udev, struct usb_proxy_ep *me,
                       void *buf, int bufsz, int *out_len)
{
    int pipe, actual = 0, ret;

    *out_len = 0;

    if (me->xfer_type == USB_ENDPOINT_XFER_INT) {
        pipe = usb_rcvintpipe(udev, me->real_ep_num);

        bufsz = min_t(int, bufsz, usb_endpoint_maxp(&me->ep_desc));

        ret = usb_interrupt_msg(udev, pipe, buf, bufsz, &actual,
                                int_timeout_ms(me));
        if (ret == 0) {
            *out_len = actual;
            return 0;
        }

        if (ret == -EPIPE || ret == -ETIMEDOUT)
            usb_clear_halt(udev, pipe);

        return ret;
    }

    /* default BULK */
    pipe = usb_rcvbulkpipe(udev, me->real_ep_num);

    ret = usb_bulk_msg(udev, pipe, buf, bufsz, &actual, USB_REQUEST_TIMEOUT_MS);
    if (ret == 0) {
        *out_len = actual;
        return 0;
    }

    if (ret == -EPIPE || ret == -ETIMEDOUT)
        usb_clear_halt(udev, pipe);

    return ret;
}

static inline bool rg_queue_has_data(struct rg_queue *q)
{
    unsigned long flags;
    bool ok;
    spin_lock_irqsave(&q->lock, flags);
    ok = (q->count > 0);
    spin_unlock_irqrestore(&q->lock, flags);
    return ok;
}


static inline bool rg_queue_has_space(struct rg_queue *q)
{
    unsigned long flags;
    bool ok;
    spin_lock_irqsave(&q->lock, flags);
    ok = (q->count < RG_QUEUE_DEPTH);
    spin_unlock_irqrestore(&q->lock, flags);
    return ok;
}

static int rg_queue_pop(struct rg_queue *q, u8 *dst, int dstsz, int *out_len)
{
    unsigned long flags;
    u32 len;

    if (!dst || dstsz <= 0 || !out_len)
        return -EINVAL;

    spin_lock_irqsave(&q->lock, flags);
    if (q->count == 0) {
        spin_unlock_irqrestore(&q->lock, flags);
        return -ENOENT;
    }

    len = q->slot[q->head].len;
    if (len > (u32)dstsz)
        len = (u32)dstsz;

    memcpy(dst, q->slot[q->head].buf, len);

    q->slot[q->head].len = 0;

    q->head = (q->head + 1) % RG_QUEUE_DEPTH;
    q->count--;
    spin_unlock_irqrestore(&q->lock, flags);

    *out_len = (int)len;

    wake_up_interruptible(&q->wq);
    return 0;
}

static int ep_loop_read_thread(void *arg)
{
    struct usb_proxy_ep *me = arg;
    struct rg_queue *q = &me->queue;

    int maxp  = usb_endpoint_maxp(&me->ep_desc);
    int bufsz = max(512, maxp * 8);
    u8 *tmp;

    if (bufsz > PAGE_SIZE)
        bufsz = PAGE_SIZE;

    tmp = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!tmp) {
        me->rx_thread = NULL;
        return -ENOMEM;
    }

    pr_info("rg: READ thread EP%02x start (dir=%s) maxp=%d bufsz=%d ep_handle=%d real_ep_num=%d\n",
            me->real_ep_addr, me->dir_in ? "IN" : "OUT",
            maxp, bufsz, me->ep_handle, me->real_ep_num);

    while (!kthread_should_stop() && atomic_read(&me->running)) {
        int ret, nbytes = 0;

        ret = wait_event_interruptible(q->wq,
            kthread_should_stop() ||
            !atomic_read(&me->running) ||
            rg_queue_has_space(q)
        );

        if (ret == -ERESTARTSYS)
            continue;

        if (kthread_should_stop() || !atomic_read(&me->running))
            break;

        if (me->dir_in) {
            ret = k_recv_xfer(me->real, me, tmp, bufsz, &nbytes);
            if (ret < 0) {
                if (me->xfer_type == USB_ENDPOINT_XFER_INT && ret == -ETIMEDOUT)
                    continue;

                pr_debug("rg: EP%02x REAL->Q recv ret=%d\n",
                         me->real_ep_addr, ret);

                if (ret == -ENODEV || ret == -ESHUTDOWN)
                    break;

                continue;
            }

            if (nbytes <= 0)
                continue;

            ret = rg_queue_push(q, tmp, nbytes);
            if (ret < 0) {
                pr_debug("rg: EP%02x REAL->Q push ret=%d\n",
                         me->real_ep_addr, ret);
                continue;
            }

            pr_debug("rg: EP%02x REAL->Q got %d bytes\n",
                     me->real_ep_addr, nbytes);

        } else {
            struct usb_raw_ep_io *io;

            io = usb_raw_io_alloc(PAGE_SIZE, GFP_KERNEL);
            if (!io)
                continue;

            io->ep     = me->ep_handle;
            io->flags  = 0;
            io->length = PAGE_SIZE;

            ret = usb_raw_ep_read_k(me->rg, io);
            if (ret < 0) {
                pr_debug("rg: EP%02x HOST->Q read ret=%d\n",
                         me->real_ep_addr, ret);

                usb_raw_io_free(io);

                if (ret == -ESHUTDOWN || ret == -ENODEV || ret == -EINTR)
                    break;

                continue;
            }

            if (ret > 0) {
                int push = rg_queue_push(q, usb_raw_io_data(io), ret);
                if (push == 0)
                    pr_debug("rg: EP%02x HOST->Q got %d bytes\n",
                             me->real_ep_addr, ret);
            }

            usb_raw_io_free(io);
        }
    }

    pr_info("rg: READ thread EP%02x stop\n", me->real_ep_addr);

    kfree(tmp);
    me->rx_thread = NULL;
    return 0;
}

static int ep_loop_write_thread(void *arg)
{
    struct usb_proxy_ep *me = arg;
    struct rg_queue *q = &me->queue;
    u8 *tmp;
    int tmpsz = PAGE_SIZE;

    tmp = kmalloc(tmpsz, GFP_KERNEL);
    if (!tmp) {
        me->tx_thread = NULL;
        return -ENOMEM;
    }

    pr_info("rg: WRITE thread EP%02x start (dir=%s) ep_handle=%d real_ep_num=%d\n",
            me->real_ep_addr, me->dir_in ? "IN" : "OUT",
            me->ep_handle, me->real_ep_num);

    while (!kthread_should_stop() && atomic_read(&me->running)) {
        int ret, nbytes = 0;

        ret = wait_event_interruptible(q->wq,
            kthread_should_stop() ||
            !atomic_read(&me->running) ||
            rg_queue_has_data(q)
        );

        if (ret == -ERESTARTSYS)
            continue;

        if (kthread_should_stop() || !atomic_read(&me->running))
            break;

        ret = rg_queue_pop(q, tmp, tmpsz, &nbytes);
        if (ret < 0 || nbytes <= 0)
            continue;

        if (me->dir_in) {
            struct usb_raw_ep_io *io;

            io = usb_raw_io_alloc(nbytes, GFP_KERNEL);
            if (!io)
                continue;

            io->ep     = me->ep_handle;
            io->flags  = 0;
            io->length = nbytes;

            memcpy(usb_raw_io_data(io), tmp, nbytes);

            ret = usb_raw_ep_write_k(me->rg, io);
            usb_raw_io_free(io);

            if (ret < 0) {
                if (ret == -ESHUTDOWN || ret == -ENODEV || ret == -EINTR)
                    break;

                continue;
            }

        } else {
            ret = k_send_xfer(me->real, me, tmp, nbytes);
            if (ret < 0) {
                if (ret == -ENODEV || ret == -ESHUTDOWN)
                    break;

                continue;
            }
        }

        wake_up_interruptible(&q->wq);
    }

    pr_info("rg: WRITE thread EP%02x stop\n", me->real_ep_addr);

    kfree(tmp);
    me->tx_thread = NULL;
    return 0;
}

static void start_eps_threads(struct usb_proxy_dev *mdev,
                             struct usb_endpoint_descriptor *ep)
{
    struct usb_proxy_ep *me;
    u8 addr = ep->bEndpointAddress;
    u8 num  = usb_endpoint_num(ep);
    int handle, ret;

    if (num == 0)
        return;

    if (!usb_endpoint_xfer_bulk(ep) && !usb_endpoint_xfer_int(ep))
        return;

    if (mdev->num_eps >= RG_MAX_EPS)
        return;

    me = &mdev->eps[mdev->num_eps++];
    memset(me, 0, sizeof(*me));

    me->rg = mdev->rg;
    me->real = mdev->udev;
    me->ep_desc = *ep;
    me->real_ep_addr = addr;
    me->real_ep_num  = num;
    me->dir_in       = usb_endpoint_dir_in(ep);

    me->xfer_type = usb_endpoint_type(ep);
    me->interval  = ep->bInterval;
    me->mdev = mdev;
    
    atomic_set(&me->running, 1);

    handle = usb_raw_ep_enable_k(mdev->rg, &me->ep_desc);
    if (handle < 0) {
        mdev->num_eps--;
        memset(me, 0, sizeof(*me));
        return;
    }
    me->ep_handle = handle;

    ret = rg_queue_init(&me->queue);
    if (ret) {
        usb_raw_ep_disable_k(mdev->rg, me->ep_handle);
        me->ep_handle = -1;
        mdev->num_eps--;
        memset(me, 0, sizeof(*me));
        return;
    }

    me->rx_thread = kthread_run(ep_loop_read_thread, me, "rg_r_%02x", addr);
    if (IS_ERR(me->rx_thread)) {
        me->rx_thread = NULL;
        goto err;
    }

    me->tx_thread = kthread_run(ep_loop_write_thread, me, "rg_w_%02x", addr);
    if (IS_ERR(me->tx_thread)) {
        me->tx_thread = NULL;
        goto err;
    }

    pr_info("rg: enabled %s %s EP%02x handle=%d real_ep_num=%u interval=%u\n",
            (me->xfer_type == USB_ENDPOINT_XFER_INT) ? "INT" : "BULK",
            me->dir_in ? "IN" : "OUT",
            addr, me->ep_handle, me->real_ep_num, me->interval);

    return;

err:
    atomic_set(&me->running, 0);
    wake_up_all(&me->queue.wq);

    if (me->rx_thread) { kthread_stop(me->rx_thread); me->rx_thread = NULL; }
    if (me->tx_thread) { kthread_stop(me->tx_thread); me->tx_thread = NULL; }

    rg_queue_free(&me->queue);

    usb_raw_ep_disable_k(mdev->rg, me->ep_handle);
    me->ep_handle = -1;

    mdev->num_eps--;
    memset(me, 0, sizeof(*me));
}


static void rg_stop_all_eps(struct usb_proxy_dev *mdev)
{
    int i;

    if (!mdev)
        return;

    mutex_lock(&mdev->stop_lock);

    if (mdev->eps_stopped) {
        mutex_unlock(&mdev->stop_lock);
        return;
    }

    mdev->eps_stopped = true;

    for (i = 0; i < mdev->num_eps; i++) {
        struct usb_proxy_ep *ep = &mdev->eps[i];

        atomic_set(&ep->running, 0);
        wake_up_all(&ep->queue.wq);
    }

    for (i = 0; i < mdev->num_eps; i++) {
        struct usb_proxy_ep *ep = &mdev->eps[i];

        if (ep->ep_handle >= 0) {
            pr_info("usb_proxy: rg: disabling EP%02x handle=%d\n",
                    ep->real_ep_addr, ep->ep_handle);

            usb_raw_ep_disable_k(mdev->rg, ep->ep_handle);
            ep->ep_handle = -1;
        }
    }

    for (i = 0; i < mdev->num_eps; i++) {
        struct usb_proxy_ep *ep = &mdev->eps[i];
        struct task_struct *rx;
        struct task_struct *tx;

        rx = ep->rx_thread;
        ep->rx_thread = NULL;

        tx = ep->tx_thread;
        ep->tx_thread = NULL;

        if (rx && !IS_ERR(rx))
            kthread_stop(rx);

        if (tx && !IS_ERR(tx))
            kthread_stop(tx);

        rg_queue_free(&ep->queue);
    }

    mdev->num_eps = 0;

    mutex_unlock(&mdev->stop_lock);
}


static struct usb_host_config *rg_find_cfg_by_value(struct usb_device *udev, u8 cfgval)
{
    int i;

    if (!udev)
        return NULL;

    for (i = 0; i < udev->descriptor.bNumConfigurations; i++) {
        struct usb_host_config *cfg = &udev->config[i];
        if (cfg->desc.bConfigurationValue == cfgval)
            return cfg;
    }
    return NULL;
}

static int rg_start_eps_for_config(struct usb_proxy_dev *mdev, u8 cfgval)
{
    struct usb_device *udev = mdev->udev;
    struct usb_host_config *cfg;
    int i, j;

    cfg = rg_find_cfg_by_value(udev, cfgval);
    if (!cfg) {
        pr_err("rg: no config %u\n", cfgval);
        return -EINVAL;
    }

    mdev->num_eps = 0;

    mutex_lock(&mdev->stop_lock);
    mdev->eps_stopped = false;
    mutex_unlock(&mdev->stop_lock);

    for (i = 0; i < cfg->desc.bNumInterfaces; i++) {
        struct usb_interface_cache *ic = cfg->intf_cache[i];
        struct usb_host_interface *alt;

        if (!ic || ic->num_altsetting == 0)
            continue;

        alt = &ic->altsetting[0];

        for (j = 0; j < alt->desc.bNumEndpoints; j++) {
            struct usb_endpoint_descriptor *ep = &alt->endpoint[j].desc;

            if (!usb_endpoint_xfer_bulk(ep) && !usb_endpoint_xfer_int(ep))
                continue;

            if (mdev->num_eps >= RG_MAX_EPS)
                return 0;

            start_eps_threads(mdev, ep);
        }
    }

    return 0;
}


static int rg_ep0_ack_in_status(struct raw_dev *rg)
{
    int ret;

    ret = rg_ep0_ack_out0(rg);

    if (ret == -EBUSY)
        return 0;

    if (ret == -EINTR)
        return 0;

    return ret;
}

static const char *rg_usb_class_name(u8 cls)
{
    switch (cls) {
    case USB_CLASS_PER_INTERFACE:
        return "Defined at Interface level";
    case USB_CLASS_AUDIO:
        return "Audio";
    case USB_CLASS_COMM:
        return "CDC/Communications";
    case USB_CLASS_HID:
        return "HID";
    case USB_CLASS_PHYSICAL:
        return "Physical";
    case USB_CLASS_STILL_IMAGE:
        return "Still Image";
    case USB_CLASS_PRINTER:
        return "Printer";
    case USB_CLASS_MASS_STORAGE:
        return "Mass Storage";
    case USB_CLASS_HUB:
        return "Hub";
    case USB_CLASS_CDC_DATA:
        return "CDC Data";
    case USB_CLASS_CSCID:
        return "Smart Card";
    case USB_CLASS_CONTENT_SEC:
        return "Content Security";
    case USB_CLASS_VIDEO:
        return "Video";
    case USB_CLASS_WIRELESS_CONTROLLER:
        return "Wireless Controller";
    case USB_CLASS_MISC:
        return "Misc";
    case USB_CLASS_APP_SPEC:
        return "Application Specific";
    case USB_CLASS_VENDOR_SPEC:
        return "Vendor Specific";
    default:
        return "Unknown";
    }
}

static void rg_log_device_desc_simple(const u8 *buf, int len)
{
    const struct usb_device_descriptor *dd;

    if (!buf || len < sizeof(*dd))
        return;

    dd = (const struct usb_device_descriptor *)buf;

    pr_info("usb_proxy: USB Device: %04x:%04x\n",
            le16_to_cpu(dd->idVendor),
            le16_to_cpu(dd->idProduct));
}

static void rg_log_config_interfaces_simple(const u8 *buf, int len)
{
    int off = 0;

    while (off + 2 <= len) {
        const struct usb_descriptor_header *hdr =
            (const struct usb_descriptor_header *)(buf + off);

        if (hdr->bLength < 2)
            break;
        if (off + hdr->bLength > len)
            break;

        if (hdr->bDescriptorType == USB_DT_INTERFACE) {
            const struct usb_interface_descriptor *id =
                (const struct usb_interface_descriptor *)(buf + off);

            pr_info("usb_proxy:  -> Interface %u: %s\n",
                    id->bInterfaceNumber,
                    rg_usb_class_name(id->bInterfaceClass));
        }

        off += hdr->bLength;
    }
}

static bool is_android_vid(u16 vid)
{
    switch (vid) {
    case 0x18d1: /* Google / Android */
    case 0x04e8: /* Samsung */
    case 0x12d1: /* Huawei */
    case 0x22b8: /* Motorola */
    case 0x0bb4: /* HTC */
    case 0x2717: /* Xiaomi */
    case 0x2a70: /* OnePlus */
    case 0x2d95: /* Vivo */
    case 0x22d9: /* OPPO */
    case 0x2c3f: /* Nothing / Android-like */
    case 0x0fce: /* Sony */
    case 0x1004: /* LG */
    case 0x19d2: /* ZTE */
    case 0x2a45: /* Meizu */
        return true;
    default:
        return false;
    }
}

static bool is_android_device(struct usb_device *udev)
{
    u16 vid;

    if (!udev)
        return false;

    vid = le16_to_cpu(udev->descriptor.idVendor);
    return is_android_vid(vid);
}

static int rg_handle_control(struct usb_proxy_dev *mdev,
                             const struct usb_ctrlrequest *ctrl)
{
    struct raw_dev *rg = mdev->rg;
    struct usb_device *real = mdev->udev;

    u8  rt     = ctrl->bRequestType;
    u8  req    = ctrl->bRequest;

    u16 wValue = le16_to_cpu(ctrl->wValue);
    u16 wIndex = le16_to_cpu(ctrl->wIndex);
    u16 wLen   = le16_to_cpu(ctrl->wLength);

    bool in = !!(rt & USB_DIR_IN);
    int ret;
    u8 *buf = NULL;

    pr_info("usb_proxy: rg CTRL: %s rt=%02x req=%02x wValue=%04x wIndex=%04x wLen=%u\n",
            in ? "IN " : "OUT",
            rt, req, wValue, wIndex, wLen);

    if (!real) {
        pr_err("usb_proxy: rg: no real device bound\n");
        usb_raw_ep0_stall_k(rg);
        return 0;
    }

    if (wLen) {
        buf = kzalloc(wLen, GFP_KERNEL);
        if (!buf) {
            usb_raw_ep0_stall_k(rg);
            return 0;
        }
    }

    if (!in && wLen) {
        ret = rg_ep0_read_out(rg, buf, wLen);
        if (ret < 0) {
            pr_err("usb_proxy: rg: ep0_read_out failed: %d\n", ret);
            goto out;
        }
        pr_info("usb_proxy: rg: OUT payload received (%d bytes)\n", ret);
    }

    /* -------- STANDARD REQUESTS -------- */
    if ((rt & USB_TYPE_MASK) == USB_TYPE_STANDARD) {
        switch (req) {

        case USB_REQ_GET_DESCRIPTOR: {
            u8 dtype = (wValue >> 8) & 0xff;
            u8 dindex = wValue & 0xff;
            pr_info("usb_proxy: rg: GET_DESCRIPTOR type=%u index=%u\n", dtype, dindex);
            break; /* forward generic below */
        }

        case USB_REQ_SET_ADDRESS:
            pr_info("usb_proxy: rg: SET_ADDRESS %u\n", wValue & 0x7f);
            mdev->rg_address = wValue & 0x7f;
            rg_ep0_ack_out0(rg);
            goto out;

        case USB_REQ_SET_CONFIGURATION: {
            u8 requested_cfg = wValue & 0xff;
            u8 cfg = requested_cfg;
            bool is_iphone = false;

            if (real &&
                le16_to_cpu(real->descriptor.idVendor) == 0x05ac &&
                le16_to_cpu(real->descriptor.idProduct) == 0x12a8) {
                is_iphone = true;
            }

            if (is_iphone && requested_cfg != 0)
                cfg = 4;

            if (is_iphone && mdev->config_locked) {
                pr_info("usb_proxy: rg: iPhone config already locked to %u, ignoring SET_CONFIGURATION %u\n",
                        mdev->rg_config, requested_cfg);

                ret = rg_ep0_ack_out0(rg);
                if (ret < 0)
                    pr_err("usb_proxy: rg: ack ignored SET_CONFIGURATION failed: %d\n", ret);

                goto out;
            }

            pr_info("usb_proxy: rg: SET_CONFIGURATION requested=%u actual=%u\n",
                    requested_cfg, cfg);

            rg_stop_all_eps(mdev);
            mdev->rg_config = cfg;

            if (is_android_device(real)) {
                pr_info("usb_proxy: rg: Android detected, NOT forwarding SET_CONFIGURATION %u to real device\n",
                        cfg);
            } else {
                ret = usb_control_msg(real,
                                    usb_sndctrlpipe(real, 0),
                                    req, rt,
                                    wValue, wIndex,
                                    NULL, 0,
                                    1000);
                if (ret < 0) {
                    pr_err("usb_proxy: rg: forward SET_CONFIGURATION failed: %d\n", ret);
                    usb_raw_ep0_stall_k(rg);
                    goto out;
                }
            }

            if (cfg) {
                ret = usb_raw_configure_k(rg);
                if (ret < 0) {
                    pr_err("usb_proxy: rg: usb_raw_configure_k failed: %d\n", ret);
                    usb_raw_ep0_stall_k(rg);
                    goto out;
                }

                ret = rg_start_eps_for_config(mdev, cfg);
                if (ret < 0) {
                    pr_err("usb_proxy: rg: start eps for config %u failed: %d\n",
                        cfg, ret);
                    usb_raw_ep0_stall_k(rg);
                    goto out;
                }

                if (is_iphone)
                    mdev->config_locked = true;
            }

            ret = rg_ep0_ack_out0(rg);
            if (ret < 0)
                pr_err("usb_proxy: rg: ack SET_CONFIGURATION failed: %d\n", ret);

            goto out;
        }

        case USB_REQ_GET_CONFIGURATION: {
            u8 cfg = mdev->rg_config;
            pr_info("usb_proxy: rg: GET_CONFIGURATION -> %u\n", cfg);

            ret = rg_ep0_write_in(rg, &cfg, min_t(u16, wLen, 1));
            if (ret < 0) {
                pr_err("usb_proxy: rg: ep0_write_in(GET_CONFIGURATION) failed: %d\n", ret);
                usb_raw_ep0_stall_k(rg);
                goto out;
            }

            ret = rg_ep0_ack_in_status(rg);
            if (ret < 0)
                pr_err("usb_proxy: rg: IN status ack failed (GET_CONFIGURATION): %d\n", ret);

            goto out;
        }

        case USB_REQ_GET_STATUS: {
            u8 st[2] = { 0x00, 0x00 };
            pr_info("usb_proxy: rg: GET_STATUS\n");

            ret = rg_ep0_write_in(rg, st, min_t(u16, wLen, 2));
            if (ret < 0) {
                pr_err("usb_proxy: rg: ep0_write_in(GET_STATUS) failed: %d\n", ret);
                usb_raw_ep0_stall_k(rg);
                goto out;
            }

            ret = rg_ep0_ack_in_status(rg);
            if (ret < 0)
                pr_err("usb_proxy: rg: IN status ack failed (GET_STATUS): %d\n", ret);

            goto out;
        }

        default:
            pr_info("usb_proxy: rg: STANDARD req %02x not special-cased\n", req);
            break; /* forward generic below */
        }
    }

    /* -------- FORWARD GENERIC REQUEST -------- */
    pr_info("usb_proxy: rg: forward ctrl request to real device\n");

    ret = usb_control_msg(real,
                          in ? usb_rcvctrlpipe(real, 0)
                             : usb_sndctrlpipe(real, 0),
                          req,
                          rt,
                          wValue,
                          wIndex,
                          buf,
                          wLen,
                          1000);

    if (ret < 0) {
        pr_err("usb_proxy: rg: usb_control_msg failed: %d\n", ret);
        usb_raw_ep0_stall_k(rg);
        goto out;
    }

    if (in) {
        u32 n = min_t(u32, ret, wLen);

        /* bMaxPacketSize0 quirk */
        if ((rt & USB_TYPE_MASK) == USB_TYPE_STANDARD &&
            req == USB_REQ_GET_DESCRIPTOR &&
            ((wValue >> 8) & 0xff) == USB_DT_DEVICE &&
            n >= USB_DT_DEVICE_SIZE) {

            struct usb_device_descriptor *dd =
                (struct usb_device_descriptor *)buf;

            if (dd->bMaxPacketSize0 < 64) {
                pr_info("usb_proxy: rg: fixing bMaxPacketSize0 %u -> 64\n",
                        dd->bMaxPacketSize0);
                dd->bMaxPacketSize0 = 64;
            }
        }

        if ((rt & USB_TYPE_MASK) == USB_TYPE_STANDARD &&
            req == USB_REQ_GET_DESCRIPTOR) {
            u8 dtype = (wValue >> 8) & 0xff;

            if (dtype == USB_DT_DEVICE) {
                rg_log_device_desc_simple(buf, n);
            } else if (dtype == USB_DT_CONFIG) {
                rg_log_config_interfaces_simple(buf, n);
            }
        }

        pr_info("usb_proxy: rg: EP0 IN reply %u bytes\n", n);

        ret = rg_ep0_write_in(rg, buf, n);
        if (ret < 0) {
            pr_err("usb_proxy: rg: ep0_write_in failed: %d\n", ret);
            usb_raw_ep0_stall_k(rg);
            goto out;
        }

        ret = rg_ep0_ack_in_status(rg);
        if (ret < 0)
            pr_err("usb_proxy: rg: IN status ack failed: %d\n", ret);

    } else {
        if (wLen == 0) {
            pr_info("usb_proxy: rg: EP0 OUT status ACK\n");
            rg_ep0_ack_out0(rg);
        } else {

        }
    }

out:
    kfree(buf);
    return 0;
}

static int rg_thread_fn(void *arg)
{
    struct usb_proxy_dev *mdev = arg;
    struct usb_raw_event *ev;

    ev = kzalloc(sizeof(*ev) + 512, GFP_KERNEL);
    if (!ev)
        return -ENOMEM;

    ev->length = 512;

    while (!kthread_should_stop()) {
        int ret = usb_raw_event_fetch_k(mdev->rg, ev);

        if (ret == -EINTR)
            continue;
        if (ret < 0) {
            pr_err("usb_proxy: raw_gadget: event_fetch failed: %d\n", ret);
            break;
        }

        switch (ev->type) {
        case USB_RAW_EVENT_CONNECT:
            pr_info("usb_proxy: raw_gadget: CONNECT!\n");
            break;

        case USB_RAW_EVENT_CONTROL: {
            const struct usb_ctrlrequest *ctrl;

            pr_info("usb_proxy: raw_gadget: event control!\n");
            ctrl = (const struct usb_ctrlrequest *)ev->data;
            rg_handle_control(mdev, ctrl);
            break;
        }

        case USB_RAW_EVENT_RESET:
            pr_info("usb_proxy: raw_gadget: RESET\n");

            /* reset state */
            mdev->rg_address = 0;
            mdev->rg_config  = 0;

            pr_info("usb_proxy: raw_gadget: RESET cleanup done\n");
            break;

        case USB_RAW_EVENT_DISCONNECT:
            pr_info("usb_proxy: raw_gadget: DISCONNECT\n");

            mdev->rg_address = 0;
            mdev->rg_config  = 0;

            pr_info("usb_proxy: raw_gadget: DISCONNECT cleanup done\n");
            break;

        case USB_RAW_EVENT_SUSPEND:
            pr_info("usb_proxy: raw_gadget: SUSPEND\n");
            break;

        case USB_RAW_EVENT_RESUME:
            pr_info("usb_proxy: raw_gadget: RESUME\n");
            break;

        default:
            pr_info("usb_proxy: raw_gadget: event type=%u\n", ev->type);
            break;
        }

        ev->length = 512;
    }

    kfree(ev);
    return 0;
}

static int usb_proxy_probe(struct usb_interface *intf, const struct usb_device_id *id)
{
    struct usb_device *udev = interface_to_usbdev(intf);
    struct usb_proxy_dev *dev;
    struct usb_host_interface *alt = intf->cur_altsetting;
    int ret;

    if (!alt || alt->desc.bInterfaceNumber != 0) {
        dev_info(&intf->dev,
                 "usb_proxy: skipping interface %u, proxy already handled on interface 0\n",
                 alt ? alt->desc.bInterfaceNumber : 0xff);
        return -ENODEV;
    }

    ret = usb_proxy_check_policy(udev, &intf->dev);
    if (ret) {
        dev_warn(&intf->dev,
                "usb_proxy: device rejected by policy, probe aborted\n");
        return ret;
    }
    

    dev = kzalloc(sizeof(*dev), GFP_KERNEL);
    if (!dev)
        return -ENOMEM;

    mutex_init(&dev->stop_lock);
    dev->eps_stopped = true;

    dev->udev = usb_get_dev(udev);
    dev->intf = intf;

    dev->rg = NULL;
    dev->rg_thread = NULL;
    dev->rg_address = 0;
    dev->rg_config = 0;
    dev->rg_running = false;
    dev->config_locked = false;

    usb_set_intfdata(intf, dev);

    mutex_lock(&lock);
    if (g_dev) {
        mutex_unlock(&lock);
        dev_warn(&intf->dev, "usb_proxy: another device already active\n");
        ret = -EBUSY;
        goto err_out;
    }
    g_dev = dev;
    mutex_unlock(&lock);

    dev_info(&intf->dev, "usb_proxy: probe OK VID=%04x PID=%04x\n",
             le16_to_cpu(udev->descriptor.idVendor),
             le16_to_cpu(udev->descriptor.idProduct));

    {
        int r;

        r = usb_lock_device_for_reset(udev, intf);
        if (r < 0) {
            dev_warn(&intf->dev, "usb_proxy: lock_device_for_reset failed: %d\n", r);
        } else {
            r = usb_reset_device(udev);
            usb_unlock_device(udev);
            dev_info(&intf->dev, "usb_proxy: usb_reset_device ret=%d\n", r);
        }
    }

    /* ---- start raw gadget on UDC ---- */
    dev->rg = usb_raw_open_k();
    if (!dev->rg) {
        dev_err(&intf->dev, "usb_proxy: raw_gadget: usb_raw_open_k failed\n");
        ret = -ENOMEM;
        goto err_out;
    }

    ret = usb_raw_init_k(dev->rg, USB_SPEED_HIGH, udc_name, udc_name);
    if (ret) {
        dev_err(&intf->dev, "usb_proxy: raw_gadget: usb_raw_init_k failed: %d\n", ret);
        goto err_rg;
    }

    ret = usb_raw_run_k(dev->rg);
    if (ret) {
        dev_err(&intf->dev, "usb_proxy: raw_gadget: usb_raw_run_k failed: %d\n", ret);
        goto err_rg;
    }

    dev->rg_running = true;

    dev->rg_thread = kthread_run(rg_thread_fn, dev, "rg_loop");
    if (IS_ERR(dev->rg_thread)) {
        ret = PTR_ERR(dev->rg_thread);
        dev->rg_thread = NULL;
        dev_err(&intf->dev, "usb_proxy: raw_gadget: kthread_run failed: %d\n", ret);
        goto err_rg_stop;
    }

    dev_info(&intf->dev, "usb_proxy: raw_gadget started on UDC=%s\n",
             udc_name);

    return 0;

err_rg_stop:
    dev->rg_running = false;
err_rg:
    if (dev->rg) {
        usb_raw_close_k(dev->rg);
        dev->rg = NULL;
    }
err_out:
    mutex_lock(&lock);
    if (g_dev == dev)
        g_dev = NULL;
    mutex_unlock(&lock);

    usb_set_intfdata(intf, NULL);

    if (dev->udev)
        usb_put_dev(dev->udev);
    kfree(dev);

    return ret;
}

static void usb_proxy_disconnect(struct usb_interface *intf)
{
    struct usb_proxy_dev *dev = usb_get_intfdata(intf);

    usb_set_intfdata(intf, NULL);

    mutex_lock(&lock);
    if (g_dev == dev)
        g_dev = NULL;
    mutex_unlock(&lock);

    if (!dev)
        return;

    if (!IS_ERR_OR_NULL(dev->rg_thread)) {
        struct task_struct *t = dev->rg_thread;
        dev->rg_thread = NULL;
        kthread_stop(t);
    }

    if (dev->rg) {
        usb_raw_close_k(dev->rg);
        dev->rg = NULL;
    }

    dev->rg_running = false;

    if (dev->udev) {
        usb_put_dev(dev->udev);
        dev->udev = NULL;
    }

    kfree(dev);

    dev_info(&intf->dev, "usb_proxy: disconnect\n");
}

static struct usb_device_id usb_proxy_table[] = {
    { USB_DEVICE(0x0000, 0x0000) },
    { }
};
MODULE_DEVICE_TABLE(usb, usb_proxy_table);

static struct usb_driver usb_proxy_driver = {
    .name       = "usb_proxy",
    .probe      = usb_proxy_probe,
    .disconnect = usb_proxy_disconnect,
    .id_table   = usb_proxy_table,
};

static int __init usb_proxy_init(void)
{
    int ret;

    mutex_init(&lock);
    g_dev = NULL;

    if (!vid || !pid) {
        pr_err("usb_proxy: load with vid=0x.... pid=0x....\n");
        return -EINVAL;
    }

    if (!udc_name || !*udc_name) {
        pr_err("usb_proxy: load with udc_name=... (from /sys/class/udc)\n");
        return -EINVAL;
    }

    pr_info("usb_proxy: params: target=%04x:%04x udc_name=%s\n",
            vid, pid, udc_name);

    usb_proxy_table[0].match_flags = USB_DEVICE_ID_MATCH_VENDOR |
                                USB_DEVICE_ID_MATCH_PRODUCT;
    usb_proxy_table[0].idVendor  = cpu_to_le16(vid);
    usb_proxy_table[0].idProduct = cpu_to_le16(pid);

    ret = misc_register(&usb_proxy_miscdev);
    if (ret) {
        pr_err("usb_proxy: misc_register failed: %d\n", ret);
        return ret;
    }

    ret = usb_register(&usb_proxy_driver);
    if (ret) {
        pr_err("usb_proxy: usb_register failed: %d\n", ret);
        misc_deregister(&usb_proxy_miscdev);
        return ret;
    }

    pr_info("usb_proxy: loaded. /dev/%s (write: desc|status|ctrl). Target=%04x:%04x\n",
            DEVNODE_NAME, vid, pid);

    ret = usb_packet_inspector_sysfs_init();
    if (ret) {
        pr_err("usb_proxy: packet inspector init failed: %d\n", ret);
        usb_deregister(&usb_proxy_driver);
        misc_deregister(&usb_proxy_miscdev);
        return ret;
    }

    ret = usb_proxy_policy_init();
    if (ret) {
        pr_err("usb_proxy: policy init failed: %d\n", ret);
        usb_packet_inspector_sysfs_exit();
        usb_deregister(&usb_proxy_driver);
        misc_deregister(&usb_proxy_miscdev);
        return ret;
    }

    return 0;
}

static void __exit usb_proxy_exit(void)
{
    usb_deregister(&usb_proxy_driver);

    misc_deregister(&usb_proxy_miscdev);

    mutex_lock(&lock);
    g_dev = NULL;
    mutex_unlock(&lock);

    pr_info("usb_proxy: unloaded\n");
    
    usb_packet_inspector_sysfs_exit();
    usb_proxy_policy_exit();

}

module_init(usb_proxy_init);
module_exit(usb_proxy_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Madalin Vasile");
MODULE_DESCRIPTION("Kernel-level USB proxy control interface");