// SPDX-License-Identifier: GPL-2.0
/*
 * USB Packet Inspector
 *
 * Kernel-level USB packet inspection module used by the USB proxy.
 * Implements packet filtering and behavioral analysis to detect
 * suspicious USB traffic exchanged between the host system and
 * connected USB devices.
 *
 * Copyright (c) 2026 Madalin Vasile
 * Author: Madalin Vasile
 */

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/usb.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/errno.h>
#include <linux/types.h>

#include "usb_packet_inspector.h"

#define MAX_KEYWORDS       64
#define MAX_KEYWORD_LEN    128
#define SYSFS_BUF_SZ       1024

struct inspector_keyword {
    char *word;
};

static struct inspector_keyword watched_keywords[MAX_KEYWORDS];
static int watched_keywords_count;

static DEFINE_MUTEX(keywords_lock);

static struct kobject *inspector_kobj;


static const char * const default_keywords[] = {
    "OPEN",
};

static void free_keywords_locked(void)
{
    int i;

    for (i = 0; i < watched_keywords_count; i++) {
        kfree(watched_keywords[i].word);
        watched_keywords[i].word = NULL;
    }

    watched_keywords_count = 0;
}

static bool keyword_exists_locked(const char *word)
{
    int i;

    if (!word)
        return false;

    for (i = 0; i < watched_keywords_count; i++) {
        if (!watched_keywords[i].word)
            continue;

        if (!strcmp(watched_keywords[i].word, word))
            return true;
    }

    return false;
}

static int add_keyword_locked(const char *word)
{
    size_t len;
    char *copy;

    if (!word)
        return -EINVAL;

    len = strlen(word);

    if (len == 0)
        return -EINVAL;

    if (len >= MAX_KEYWORD_LEN)
        return -E2BIG;

    if (watched_keywords_count >= MAX_KEYWORDS)
        return -ENOSPC;

    if (keyword_exists_locked(word))
        return -EEXIST;

    copy = kstrdup(word, GFP_KERNEL);
    if (!copy)
        return -ENOMEM;

    watched_keywords[watched_keywords_count].word = copy;
    watched_keywords_count++;

    return 0;
}

static void trim_inplace(char *s)
{
    char *start;
    char *end;

    if (!s || !*s)
        return;

    start = s;

    while (*start && isspace((unsigned char)*start))
        start++;

    if (start != s)
        memmove(s, start, strlen(start) + 1);

    if (!*s)
        return;

    end = s + strlen(s) - 1;

    while (end >= s && isspace((unsigned char)*end)) {
        *end = '\0';
        end--;
    }
}

static int replace_keywords_locked(const char *input)
{
    char *tmp;
    char *cursor;
    char *token;
    int ret = 0;

    if (!input)
        return -EINVAL;

    tmp = kstrdup(input, GFP_KERNEL);
    if (!tmp)
        return -ENOMEM;

    free_keywords_locked();

    cursor = tmp;

    while ((token = strsep(&cursor, ",\n")) != NULL) {
        trim_inplace(token);

        if (!*token)
            continue;

        ret = add_keyword_locked(token);

        if (ret == -EEXIST) {
            pr_warn("usb_packet_inspector: duplicate keyword '%s' ignored\n",
                    token);
            ret = 0;
            continue;
        }

        if (ret) {
            pr_warn("usb_packet_inspector: failed to add keyword '%s': %d\n",
                    token, ret);
            break;
        }
    }

    kfree(tmp);
    return ret;
}

static int load_default_keywords(void)
{
    int i;
    int ret = 0;

    mutex_lock(&keywords_lock);

    free_keywords_locked();

    for (i = 0; i < ARRAY_SIZE(default_keywords); i++) {
        ret = add_keyword_locked(default_keywords[i]);
        if (ret)
            break;
    }

    mutex_unlock(&keywords_lock);

    return ret;
}

static const void *inspector_memmem(const void *haystack,
                                    size_t haystack_len,
                                    const void *needle,
                                    size_t needle_len)
{
    const unsigned char *h = haystack;
    size_t i;

    if (!haystack || !needle)
        return NULL;

    if (needle_len == 0 || haystack_len < needle_len)
        return NULL;

    for (i = 0; i <= haystack_len - needle_len; i++) {
        if (!memcmp(h + i, needle, needle_len))
            return h + i;
    }

    return NULL;
}

static const char *transfer_type_name(u8 xfer_type)
{
    switch (xfer_type) {
    case USB_ENDPOINT_XFER_BULK:
        return "BULK OUT";

    case USB_ENDPOINT_XFER_INT:
        return "INTERRUPT OUT";

    case USB_ENDPOINT_XFER_CONTROL:
        return "CONTROL OUT";

    case USB_ENDPOINT_XFER_ISOC:
        return "ISOCHRONOUS OUT";

    default:
        return "UNKNOWN OUT";
    }
}

static void log_usb_payload_human(const char *type_name,
                                  const void *buf,
                                  int len)
{
    const unsigned char *payload = buf;
    char line[81];
    int i;
    int j;

    if (!buf || len <= 0)
        return;

    if (!type_name)
        type_name = "USB OUT";

    for (i = 0; i < len; i += 80) {
        int chunk = min(80, len - i);

        for (j = 0; j < chunk; j++) {
            unsigned char c = payload[i + j];

            line[j] = isprint(c) ? c : '.';
        }

        line[chunk] = '\0';

        pr_info("usb_packet_inspector: %s ASCII [%04d]: %s\n",
                type_name, i, line);
    }

    print_hex_dump(KERN_INFO,
                   "usb_packet_inspector: OUT HEX: ",
                   DUMP_PREFIX_OFFSET,
                   16,
                   1,
                   buf,
                   len,
                   true);
}

int inspect_usb_out_packet(const void *buf, int len, u8 xfer_type)
{
    const char *matched_keyword = NULL;
    const char *type_name;
    int i;

    if (!buf || len <= 0)
        return 0;

    if (xfer_type != USB_ENDPOINT_XFER_BULK &&
        xfer_type != USB_ENDPOINT_XFER_INT)
        return 0;

    type_name = transfer_type_name(xfer_type);

    mutex_lock(&keywords_lock);

    for (i = 0; i < watched_keywords_count; i++) {
        const char *keyword = watched_keywords[i].word;
        size_t keyword_len;

        if (!keyword)
            continue;

        keyword_len = strlen(keyword);

        if (keyword_len == 0)
            continue;

        if (len >= keyword_len &&
            inspector_memmem(buf,
                             len,
                             keyword,
                             keyword_len)) {
            matched_keyword = keyword;

            pr_err("usb_packet_inspector: BLOCK keyword '%s' in %s, len=%d\n",
                   keyword,
                   type_name,
                   len);

            break;
        }
    }

    if (matched_keyword) {
        mutex_unlock(&keywords_lock);

        log_usb_payload_human(type_name, buf, len);
        return -EPERM;
    }

    mutex_unlock(&keywords_lock);
    return 0;
}

int inspect_interrupt_out_packet(const void *buf, int len)
{
    return inspect_usb_out_packet(buf,
                                  len,
                                  USB_ENDPOINT_XFER_INT);
}

static ssize_t add_keyword_store(struct kobject *kobj,
                                 struct kobj_attribute *attr,
                                 const char *buf,
                                 size_t count)
{
    char *tmp;
    int ret;

    if (!buf || count == 0)
        return -EINVAL;

    if (count >= MAX_KEYWORD_LEN)
        return -E2BIG;

    tmp = kmalloc(count + 1, GFP_KERNEL);
    if (!tmp)
        return -ENOMEM;

    memcpy(tmp, buf, count);
    tmp[count] = '\0';

    trim_inplace(tmp);

    if (!*tmp) {
        kfree(tmp);
        return -EINVAL;
    }

    mutex_lock(&keywords_lock);
    ret = add_keyword_locked(tmp);
    mutex_unlock(&keywords_lock);

    if (ret == -EEXIST) {
        pr_warn("usb_packet_inspector: keyword '%s' already exists\n",
                tmp);
        kfree(tmp);
        return ret;
    }

    if (ret) {
        pr_warn("usb_packet_inspector: failed to add keyword '%s': %d\n",
                tmp, ret);
        kfree(tmp);
        return ret;
    }

    pr_info("usb_packet_inspector: keyword '%s' added\n", tmp);

    kfree(tmp);
    return count;
}

static ssize_t watch_keywords_show(struct kobject *kobj,
                                   struct kobj_attribute *attr,
                                   char *buf)
{
    ssize_t pos = 0;
    int i;

    mutex_lock(&keywords_lock);

    for (i = 0; i < watched_keywords_count; i++) {
        const char *word = watched_keywords[i].word;
        ssize_t written;

        if (!word)
            continue;

        written = scnprintf(buf + pos,
                            PAGE_SIZE - pos,
                            "%s%s",
                            word,
                            i == watched_keywords_count - 1
                                ? "\n"
                                : ",");

        pos += written;

        if (pos >= PAGE_SIZE - 1)
            break;
    }

    if (watched_keywords_count == 0)
        pos += scnprintf(buf + pos, PAGE_SIZE - pos, "\n");

    mutex_unlock(&keywords_lock);

    return pos;
}

static ssize_t watch_keywords_store(struct kobject *kobj,
                                    struct kobj_attribute *attr,
                                    const char *buf,
                                    size_t count)
{
    char *tmp;
    int ret;

    if (!buf || count == 0)
        return -EINVAL;

    if (count >= SYSFS_BUF_SZ)
        return -E2BIG;

    tmp = kmalloc(count + 1, GFP_KERNEL);
    if (!tmp)
        return -ENOMEM;

    memcpy(tmp, buf, count);
    tmp[count] = '\0';

    mutex_lock(&keywords_lock);
    ret = replace_keywords_locked(tmp);
    mutex_unlock(&keywords_lock);

    kfree(tmp);

    if (ret)
        return ret;

    pr_info("usb_packet_inspector: keyword configuration replaced\n");

    return count;
}

static ssize_t clear_keywords_store(struct kobject *kobj,
                                    struct kobj_attribute *attr,
                                    const char *buf,
                                    size_t count)
{
    if (!buf || count == 0)
        return -EINVAL;

    mutex_lock(&keywords_lock);
    free_keywords_locked();
    mutex_unlock(&keywords_lock);

    pr_info("usb_packet_inspector: keyword list cleared\n");

    return count;
}

static ssize_t reset_keywords_store(struct kobject *kobj,
                                    struct kobj_attribute *attr,
                                    const char *buf,
                                    size_t count)
{
    int ret;

    if (!buf || count == 0)
        return -EINVAL;

    ret = load_default_keywords();
    if (ret)
        return ret;

    pr_info("usb_packet_inspector: default keyword configuration restored\n");

    return count;
}

static struct kobj_attribute add_keyword_attr =
    __ATTR(add_keyword,
           0220,
           NULL,
           add_keyword_store);

static struct kobj_attribute watch_keywords_attr =
    __ATTR(watch_keywords,
           0664,
           watch_keywords_show,
           watch_keywords_store);

static struct kobj_attribute clear_keywords_attr =
    __ATTR(clear_keywords,
           0220,
           NULL,
           clear_keywords_store);

static struct kobj_attribute reset_keywords_attr =
    __ATTR(reset_keywords,
           0220,
           NULL,
           reset_keywords_store);

static struct attribute *inspector_attrs[] = {
    &add_keyword_attr.attr,
    &watch_keywords_attr.attr,
    &clear_keywords_attr.attr,
    &reset_keywords_attr.attr,
    NULL,
};

static const struct attribute_group inspector_attr_group = {
    .attrs = inspector_attrs,
};

int usb_packet_inspector_sysfs_init(void)
{
    int ret;

    ret = load_default_keywords();
    if (ret) {
        pr_err("usb_packet_inspector: failed to load default keywords: %d\n",
               ret);
        return ret;
    }

    inspector_kobj = kobject_create_and_add("inspector", kernel_kobj);
    if (!inspector_kobj) {
        pr_err("usb_packet_inspector: failed to create sysfs kobject\n");

        mutex_lock(&keywords_lock);
        free_keywords_locked();
        mutex_unlock(&keywords_lock);

        return -ENOMEM;
    }

    ret = sysfs_create_group(inspector_kobj,
                             &inspector_attr_group);
    if (ret) {
        pr_err("usb_packet_inspector: failed to create sysfs group: %d\n",
               ret);

        kobject_put(inspector_kobj);
        inspector_kobj = NULL;

        mutex_lock(&keywords_lock);
        free_keywords_locked();
        mutex_unlock(&keywords_lock);

        return ret;
    }

    pr_info("usb_packet_inspector: sysfs ready at /sys/kernel/inspector/\n");

    return 0;
}

void usb_packet_inspector_sysfs_exit(void)
{
    if (inspector_kobj) {
        sysfs_remove_group(inspector_kobj,
                           &inspector_attr_group);

        kobject_put(inspector_kobj);
        inspector_kobj = NULL;
    }

    mutex_lock(&keywords_lock);
    free_keywords_locked();
    mutex_unlock(&keywords_lock);

    pr_info("usb_packet_inspector: stopped\n");
}