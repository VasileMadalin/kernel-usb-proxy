// SPDX-License-Identifier: GPL-2.0
/*
 * USB Policy Engine
 *
 * Implements descriptor-based USB policy enforcement for the
 * kernel-level USB proxy. The module evaluates USB descriptors
 * and interface combinations to determine whether a device should
 * be allowed or blocked before enumeration.
 *
 * Copyright (c) 2026 Madalin Vasile
 * Author: Madalin Vasile
 */
 
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/usb.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/stddef.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/init.h>

#include "usb_policy_engine.h"

#ifndef USB_CLASS_IMAGE
#define USB_CLASS_IMAGE 0x06
#endif

enum usb_proxy_policy_action {
    USB_PROXY_POLICY_ALLOW = 0,
    USB_PROXY_POLICY_DENY,
    USB_PROXY_POLICY_LOG,
};

enum usb_proxy_rule_type {
    USB_PROXY_RULE_VID_PID = 0,
    USB_PROXY_RULE_INTERFACE_CLASS_COUNT,
    USB_PROXY_RULE_INTERFACE_COMBINATION,
    USB_PROXY_RULE_INTERFACE_COUNT_GT,
};

struct usb_proxy_policy_rule {
    int id;
    enum usb_proxy_policy_action action;
    enum usb_proxy_rule_type type;

    union {
        struct {
            __u16 vid;
            __u16 pid;
        } vid_pid;

        struct {
            __u8 interface_class;
            int interface_count;
        } if_class_count;

        struct {
            __u8 class1;
            __u8 class2;
        } if_combo;

        struct {
            int interface_count_gt;
        } if_count_gt;
    } u;
};

struct usb_proxy_dynamic_rule {
    struct list_head list;
    struct usb_proxy_policy_rule rule;
};

static const struct usb_proxy_policy_rule usb_proxy_default_rules[] = {
    
};

#define USB_PROXY_DEFAULT_RULE_COUNT ARRAY_SIZE(usb_proxy_default_rules)

static LIST_HEAD(usb_proxy_dynamic_rules);
static DEFINE_MUTEX(usb_proxy_policy_lock);
static struct kobject *usb_proxy_policy_kobj;
static enum usb_proxy_policy_action usb_proxy_default_action = USB_PROXY_POLICY_ALLOW;

static const char *usb_proxy_action_name(enum usb_proxy_policy_action action)
{
    switch (action) {
    case USB_PROXY_POLICY_ALLOW:
        return "ALLOW";
    case USB_PROXY_POLICY_DENY:
        return "DENY";
    case USB_PROXY_POLICY_LOG:
        return "LOG";
    default:
        return "UNKNOWN";
    }
}

static const char *usb_proxy_class_name(__u8 cls)
{
    switch (cls) {
    case USB_CLASS_PER_INTERFACE:
        return "PER_INTERFACE";
    case USB_CLASS_AUDIO:
        return "AUDIO";
    case USB_CLASS_COMM:
        return "COMM";
    case USB_CLASS_HID:
        return "HID";
    case USB_CLASS_PHYSICAL:
        return "PHYSICAL";
    case USB_CLASS_STILL_IMAGE:
        return "IMAGE";
    case USB_CLASS_PRINTER:
        return "PRINTER";
    case USB_CLASS_MASS_STORAGE:
        return "MASS_STORAGE";
    case USB_CLASS_HUB:
        return "HUB";
    case USB_CLASS_CDC_DATA:
        return "CDC_DATA";
    case USB_CLASS_CSCID:
        return "SMART_CARD";
    case USB_CLASS_CONTENT_SEC:
        return "CONTENT_SECURITY";
    case USB_CLASS_VIDEO:
        return "VIDEO";
    case USB_CLASS_WIRELESS_CONTROLLER:
        return "WIRELESS";
    case USB_CLASS_MISC:
        return "MISC";
    case USB_CLASS_APP_SPEC:
        return "APPLICATION_SPECIFIC";
    case USB_CLASS_VENDOR_SPEC:
        return "VENDOR_SPECIFIC";
    default:
        return "UNKNOWN";
    }
}

static int usb_proxy_parse_action(const char *s, enum usb_proxy_policy_action *action)
{
    if (!s || !action)
        return -EINVAL;

    if (!strcmp(s, "ALLOW")) {
        *action = USB_PROXY_POLICY_ALLOW;
        return 0;
    }
    if (!strcmp(s, "DENY")) {
        *action = USB_PROXY_POLICY_DENY;
        return 0;
    }
    if (!strcmp(s, "LOG")) {
        *action = USB_PROXY_POLICY_LOG;
        return 0;
    }

    return -EINVAL;
}

static int usb_proxy_parse_class(const char *s, __u8 *cls)
{
    if (!s || !cls)
        return -EINVAL;

    if (!strcmp(s, "HID")) {
        *cls = USB_CLASS_HID;
        return 0;
    }
    if (!strcmp(s, "MASS_STORAGE")) {
        *cls = USB_CLASS_MASS_STORAGE;
        return 0;
    }
    if (!strcmp(s, "IMAGE")) {
        *cls = USB_CLASS_IMAGE;
        return 0;
    }
    if (!strcmp(s, "VIDEO")) {
        *cls = USB_CLASS_VIDEO;
        return 0;
    }
    if (!strcmp(s, "HUB")) {
        *cls = USB_CLASS_HUB;
        return 0;
    }
    if (!strcmp(s, "VENDOR_SPECIFIC")) {
        *cls = USB_CLASS_VENDOR_SPEC;
        return 0;
    }

    return -EINVAL;
}

static int usb_proxy_get_interface_count(struct usb_device *udev)
{
    if (!udev || !udev->actconfig)
        return 0;

    return udev->actconfig->desc.bNumInterfaces;
}

static bool usb_proxy_has_interface_class(struct usb_device *udev, __u8 if_class)
{
    struct usb_host_config *cfg;
    int i;

    if (!udev || !udev->actconfig)
        return false;

    cfg = udev->actconfig;

    for (i = 0; i < cfg->desc.bNumInterfaces; i++) {
        struct usb_interface_cache *intfc;
        struct usb_host_interface *alt;

        intfc = cfg->intf_cache[i];
        if (!intfc || intfc->num_altsetting < 1)
            continue;

        alt = &intfc->altsetting[0];
        if (alt->desc.bInterfaceClass == if_class)
            return true;
    }

    return false;
}

static bool usb_proxy_has_interface_combination(struct usb_device *udev,
                                            __u8 class1, __u8 class2)
{
    return usb_proxy_has_interface_class(udev, class1) &&
           usb_proxy_has_interface_class(udev, class2);
}

static void usb_proxy_log_interfaces(struct usb_device *udev, struct device *logdev)
{
    struct usb_host_config *cfg;
    int i;

    if (!udev || !udev->actconfig || !logdev)
        return;

    cfg = udev->actconfig;

    dev_info(logdev,
             "usb_proxy: active config=%u, interfaces=%u\n",
             cfg->desc.bConfigurationValue,
             cfg->desc.bNumInterfaces);

    for (i = 0; i < cfg->desc.bNumInterfaces; i++) {
        struct usb_interface_cache *intfc;
        struct usb_host_interface *alt;

        intfc = cfg->intf_cache[i];
        if (!intfc || intfc->num_altsetting < 1) {
            dev_info(logdev, "usb_proxy: interface[%d]: unavailable\n", i);
            continue;
        }

        alt = &intfc->altsetting[0];

        dev_info(logdev,
                 "usb_proxy: interface[%d]: number=%u class=0x%02x(%s) subclass=0x%02x protocol=0x%02x endpoints=%u\n",
                 i,
                 alt->desc.bInterfaceNumber,
                 alt->desc.bInterfaceClass,
                 usb_proxy_class_name(alt->desc.bInterfaceClass),
                 alt->desc.bInterfaceSubClass,
                 alt->desc.bInterfaceProtocol,
                 alt->desc.bNumEndpoints);
    }
}

static bool usb_proxy_rule_matches(struct usb_device *udev,
                               const struct usb_proxy_policy_rule *rule)
{
    __u16 vid, pid;
    int if_count;

    if (!udev || !rule)
        return false;

    vid = le16_to_cpu(udev->descriptor.idVendor);
    pid = le16_to_cpu(udev->descriptor.idProduct);
    if_count = usb_proxy_get_interface_count(udev);

    switch (rule->type) {
    case USB_PROXY_RULE_VID_PID:
        return (vid == rule->u.vid_pid.vid &&
                pid == rule->u.vid_pid.pid);

    case USB_PROXY_RULE_INTERFACE_CLASS_COUNT:
        return (if_count == rule->u.if_class_count.interface_count &&
                usb_proxy_has_interface_class(udev,
                                          rule->u.if_class_count.interface_class));

    case USB_PROXY_RULE_INTERFACE_COMBINATION:
        return usb_proxy_has_interface_combination(udev,
                                               rule->u.if_combo.class1,
                                               rule->u.if_combo.class2);

    case USB_PROXY_RULE_INTERFACE_COUNT_GT:
        return if_count > rule->u.if_count_gt.interface_count_gt;

    default:
        return false;
    }
}

static void usb_proxy_log_match_reason(struct usb_device *udev,
                                   struct device *logdev,
                                   const struct usb_proxy_policy_rule *rule)
{
    __u16 vid, pid;
    int if_count;

    if (!udev || !logdev || !rule)
        return;

    vid = le16_to_cpu(udev->descriptor.idVendor);
    pid = le16_to_cpu(udev->descriptor.idProduct);
    if_count = usb_proxy_get_interface_count(udev);

    switch (rule->type) {
    case USB_PROXY_RULE_VID_PID:
        dev_info(logdev,
                 "usb_proxy: matched RULE %d [%s] on VID/PID "
                 "(dev=%04x:%04x rule=%04x:%04x)\n",
                 rule->id, usb_proxy_action_name(rule->action),
                 vid, pid,
                 rule->u.vid_pid.vid,
                 rule->u.vid_pid.pid);
        break;

    case USB_PROXY_RULE_INTERFACE_CLASS_COUNT:
        dev_info(logdev,
                 "usb_proxy: matched RULE %d [%s] on INTERFACE_CLASS=%s(0x%02x), INTERFACE_COUNT=%d\n",
                 rule->id, usb_proxy_action_name(rule->action),
                 usb_proxy_class_name(rule->u.if_class_count.interface_class),
                 rule->u.if_class_count.interface_class,
                 if_count);
        break;

    case USB_PROXY_RULE_INTERFACE_COMBINATION:
        dev_info(logdev,
                 "usb_proxy: matched RULE %d [%s] on INTERFACE_COMBINATION=%s(0x%02x)+%s(0x%02x)\n",
                 rule->id, usb_proxy_action_name(rule->action),
                 usb_proxy_class_name(rule->u.if_combo.class1),
                 rule->u.if_combo.class1,
                 usb_proxy_class_name(rule->u.if_combo.class2),
                 rule->u.if_combo.class2);
        break;

    case USB_PROXY_RULE_INTERFACE_COUNT_GT:
        dev_info(logdev,
                 "usb_proxy: matched RULE %d [%s] on INTERFACE_COUNT=%d > %d\n",
                 rule->id, usb_proxy_action_name(rule->action),
                 if_count,
                 rule->u.if_count_gt.interface_count_gt);
        break;

    default:
        dev_info(logdev,
                 "usb_proxy: matched RULE %d [%s]\n",
                 rule->id, usb_proxy_action_name(rule->action));
        break;
    }
}

static int usb_proxy_apply_rule(struct usb_device *udev, struct device *logdev,
                            const struct usb_proxy_policy_rule *rule)
{
    if (!usb_proxy_rule_matches(udev, rule))
        return 1; /* no match */

    usb_proxy_log_match_reason(udev, logdev, rule);

    switch (rule->action) {
    case USB_PROXY_POLICY_ALLOW:
        dev_info(logdev, "usb_proxy: policy decision -> ALLOW (RULE %d)\n",
                 rule->id);
        return 0;

    case USB_PROXY_POLICY_DENY:
        dev_warn(logdev, "usb_proxy: policy decision -> DENY (RULE %d)\n",
                 rule->id);
        return -EPERM;

    case USB_PROXY_POLICY_LOG:
        dev_info(logdev,
                 "usb_proxy: policy decision -> LOG (RULE %d), continuing evaluation\n",
                 rule->id);
        return 2;
    }

    return 1;
}

/* ------------------------------------------------------------------ */
/* Rule formatting                                                    */
/* ------------------------------------------------------------------ */

static int usb_proxy_format_rule(const struct usb_proxy_policy_rule *rule,
                             char *buf, size_t buflen)
{
    switch (rule->type) {
    case USB_PROXY_RULE_VID_PID:
        return scnprintf(buf, buflen,
                         "RULE %d ACTION=%s VID=0x%04x PID=0x%04x\n",
                         rule->id, usb_proxy_action_name(rule->action),
                         rule->u.vid_pid.vid, rule->u.vid_pid.pid);

    case USB_PROXY_RULE_INTERFACE_CLASS_COUNT:
        return scnprintf(buf, buflen,
                         "RULE %d ACTION=%s INTERFACE_CLASS=%s INTERFACE_COUNT=%d\n",
                         rule->id, usb_proxy_action_name(rule->action),
                         usb_proxy_class_name(rule->u.if_class_count.interface_class),
                         rule->u.if_class_count.interface_count);

    case USB_PROXY_RULE_INTERFACE_COMBINATION:
        return scnprintf(buf, buflen,
                         "RULE %d ACTION=%s INTERFACE_COMBINATION=%s,%s\n",
                         rule->id, usb_proxy_action_name(rule->action),
                         usb_proxy_class_name(rule->u.if_combo.class1),
                         usb_proxy_class_name(rule->u.if_combo.class2));

    case USB_PROXY_RULE_INTERFACE_COUNT_GT:
        return scnprintf(buf, buflen,
                         "RULE %d ACTION=%s INTERFACE_COUNT_GT=%d\n",
                         rule->id, usb_proxy_action_name(rule->action),
                         rule->u.if_count_gt.interface_count_gt);
    }

    return scnprintf(buf, buflen, "RULE %d ACTION=%s UNKNOWN\n",
                     rule->id, usb_proxy_action_name(rule->action));
}

/* ------------------------------------------------------------------ */
/* Parser for sysfs rules                                             */
/* ------------------------------------------------------------------ */

static int usb_proxy_parse_rule_string(const char *input,
                                   struct usb_proxy_policy_rule *rule)
{
    char *work, *p, *tok;
    int ret = -EINVAL;
    bool have_action = false;
    bool have_type = false;

    if (!input || !rule)
        return -EINVAL;

    memset(rule, 0, sizeof(*rule));

    work = kstrdup(input, GFP_KERNEL);
    if (!work)
        return -ENOMEM;

    p = strim(work);

    while ((tok = strsep(&p, " \t\n")) != NULL) {
        char *eq;

        if (!*tok)
            continue;

        if (!strcmp(tok, "RULE"))
            continue;

        if (!strncmp(tok, "ACTION=", 7)) {
            ret = usb_proxy_parse_action(tok + 7, &rule->action);
            if (ret)
                goto out;
            have_action = true;
            continue;
        }

        if (!strncmp(tok, "VID=", 4)) {
            unsigned int v;
            ret = kstrtouint(tok + 4, 0, &v);
            if (ret)
                goto out;
            rule->type = USB_PROXY_RULE_VID_PID;
            rule->u.vid_pid.vid = (__u16)v;
            have_type = true;
            continue;
        }

        if (!strncmp(tok, "PID=", 4)) {
            unsigned int v;
            ret = kstrtouint(tok + 4, 0, &v);
            if (ret)
                goto out;
            rule->type = USB_PROXY_RULE_VID_PID;
            rule->u.vid_pid.pid = (__u16)v;
            have_type = true;
            continue;
        }

        if (!strncmp(tok, "INTERFACE_CLASS=", 16)) {
            ret = usb_proxy_parse_class(tok + 16,
                                    &rule->u.if_class_count.interface_class);
            if (ret)
                goto out;
            rule->type = USB_PROXY_RULE_INTERFACE_CLASS_COUNT;
            have_type = true;
            continue;
        }

        if (!strncmp(tok, "INTERFACE_COUNT=", 16)) {
            ret = kstrtoint(tok + 16, 0, &rule->u.if_class_count.interface_count);
            if (ret)
                goto out;
            rule->type = USB_PROXY_RULE_INTERFACE_CLASS_COUNT;
            have_type = true;
            continue;
        }

        if (!strncmp(tok, "INTERFACE_COMBINATION=", 22)) {
            char *combo, *comma;
            combo = tok + 22;
            comma = strchr(combo, ',');
            if (!comma) {
                ret = -EINVAL;
                goto out;
            }
            *comma = '\0';
            ret = usb_proxy_parse_class(combo, &rule->u.if_combo.class1);
            if (ret)
                goto out;
            ret = usb_proxy_parse_class(comma + 1, &rule->u.if_combo.class2);
            if (ret)
                goto out;
            rule->type = USB_PROXY_RULE_INTERFACE_COMBINATION;
            have_type = true;
            continue;
        }

        if (!strncmp(tok, "INTERFACE_COUNT_GT=", 19)) {
            ret = kstrtoint(tok + 19, 0, &rule->u.if_count_gt.interface_count_gt);
            if (ret)
                goto out;
            rule->type = USB_PROXY_RULE_INTERFACE_COUNT_GT;
            have_type = true;
            continue;
        }

        if (!strncmp(tok, "ID=", 3)) {
            ret = kstrtoint(tok + 3, 0, &rule->id);
            if (ret)
                goto out;
            continue;
        }

        eq = strchr(tok, '=');
        if (!eq) {
            if (!rule->id) {
                ret = kstrtoint(tok, 0, &rule->id);
                if (!ret)
                    continue;
            }
        }

        ret = -EINVAL;
        goto out;
    }

    if (!rule->id)
        rule->id = 1000;

    if (!have_action || !have_type) {
        ret = -EINVAL;
        goto out;
    }

    if (rule->type == USB_PROXY_RULE_VID_PID &&
        (!rule->u.vid_pid.vid || !rule->u.vid_pid.pid)) {
        ret = -EINVAL;
        goto out;
    }

    if (rule->type == USB_PROXY_RULE_INTERFACE_CLASS_COUNT &&
        rule->u.if_class_count.interface_count <= 0) {
        ret = -EINVAL;
        goto out;
    }

    ret = 0;

out:
    kfree(work);
    return ret;
}

static ssize_t rules_show(struct kobject *kobj,
                          struct kobj_attribute *attr, char *buf)
{
    ssize_t len = 0;
    int i;
    struct usb_proxy_dynamic_rule *dr;

    mutex_lock(&usb_proxy_policy_lock);

    len += scnprintf(buf + len, PAGE_SIZE - len, "# Default rules\n");
    for (i = 0; i < USB_PROXY_DEFAULT_RULE_COUNT && len < PAGE_SIZE; i++)
        len += usb_proxy_format_rule(&usb_proxy_default_rules[i],
                                 buf + len, PAGE_SIZE - len);

    len += scnprintf(buf + len, PAGE_SIZE - len, "# Dynamic rules\n");
    list_for_each_entry(dr, &usb_proxy_dynamic_rules, list) {
        if (len >= PAGE_SIZE)
            break;
        len += usb_proxy_format_rule(&dr->rule, buf + len, PAGE_SIZE - len);
    }

    len += scnprintf(buf + len, PAGE_SIZE - len, "DEFAULT ACTION=%s\n",
                     usb_proxy_action_name(usb_proxy_default_action));

    mutex_unlock(&usb_proxy_policy_lock);
    return len;
}

static ssize_t add_rule_store(struct kobject *kobj,
                              struct kobj_attribute *attr,
                              const char *buf, size_t count)
{
    struct usb_proxy_dynamic_rule *dr;
    int ret;

    dr = kzalloc(sizeof(*dr), GFP_KERNEL);
    if (!dr)
        return -ENOMEM;

    ret = usb_proxy_parse_rule_string(buf, &dr->rule);
    if (ret) {
        kfree(dr);
        return ret;
    }

    mutex_lock(&usb_proxy_policy_lock);
    list_add_tail(&dr->list, &usb_proxy_dynamic_rules);
    mutex_unlock(&usb_proxy_policy_lock);

    pr_info("usb_proxy_policy: added dynamic rule %d\n", dr->rule.id);
    return count;
}

static ssize_t clear_rules_store(struct kobject *kobj,
                                 struct kobj_attribute *attr,
                                 const char *buf, size_t count)
{
    struct usb_proxy_dynamic_rule *dr, *tmp;

    mutex_lock(&usb_proxy_policy_lock);
    list_for_each_entry_safe(dr, tmp, &usb_proxy_dynamic_rules, list) {
        list_del(&dr->list);
        kfree(dr);
    }
    mutex_unlock(&usb_proxy_policy_lock);

    pr_info("usb_proxy_policy: cleared dynamic rules\n");
    return count;
}

static ssize_t default_action_show(struct kobject *kobj,
                                   struct kobj_attribute *attr, char *buf)
{
    return scnprintf(buf, PAGE_SIZE, "%s\n",
                     usb_proxy_action_name(usb_proxy_default_action));
}

static ssize_t default_action_store(struct kobject *kobj,
                                    struct kobj_attribute *attr,
                                    const char *buf, size_t count)
{
    char tmp[16];
    enum usb_proxy_policy_action action;
    size_t n = min(count, sizeof(tmp) - 1);

    memcpy(tmp, buf, n);
    tmp[n] = '\0';
    strim(tmp);

    if (usb_proxy_parse_action(tmp, &action))
        return -EINVAL;

    mutex_lock(&usb_proxy_policy_lock);
    usb_proxy_default_action = action;
    mutex_unlock(&usb_proxy_policy_lock);

    pr_info("usb_proxy_policy: default action set to %s\n",
            usb_proxy_action_name(action));
    return count;
}

static struct kobj_attribute rules_attr =
    __ATTR(rules, 0444, rules_show, NULL);
static struct kobj_attribute add_rule_attr =
    __ATTR(add_rule, 0200, NULL, add_rule_store);
static struct kobj_attribute clear_rules_attr =
    __ATTR(clear_rules, 0200, NULL, clear_rules_store);
static struct kobj_attribute default_action_attr =
    __ATTR(default_action, 0644, default_action_show, default_action_store);

static struct attribute *usb_proxy_policy_attrs[] = {
    &rules_attr.attr,
    &add_rule_attr.attr,
    &clear_rules_attr.attr,
    &default_action_attr.attr,
    NULL,
};

static const struct attribute_group usb_proxy_policy_attr_group = {
    .attrs = usb_proxy_policy_attrs,
};

int usb_proxy_check_policy(struct usb_device *udev, struct device *logdev)
{
    __u16 vid, pid;
    int if_count;
    int i, ret;
    struct usb_proxy_dynamic_rule *dr;

    if (!udev || !logdev)
        return -EINVAL;

    vid = le16_to_cpu(udev->descriptor.idVendor);
    pid = le16_to_cpu(udev->descriptor.idProduct);
    if_count = usb_proxy_get_interface_count(udev);

    dev_info(logdev,
             "usb_proxy: policy check start VID=%04x PID=%04x IF_COUNT=%d\n",
             vid, pid, if_count);

    usb_proxy_log_interfaces(udev, logdev);

    for (i = 0; i < USB_PROXY_DEFAULT_RULE_COUNT; i++) {
        ret = usb_proxy_apply_rule(udev, logdev, &usb_proxy_default_rules[i]);
        if (ret == 0 || ret == -EPERM)
            return ret;
    }

    mutex_lock(&usb_proxy_policy_lock);
    list_for_each_entry(dr, &usb_proxy_dynamic_rules, list) {
        ret = usb_proxy_apply_rule(udev, logdev, &dr->rule);
        if (ret == 0 || ret == -EPERM) {
            mutex_unlock(&usb_proxy_policy_lock);
            return ret;
        }
    }

    switch (usb_proxy_default_action) {
    case USB_PROXY_POLICY_ALLOW:
        dev_info(logdev, "usb_proxy: default policy -> ALLOW\n");
        mutex_unlock(&usb_proxy_policy_lock);
        return 0;

    case USB_PROXY_POLICY_DENY:
        dev_warn(logdev, "usb_proxy: default policy -> DENY\n");
        mutex_unlock(&usb_proxy_policy_lock);
        return -EPERM;

    case USB_PROXY_POLICY_LOG:
    default:
        dev_info(logdev, "usb_proxy: default policy -> LOG/ALLOW\n");
        mutex_unlock(&usb_proxy_policy_lock);
        return 0;
    }
}
EXPORT_SYMBOL_GPL(usb_proxy_check_policy);

int usb_proxy_policy_init(void)
{
    int ret;

    usb_proxy_policy_kobj = kobject_create_and_add("usb_proxy", kernel_kobj);
    if (!usb_proxy_policy_kobj)
        return -ENOMEM;

    ret = sysfs_create_group(usb_proxy_policy_kobj, &usb_proxy_policy_attr_group);
    if (ret) {
        kobject_put(usb_proxy_policy_kobj);
        usb_proxy_policy_kobj = NULL;
        return ret;
    }

    pr_info("usb_proxy_policy: sysfs initialized at /sys/kernel/usb_proxy_policy\n");
    return 0;
}
EXPORT_SYMBOL_GPL(usb_proxy_policy_init);

void usb_proxy_policy_exit(void)
{
    struct usb_proxy_dynamic_rule *dr, *tmp;

    mutex_lock(&usb_proxy_policy_lock);
    list_for_each_entry_safe(dr, tmp, &usb_proxy_dynamic_rules, list) {
        list_del(&dr->list);
        kfree(dr);
    }
    mutex_unlock(&usb_proxy_policy_lock);

    if (usb_proxy_policy_kobj) {
        sysfs_remove_group(usb_proxy_policy_kobj, &usb_proxy_policy_attr_group);
        kobject_put(usb_proxy_policy_kobj);
        usb_proxy_policy_kobj = NULL;
    }

    pr_info("usb_proxy_policy: sysfs removed\n");
}
EXPORT_SYMBOL_GPL(usb_proxy_policy_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Madalin Vasile");
MODULE_DESCRIPTION("USB policy engine with default and dynamic filtering rules");