# Modified USB Raw Gadget

## Overview

This directory contains a modified version of the Linux USB Raw Gadget implementation originally developed by Andrey Konovalov.

Original project:

https://github.com/xairy/raw-gadget

The original implementation provides a userspace interface for creating and controlling USB gadgets through the Linux USB Gadget framework.

---

## Purpose of the Modifications

The original Raw Gadget implementation was adapted to support the kernel-level USB proxy presented in the accompanying IEEE Access manuscript.

The primary objective of these modifications is to eliminate the dependency on userspace communication and provide a direct in-kernel interface that can be used by the USB proxy modules.

---

## Main Modifications

The following changes were introduced:

- Added an internal kernel API for direct interaction with Raw Gadget.
- Removed the dependency on userspace IOCTL communication required by the original implementation.
- Added support for direct kernel-space request forwarding.
- Exposed internal functions required by the USB proxy.
- Integrated the implementation with the USB proxy control module.

The internal API exposed by these modifications is declared in `raw_gadget_kapi.h`.

---

## License

The original Raw Gadget implementation is distributed under the GPL-2.0 license.

The modified files retain their original license and copyright notices.