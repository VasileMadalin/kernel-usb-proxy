# Kernel-Level USB Proxy for Linux

## Overview

This repository contains the reference implementation of a kernel-level USB proxy for Linux developed as part of the research presented in the IEEE Access manuscript *"A Linux Kernel USB Proxy with Integrated Threat Detection"*.

The implementation transparently mediates communication between USB host systems and connected USB devices while providing descriptor-based policy enforcement and packet-level inspection mechanisms. The proxy operates entirely inside the Linux kernel and is intended for USB security research and experimentation.

---

## Features

- Kernel-level USB proxy implementation
- Transparent USB request forwarding
- Descriptor-based USB policy enforcement
- Packet-level USB traffic inspection
- Runtime policy configuration through sysfs
- Support for multiple USB device classes

---

## Repository Structure

```
proxy_kernel/
│
├── docs/
│   ├── ARCHITECTURE.md
│   ├── BUILD.md
│   └── EXPERIMENTS.md
│
├── third_party/
│   └── raw-gadget/
│       ├── raw_gadget.c
│       └── raw_gadget.h
│
├── Makefile
├── raw_gadget_kapi.h
├── usb_packet_inspector.c
├── usb_packet_inspector.h
├── usb_policy_engine.c
├── usb_policy_engine.h
└── usb_proxy_control.c
```

---

## Components

### usb_proxy_control

Implements the main control logic of the USB proxy, including initialization, forwarding management and communication with the remaining modules.

### usb_policy_engine

Implements descriptor-based filtering policies used to decide whether newly connected USB devices should be accepted or rejected before enumeration.

### usb_packet_inspector

Implements packet-level inspection and filtering of USB requests exchanged between the host system and connected USB devices.

### raw_gadget_kapi

Defines the internal kernel API used by the USB proxy to communicate with the modified USB Raw Gadget implementation.

### third_party/raw-gadget

Contains a modified version of the Linux USB Raw Gadget implementation originally developed by Andrey Konovalov.

The original source code is available at:

https://github.com/xairy/raw-gadget

The implementation has been adapted to expose an internal kernel API required by the USB proxy.

---

## Experimental Validation

The implementation has been experimentally validated using multiple USB device categories, including:

- HID peripherals
- Android smartphones (ADB, MTP and RNDIS)
- Apple iPhone
- USB LTE modems
- USB Ethernet adapters
- USB-to-serial converters
- USB mass storage devices
- Composite USB devices

---

## Documentation

Additional documentation is available in the **docs/** directory.

| Document | Description |
|----------|-------------|
| BUILD.md | Build environment and compilation instructions |
| EXPERIMENTS.md | Experimental setup and reproducibility guide |
| ARCHITECTURE.md | Software architecture (to be added) |

---

## License

This repository contains original source code together with modified source files derived from the Linux USB Raw Gadget implementation.

All newly developed files are distributed under the GPL-2.0 license.

Modified Raw Gadget files retain their original GPL-2.0 license and copyright notices.