# Experimental Setup

This document summarizes the experimental platform and the procedures used to evaluate the kernel-level USB proxy presented in the accompanying IEEE Access manuscript.

---

## Hardware Platform

### Target System

- Raspberry Pi 5

### Host Systems

- Ubuntu Linux workstation
- Windows 10 workstation

---

## Software Environment

Target operating system:

- Custom Yocto Linux distribution
- Linux kernel 6.1

The USB proxy is implemented as a loadable Linux kernel module.

---

## Loading the USB Proxy

The proxy module is loaded using:

```bash
sudo insmod usb_proxy.ko \
    vid=0x04e8 \
    pid=0x6860 \
    udc=1000480000.usb
```

where:

- `vid` specifies the Vendor ID (VID) of the USB device to be proxied;
- `pid` specifies the Product ID (PID) of the USB device;
- `udc` is the name of the USB Device Controller available on the target platform.

The available UDC controller can be obtained using:

```bash
ls /sys/class/udc
```

The values shown above are provided as an example. The `vid`, `pid`, and `udc` parameters must be adapted to the target USB device and the hardware platform.

After the module is loaded, connect the target USB device to the Raspberry Pi 5 and connect the Raspberry Pi 5 to the host system.

---

## Evaluated USB Devices

The implementation was experimentally validated using representative devices from multiple USB classes, including:

- HID keyboard
- HID mouse
- Android smartphone (ADB)
- Android smartphone (MTP)
- Android smartphone (RNDIS)
- Apple iPhone
- USB modem
- USB Ethernet adapters
- USB-to-serial converter
- USB mass storage device
- Composite USB device

---

## Experimental Evaluation

The experimental evaluation presented in the accompanying paper includes:

- USB enumeration latency measurements
- USB throughput evaluation
- USB compatibility evaluation
- Descriptor-based policy enforcement
- Packet-level USB traffic inspection
- BadUSB detection
- Protection against malicious host-generated USB commands

---

## Additional Information

The complete experimental methodology, command sequences, configuration parameters, and performance measurements are described in the accompanying IEEE Access manuscript.