# Build Instructions

## Build Environment

The USB proxy was developed for a custom Yocto Linux distribution running on a Raspberry Pi 5.

To ensure ABI compatibility with the deployed kernel, the kernel modules must be compiled using the same Yocto SDK and the corresponding kernel build directory used to generate the target image.

---

## Kernel Configuration

The experimental Linux image contains only the USB core and USB Gadget infrastructure required by the proxy.

Standard USB class drivers (HID, Mass Storage, CDC Ethernet, Serial, etc.) were intentionally disabled to prevent the Linux USB subsystem from automatically binding USB devices before the proxy processes them.

This configuration allows the USB proxy to become the first kernel component handling newly connected USB devices.

---

## Compilation

Load the Yocto SDK environment:

```bash
source <YOCTO_SDK>/environment-setup-cortexa76-poky-linux
```

Specify the kernel build directory:

```bash
export KBUILD=<YOCTO_KERNEL_BUILD_DIRECTORY>
```

Compile the module:

```bash
make -C "$KBUILD" M="$PWD" modules
```

---

## Notes

The kernel version used for compilation must exactly match the version running on the target system.

Compiling against a different kernel build may result in incompatible kernel modules.