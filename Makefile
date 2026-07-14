obj-m += usb_proxy.o

usb_proxy-objs := usb_proxy_control.o \
                  usb_policy_engine.o \
                  usb_packet_inspector.o \
                  third_party/raw-gadget/raw_gadget.o

ccflags-y += -I$(src)/third_party/raw-gadget -I$(src)

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean