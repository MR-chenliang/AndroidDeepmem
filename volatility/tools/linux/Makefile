
obj-m += module.o
KDIR ?= /home/cl/goldfish
CCPATH := /home/cl/android-ndk-r17c/toolchains/x86_64-4.9/prebuilt/linux-x86_64/bin

-include version.mk

all: dwarf

dwarf: module.c
	$(MAKE)		ARCH=x86_64 CROSS_COMPILE=$(CCPATH)/x86_64-linux-android- -C$(KDIR) CONFIG_DEBUG_INFO=y M=$(PWD) modules
	dwarfdump -di module.ko > module.dwarf
clean:
	rm -f module.dwarf

