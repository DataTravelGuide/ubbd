KERNEL_SOURCE_VERSION ?= $(shell uname -r)
KERNEL_TREE ?= /lib/modules/$(KERNEL_SOURCE_VERSION)/build
KMODS_SRC := $(shell pwd)/kmods
EXTRA_CFLAGS += $(call cc-option,-Wno-tautological-compare) -Wall -Wmaybe-uninitialized -Werror

all:
	$(MAKE) -C ubbdadm
	$(MAKE) -C ubbdd
	@echo
	@rm -rf kmods/compat.h
	cd kmods; KMODS_SRC=$(KMODS_SRC) $(MAKE) -C $(KERNEL_TREE) M=$(PWD)/kmods modules V=0
	@echo "Compile completed."

clean:
	$(MAKE) -C ubbdadm clean
	$(MAKE) -C ubbdd clean
	cd kmods; $(MAKE) clean
