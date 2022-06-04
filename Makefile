KERNEL_SOURCE_VERSION ?= $(shell uname -r)
KERNEL_TREE ?= /lib/modules/$(KERNEL_SOURCE_VERSION)/build
KMODS_SRC := $(shell pwd)/kmods
KTF_SRC := $(shell pwd)/unittests/ktf
EXTRA_CFLAGS += $(call cc-option,-Wno-tautological-compare) -Wall -Wmaybe-uninitialized -Werror

all:
	$(MAKE) -C ubbdadm
	$(MAKE) -C ubbdd
	$(MAKE) -C backend
	@echo
	@rm -rf kmods/compat.h
	cd kmods; KMODS_SRC=$(KMODS_SRC) UBBD_KMODS_UT="n" KTF_SRC=$(KTF_SRC) $(MAKE) -C $(KERNEL_TREE) M=$(PWD)/kmods modules V=0
	@echo "Compile completed."

unittest:
	@rm -rf kmods/compat.h
	cd kmods; KMODS_SRC=$(KMODS_SRC) UBBD_KMODS_UT="m" KTF_SRC=$(KTF_SRC) $(MAKE) -C $(KERNEL_TREE) M=$(PWD)/kmods modules V=0

clean:
	$(MAKE) -C ubbdadm clean
	$(MAKE) -C ubbdd clean
	$(MAKE) -C backend clean
	$(MAKE) -C unittests clean
	cd kmods; $(MAKE) clean

install: all
	install ubbdadm/ubbdadm /usr/bin/ubbdadm
	install ubbdd/ubbdd /usr/bin/ubbdd
	install backend/ubbd-backend /usr/bin/ubbd-backend

uninstall:
	rm  /usr/bin/ubbdadm
	rm  /usr/bin/ubbdd
	rm  /usr/bin/ubbd-backend
