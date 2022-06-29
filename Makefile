KERNEL_SOURCE_VERSION ?= $(shell uname -r)
KERNEL_TREE ?= /lib/modules/$(KERNEL_SOURCE_VERSION)/build
UBBD_SRC := $(shell pwd)
KMODS_SRC := $(UBBD_SRC)/kmods
KTF_SRC := $(shell pwd)/unittests/ktf
EXTRA_CFLAGS += $(call cc-option,-Wno-tautological-compare) -Wall -Wmaybe-uninitialized -Werror
VERSION ?= $(shell cat VERSION)
UBBD_VERSION ?= ubbd-$(VERSION)

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
	rm -vf rhed/ubbd.spec

install: all
	mkdir -p $(DESTDIR)/usr/bin
	install ubbdadm/ubbdadm $(DESTDIR)/usr/bin/ubbdadm
	install ubbdd/ubbdd $(DESTDIR)/usr/bin/ubbdd
	install backend/ubbd-backend $(DESTDIR)/usr/bin/ubbd-backend
	cd kmods; KMODS_SRC=$(KMODS_SRC) UBBD_KMODS_UT="n" KTF_SRC=$(KTF_SRC) $(MAKE) -C $(KERNEL_TREE) M=$(PWD)/kmods modules_install V=0

uninstall:
	rm -vf $(DESTDIR)/usr/bin/ubbdadm
	rm -vf $(DESTDIR)/usr/bin/ubbdd
	rm -vf $(DESTDIR)/usr/bin/ubbd-backend

dist:
	sed "s/@VERSION@/$(VERSION)/g" rhel/ubbd.spec.in > rhel/ubbd.spec
	cd /tmp && mkdir -p $(UBBD_VERSION) && \
	cp -rf $(UBBD_SRC)/{ubbdadm,ubbdd,backend,lib,include,doc,kmods,Makefile} $(UBBD_VERSION) && \
	tar --format=posix -chf - $(UBBD_VERSION) | gzip -c > $(UBBD_SRC)/$(UBBD_VERSION).tar.gz && \
	rm -rf $(UBBD_VERSION)
