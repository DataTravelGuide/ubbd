KERNEL_SOURCE_VERSION ?= $(shell uname -r)
KERNEL_TREE ?= /lib/modules/$(KERNEL_SOURCE_VERSION)/build
UBBD_SRC := $(shell pwd)
ifeq ($(shell ls mk/config.mk && echo configired || ./configure; echo $?), 0)
	echo configure done
endif
include mk/config.mk
KTF_SRC := $(shell pwd)/unittests/ktf
EXTRA_CFLAGS += $(call cc-option,-Wno-tautological-compare) -Wall -Wmaybe-uninitialized -Werror

ifeq ("$(CONFIG_DEBUG)", "y")
    EXTRA_CFLAGS += -g
endif

ifeq ("$(CONFIG_ASAN)", "y")
    EXTRA_CFLAGS += -fsanitize=address -fno-omit-frame-pointer
endif

VERSION ?= $(shell cat VERSION)
UBBD_VERSION ?= ubbd-$(VERSION)
$(shell rm -rf include/ubbd_compat.h)
UBBDCONF_HEADER := include/ubbd_compat.h
OCFDIR = ocf/
LIBVER := 1
DIST_FILES = ubbdadm ubbdd backend lib include Makefile etc man install_dep.sh VERSION mk configure build_deb.sh build_rpm.sh debian rpm unittests CONFIG libs3 ocf

UBBD_FLAGS := -I /usr/include/libnl3/ -I $(UBBD_SRC)/include/ubbd-headers/ -I $(UBBD_SRC)/include/

ifeq ("$(CONFIG_S3_BACKEND)", "y")
	DIST_FILES += libs3
	UBBD_FLAGS += -I$(UBBD_SRC)/libs3/inc
	UBBD_FLAGS += -L$(UBBD_SRC)/libs3/build/lib/
endif

ifeq ("$(CONFIG_CACHE_BACKEND)", "y")
	DIST_FILES += ocf
	UBBD_FLAGS += -I$(UBBD_SRC)/src/ocf/env/
	UBBD_FLAGS += -I$(UBBD_SRC)/src/ocf/
endif


.DEFAULT_GOAL := all

$(UBBDCONF_HEADER):
	@> $@
	@echo $(CHECK_BUILD) compat-tests/have_sftp_fsync.c
	@if $(CC) compat-tests/have_sftp_fsync.c -lssh > /dev/null 2>&1; then echo "#define HAVE_SFTP_FSYNC 1"; else echo "/*#undefined HAVE_SFTP_FSYNC*/"; fi >> $@
	@echo $(CHECK_BUILD) compat-tests/have_rbd_quiesce.c
	@if $(CC) compat-tests/have_rbd_quiesce.c -lrbd > /dev/null 2>&1; then echo "#define HAVE_RBD_QUIESCE 1"; else echo "/*#undefined HAVE_RBD_QUIESCE*/"; fi >> $@
	@if [ "${CONFIG_CACHE_BACKEND}" = "y" ]; then echo "#define CONFIG_CACHE_BACKEND 1"; else echo "/*#undefined CONFIG_CACHE_BACKEND*/"; fi >> $@
	@if [ "${CONFIG_S3_BACKEND}" = "y" ]; then echo "#define CONFIG_S3_BACKEND 1"; else echo "/*#undefined CONFIG_S3_BACKEND*/"; fi >> $@
	@if [ "${CONFIG_RBD_BACKEND}" = "y" ]; then echo "#define CONFIG_RBD_BACKEND 1"; else echo "/*#undefined CONFIG_RBD_BACKEND*/"; fi >> $@
	@if [ "${CONFIG_SSH_BACKEND}" = "y" ]; then echo "#define CONFIG_SSH_BACKEND 1"; else echo "/*#undefined CONFIG_SSH_BACKEND*/"; fi >> $@
	@>> $@
	sed "s/@UBBD_VERSION@/$(VERSION)/g" include/ubbd_version.h.in > include/ubbd_version.h

ubbdadm: $(UBBDCONF_HEADER)
	EXTRA_CFLAGS="$(EXTRA_CFLAGS)" UBBD_FLAGS="$(UBBD_FLAGS)" $(MAKE) -C ubbdadm

lib: $(UBBDCONF_HEADER)
	LIBVER=$(LIBVER) EXTRA_CFLAGS="$(EXTRA_CFLAGS)" UBBD_FLAGS="$(UBBD_FLAGS)" $(MAKE) -C lib/

libubbd: $(UBBDCONF_HEADER)
	LIBVER=$(LIBVER) EXTRA_CFLAGS="$(EXTRA_CFLAGS)" UBBD_FLAGS="$(UBBD_FLAGS)" $(MAKE) -C lib/ libubbd

libubbd_install:
	mkdir -p $(DESTDIR)/usr/lib/ubbd/
	mkdir -p $(DESTDIR)/usr/include/ubbd/
	install lib/libubbd.so.$(LIBVER) $(DESTDIR)/usr/lib/ubbd/libubbd.so.$(LIBVER)
	install lib/libubbd.so $(DESTDIR)/usr/lib/ubbd/libubbd.so
	install include/libubbd.h $(DESTDIR)/usr/include/ubbd/libubbd.h
	install include/ubbd-headers/ubbd.h $(DESTDIR)/usr/include/ubbd/ubbd.h

backend: $(UBBDCONF_HEADER)
	EXTRA_CFLAGS="$(EXTRA_CFLAGS)" UBBD_FLAGS="$(UBBD_FLAGS)" $(MAKE) -C backend

ubbdd: $(UBBDCONF_HEADER)
	EXTRA_CFLAGS="$(EXTRA_CFLAGS)" UBBD_FLAGS="$(UBBD_FLAGS)" $(MAKE) -C ubbdd

ubbd_ut: $(UBBDCONF_HEADER)
	EXTRA_CFLAGS="$(EXTRA_CFLAGS)" UBBD_FLAGS="$(UBBD_FLAGS)" $(MAKE) -C unittests

all: $(UBBDCONF_HEADER)
	@if [ "${CONFIG_CACHE_BACKEND}" = "y" ]; then $(MAKE) -C ${OCFDIR} inc O=$(PWD); $(MAKE) -C ${OCFDIR} src O=$(PWD); $(MAKE) -C ${OCFDIR} env O=$(PWD) OCF_ENV=posix; fi
	@if [ "${CONFIG_S3_BACKEND}" = "y" ]; then $(MAKE) -C libs3/ clean; $(MAKE) -C libs3/; fi
	LIBVER=$(LIBVER) EXTRA_CFLAGS="$(EXTRA_CFLAGS)" UBBD_FLAGS="$(UBBD_FLAGS)" $(MAKE) -C lib/
	EXTRA_CFLAGS="$(EXTRA_CFLAGS)" UBBD_FLAGS="$(UBBD_FLAGS)" $(MAKE) -C ubbdadm
	EXTRA_CFLAGS="$(EXTRA_CFLAGS)" UBBD_FLAGS="$(UBBD_FLAGS)" $(MAKE) -C ubbdd
	EXTRA_CFLAGS="$(EXTRA_CFLAGS)" UBBD_FLAGS="$(UBBD_FLAGS)" $(MAKE) -C backend
	gzip -fk man/ubbdadm.8
	gzip -fk man/ubbdd.8
	@echo "Compile completed."

clean:
	$(MAKE) -C ubbdadm clean
	$(MAKE) -C ubbdd clean
	$(MAKE) -C backend clean
	$(MAKE) -C unittests clean
	$(MAKE) -C lib clean
	rm -vf rhed/ubbd.spec
	rm -vf man/*.gz

install:
	mkdir -p $(DESTDIR)/usr/bin
	mkdir -p $(DESTDIR)/usr/lib/ubbd/
	mkdir -p $(DESTDIR)/usr/include/ubbd/
	mkdir -p $(DESTDIR)/etc/ld.so.conf.d/
	mkdir -p $(DESTDIR)/etc/systemd/system/
	install etc/systemd/system/ubbdd.service $(DESTDIR)/etc/systemd/system/ubbdd.service
	install lib/libubbd.so.$(LIBVER) $(DESTDIR)/usr/lib/ubbd/libubbd.so.$(LIBVER)
	install lib/libubbd-daemon.so.$(LIBVER) $(DESTDIR)/usr/lib/ubbd/libubbd-daemon.so.$(LIBVER)
	install lib/libubbd.so $(DESTDIR)/usr/lib/ubbd/libubbd.so
	install lib/libubbd-daemon.so $(DESTDIR)/usr/lib/ubbd/libubbd-daemon.so
	if [ "${CONFIG_RBD_BACKEND}" = "y" ]; then install lib/ubbd-rbd_quiesce $(DESTDIR)/usr/lib/ubbd/ubbd-rbd_quiesce; fi
	if [ "${CONFIG_S3_BACKEND}" = "y" ]; then install libs3/build/lib/libs3-ubbd.so.4 $(DESTDIR)/usr/lib/ubbd/libs3-ubbd.so.4; fi
	install ubbdadm/ubbdadm $(DESTDIR)/usr/bin/ubbdadm
	install ubbdd/ubbdd $(DESTDIR)/usr/bin/ubbdd
	install backend/ubbd-backend $(DESTDIR)/usr/bin/ubbd-backend
	install etc/ld.so.conf.d/ubbd.conf $(DESTDIR)/etc/ld.so.conf.d/ubbd.conf
	install include/libubbd.h $(DESTDIR)/usr/include/ubbd/libubbd.h
	install include/ubbd-headers/ubbd.h $(DESTDIR)/usr/include/ubbd/ubbd.h
	install -D -g 0 -o 0 -m 0644 man/ubbdadm.8.gz $(DESTDIR)/usr/share/man/man8/ubbdadm.8.gz
	install -D -g 0 -o 0 -m 0644 man/ubbdd.8.gz $(DESTDIR)/usr/share/man/man8/ubbdd.8.gz

uninstall:
	rm -vf $(DESTDIR)/etc/ld.so.conf.d/ubbd.conf
	rm -vf $(DESTDIR)/usr/bin/ubbdadm
	rm -vf $(DESTDIR)/usr/bin/ubbdd
	rm -vf $(DESTDIR)/usr/bin/ubbd-backend
	rm -vrf $(DESTDIR)/usr/lib/ubbd/
	rm -vrf $(DESTDIR)/usr/include/ubbd/
	rm -vf $(DESTDIR)/etc/lib.so.conf.d/ubbd.conf
	rm -vf $(DESTDIR)/etc/systemd/system/ubbdd.service
	rm -vf $(DESTDIR)/usr/share/man/man8/ubbdd.8*
	rm -vf $(DESTDIR)/usr/share/man/man8/ubbdadm.8*

dist:
	git submodule update --init --recursive
	sed "s/@VERSION@/$(VERSION)/g" rpm/ubbd.spec.in > rpm/ubbd.spec
	sed -i 's/@LIBVER@/$(LIBVER)/g' rpm/ubbd.spec
	cd /tmp && mkdir -p $(UBBD_VERSION) && \
	for u in $(DIST_FILES); do cp -rf $(UBBD_SRC)/$$u $(UBBD_VERSION); done && \
	tar --format=posix -chf - $(UBBD_VERSION) | gzip -c > $(UBBD_SRC)/$(UBBD_VERSION).tar.gz && \
	rm -rf $(UBBD_VERSION)
