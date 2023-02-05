COMMIT_REV ?= $(shell git describe  --always --abbrev=12)
KERNEL_SOURCE_VERSION ?= $(shell uname -r)
KERNEL_TREE ?= /lib/modules/$(KERNEL_SOURCE_VERSION)/build

_KBUILD_CFLAGS := $(call flags,KBUILD_CFLAGS)
CHECK_BUILD := $(CC) $(NOSTDINC_FLAGS) $(KBUILD_CPPFLAGS) $(CPPFLAGS) $(LINUXINCLUDE) $(_KBUILD_CFLAGS) $(CFLAGS_KERNEL) $(EXTRA_CFLAGS) $(CFLAGS) -DKBUILD_BASENAME=\"ubbd\" -Werror -S -o /dev/null -xc 
EXTRA_CFLAGS :=
EXTRA_CFLAGS += -I$(KERNEL_TREE)
UBBDCONF_HEADER := $(KMODS_SRC)/compat.h

$(UBBDCONF_HEADER):
	@> $@
	@echo $(CHECK_BUILD) compat-tests/have_nla_parse_nested_deprecated.c
	@if $(CHECK_BUILD) $(KMODS_SRC)/compat-tests/have_nla_parse_nested_deprecated.c > /dev/null 2>&1; then echo "#define HAVE_NLA_PARSE_NESTED_DEPRECATED 1"; else echo "/*#undefined HAVE_NLA_PARSE_NESTED_DEPRECATED*/"; fi >> $@
	@echo $(CHECK_BUILD) compat-tests/have_genl_small_ops.c
	@if $(CHECK_BUILD) $(KMODS_SRC)/compat-tests/have_genl_small_ops.c > /dev/null 2>&1; then echo "#define HAVE_GENL_SMALL_OPS 1"; else echo "/*#undefined HAVE_GENL_SMALL_OPS*/"; fi >> $@
	@echo $(CHECK_BUILD) compat-tests/have_genl_policy.c
	@if $(CHECK_BUILD) $(KMODS_SRC)/compat-tests/have_genl_policy.c > /dev/null 2>&1; then echo "#define HAVE_GENL_POLICY 1"; else echo "/*#undefined HAVE_GENL_POLICY*/"; fi >> $@
	@echo $(CHECK_BUILD) compat-tests/have_genl_validate.c
	@if $(CHECK_BUILD) $(KMODS_SRC)/compat-tests/have_genl_validate.c > /dev/null 2>&1; then echo "#define HAVE_GENL_VALIDATE 1"; else echo "/*#undefined HAVE_GENL_VALIDATE*/"; fi >> $@
	@echo $(CHECK_BUILD) compat-tests/have_alloc_disk.c
	@if $(CHECK_BUILD) $(KMODS_SRC)/compat-tests/have_alloc_disk.c > /dev/null 2>&1; then echo "#define HAVE_ALLOC_DISK 1"; else echo "/*#undefined HAVE_ALLOC_DISK*/"; fi >> $@
	@echo $(CHECK_BUILD) compat-tests/have_EXT_DEVT.c
	@if $(CHECK_BUILD) $(KMODS_SRC)/compat-tests/have_EXT_DEVT.c > /dev/null 2>&1; then echo "#define HAVE_EXT_DEVT 1"; else echo "/*#undefined HAVE_EXT_DEVT*/"; fi >> $@
	@echo $(CHECK_BUILD) compat-tests/have_flag_discard.c
	@if $(CHECK_BUILD) $(KMODS_SRC)/compat-tests/have_flag_discard.c > /dev/null 2>&1; then echo "#define HAVE_FLAG_DISCARD 1"; else echo "/*#undefined HAVE_FLAG_DISCARD*/"; fi >> $@
	@>> $@

EXTRA_CFLAGS += -include $(UBBDCONF_HEADER)
EXTRA_CFLAGS += -freorder-blocks
EXTRA_CFLAGS += -fasynchronous-unwind-tables
EXTRA_CFLAGS += $(call cc-option,-Wframe-larger-than=512)
EXTRA_CFLAGS += $(call cc-option,-fno-ipa-icf)
EXTRA_CFLAGS += $(call cc-option,-Wno-tautological-compare) -Wall -Wmaybe-uninitialized -Werror
EXTRA_CFLAGS += -I${PWD}/../include/ -I${PWD}/../include/ubbd-headers/ -DCOMMIT_REV="\"$(COMMIT_REV)\""
EXTRA_CFLAGS += -I$(KERNEL_TREE)/include/ -I$(KERNEL_TREE)/include/linux
EXTRA_CFLAGS += -I$(KTF_SRC)/kernel/

KBUILD_EXTRA_SYMBOLS += $(KTF_SRC)/build/kernel/Module.symvers

obj-m := ubbd.o
ubbd-y := ubbd_main.o ubbd_req.o ubbd_nl.o ubbd_uio.o ubbd_dev.o ubbd_debugfs.o
$(obj)/ubbd.o: $(UBBDCONF_HEADER)

clean:
	rm -rf .tmp_versions Module.markers Module.symvers modules.order
	rm -f *.[oas] *.ko *.mod .*.cmd .*.d .*.tmp *.mod.c .*.flags .depend .kernel*
	rm -f compat.h
	rm -f compat-tests/*.[oas] compat-tests/.*.cmd
