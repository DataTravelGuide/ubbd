include ../mk/config.mk
KERNEL_SOURCE_VERSION ?= $(shell uname -r)
KERNEL_TREE ?= /lib/modules/$(KERNEL_SOURCE_VERSION)/build
EXTRA_CFLAGS += $(call cc-option,-Wno-tautological-compare) -Wall -Wmaybe-uninitialized -Werror
LDLIBS_CMOCKA = -lcmocka -lcurl -lcrypto -lxml2 -lnl-3 -lnl-genl-3 -lpthread -lm -lz -laio
CMOCKA_CFLAGS := --coverage
CMOCKA_CALLOC_CFLAGS := -Wl,--wrap=calloc -Wl,--wrap=free
CMOCKA_OPEN_CFLAGS := -Wl,--wrap,open -Wl,--wrap,close -Wl,--wrap,mmap -Wl,--wrap,munmap -Wl,--wrap,read -Wl,--wrap,write -Wl,--wrap,asprintf
SOURCES := $(shell find ../lib/ -name '*.c' ! -name "ubbd_log_cmdline.c")
ifneq ("$(CONFIG_RBD_BACKEND)", "y")
	SOURCES := $(filter-out ../lib/ubbd_devs/ubbd_rbd_dev.c ../lib/ubbd_backends/ubbd_rbd_backend.c ../lib/ubbd_rbd.c, $(SOURCES))
else
	LINKLIBS += -lrbd -lrados
endif

ifneq ("$(CONFIG_SSH_BACKEND)", "y")
	SOURCES := $(filter-out ../lib/ubbd_devs/ubbd_ssh_dev.c ../lib/ubbd_backends/ubbd_ssh_backend.c, $(SOURCES))
else
	LINKLIBS += -lssh
endif

ifneq ("$(CONFIG_S3_BACKEND)", "y")
	SOURCES := $(filter-out ../lib/ubbd_devs/ubbd_s3_dev.c ../lib/ubbd_backends/ubbd_s3_backend.c, $(SOURCES))
else
	LINKLIBS += -ls3-ubbd
endif

ifneq ("$(CONFIG_CACHE_BACKEND)", "y")
	SOURCES := $(filter-out ../lib/ubbd_devs/ubbd_cache_dev.c ../lib/ubbd_backends/ubbd_cache_backend.c, $(SOURCES))
endif
SOURCES += $(shell find ../src/ -name '*.c')

all:
	$(CC) $(EXTRA_CFLAGS) $(CMOCKA_CFLAGS) $(CMOCKA_CALLOC_CFLAGS) -g  utils_test.c $(UBBD_FLAGS) $(LDLIBS_CMOCKA) $(LINKLIBS) -o utils_test
	$(CC) $(EXTRA_CFLAGS) $(CMOCKA_CFLAGS) $(CMOCKA_OPEN_CFLAGS) -g ubbd_uio_test.c $(SOURCES) $(UBBD_FLAGS) $(LDLIBS_CMOCKA) $(LINKLIBS) -o ubbd_uio_test

clean:
	rm -rf utils_test
	rm -rf ubbd_uio_test
	rm -rf *.gcno *.gcda
	rm -rf result
