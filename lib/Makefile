include ../mk/config.mk
LINKLIBS := -lcurl -lcrypto -lxml2 -lnl-3 -lnl-genl-3 -lpthread -lm -lz -laio

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
	SOURCES := $(filter-out ../lib/ubbd_devs/ubbd_cache_dev.c ../lib/ubbd_backends/ubbd_cache_backend/%.c, $(SOURCES))
endif

.DEFAULT_GOAL := all

libubbd:
	$(CC) $(EXTRA_CFLAGS) libubbd.c ../lib/ubbd_log_cmdline.c ../lib/ubbd_base_mgmt.c ../lib/utils.c $(UBBD_FLAGS)  -fPIC -shared -Wl,-soname,libubbd.so.$(LIBVER) -o libubbd.so.$(LIBVER)
	@ln -sf libubbd.so.$(LIBVER)* libubbd.so

all: libubbd
	$(CC) $(EXTRA_CFLAGS) $(SOURCES) $(UBBD_FLAGS) $(LINKLIBS) -fPIC -shared -Wl,-soname,libubbd-daemon.so.$(LIBVER) -o libubbd-daemon.so.$(LIBVER)
	@ln -sf libubbd-daemon.so.$(LIBVER)* libubbd-daemon.so
clean:
	rm -rf *.so
	rm -rf *.so.*
