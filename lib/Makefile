SOURCES := $(shell find ../lib/ -name '*.c')
SOURCES += $(shell find ../src/ -name '*.c')
LINKLIBS := -lcurl -lcrypto -lxml2 -lnl-3 -lnl-genl-3 -lrbd -lrados -lpthread -lm -lz -lssh

all:
	$(CC) $(EXTRA_CFLAGS) libubbd.c ubbd_log.c ubbd_base_mgmt.c $(UBBD_FLAGS) $(LINKLIBS) -fPIC -shared -Wl,-soname,libubbd.so.$(LIBVER) -o libubbd.so.$(LIBVER)
	@ln -sf libubbd.so.$(LIBVER)* libubbd.so
	$(CC) $(EXTRA_CFLAGS) $(SOURCES) $(UBBD_FLAGS) $(LINKLIBS) -fPIC -shared -Wl,-soname,libubbd-daemon.so.$(LIBVER) -o libubbd-daemon.so.$(LIBVER)
	@ln -sf libubbd-daemon.so.$(LIBVER)* libubbd-daemon.so
clean:
	rm -rf *.so
	rm -rf *.so.*
