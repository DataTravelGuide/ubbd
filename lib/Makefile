SOURCES := $(shell find ../lib/ -name '*.c')
SOURCES += $(shell find ../src/ -name '*.c')
LIBS := -lcurl -lcrypto -lxml2 -lnl-3 -lnl-genl-3 -lrbd -lrados -lpthread -lm -lz -lssh

all:
	$(CC) $(EXTRA_CFLAGS) libubbd.c ubbd_log.c ubbd_base_mgmt.c $(UBBD_FLAGS) $(LIBS) -fPIC -shared -o libubbd.so
	$(CC) $(EXTRA_CFLAGS) $(SOURCES) $(UBBD_FLAGS) $(LIBS) -fPIC -shared -o libubbd-daemon.so
clean:
	rm -rf libubbd.so
