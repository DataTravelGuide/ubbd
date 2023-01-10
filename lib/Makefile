SOURCES := $(shell find ../lib/ -name '*.c')
SOURCES += $(shell find ../src/ -name '*.c')
LIBS := -lcurl -lcrypto -lxml2 -lnl-3 -lnl-genl-3 -lrbd -lrados -lpthread -lm -lz -lssh

all:
	$(CC) $(EXTRA_CFLAGS) $(SOURCES) $(UBBD_FLAGS) $(LIBS) -fPIC -shared -o libubbd.so
clean:
	rm -rf libubbd.so
