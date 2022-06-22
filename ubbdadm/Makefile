EXTRA_CFLAGS += $(call cc-option,-Wno-tautological-compare) -Wall -Wmaybe-uninitialized -Werror
SOURCES := $(shell find ../lib/ -name '*.c')
SOURCES += $(shell find ../src/ -name '*.c')

all:
	$(CC) $(EXTRA_CFLAGS) -g main.c $(SOURCES) -I /usr/include/libnl3/  -I ../include/ -I../src/ocf/env/ -I../src/ocf/ -lnl-3 -lnl-genl-3 -lrbd -lrados -lpthread -lm -lz -lssh -o ubbdadm
clean:
	rm -rf a.out ubbdadm
