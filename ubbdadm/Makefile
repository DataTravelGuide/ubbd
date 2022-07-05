EXTRA_CFLAGS += $(call cc-option,-Wno-tautological-compare) -Wall -Wmaybe-uninitialized -Werror
SOURCES := $(shell find ../lib/ -name '*.c')

all:
	$(CC) $(EXTRA_CFLAGS) -g main.c $(SOURCES) -I /usr/include/libnl3/  -I ../include/  -lnl-3 -lnl-genl-3 -lrbd -lrados -lpthread -lssh -o ubbdadm
clean:
	rm -rf a.out ubbdadm
