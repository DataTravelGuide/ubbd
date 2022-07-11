EXTRA_CFLAGS += $(call cc-option,-Wno-tautological-compare) -Wall -Wmaybe-uninitialized -Werror
SOURCES := $(shell find ../lib/ -name '*.c')
SOURCES += $(shell find ../src/ -name '*.c')

all:
	$(CC) $(EXTRA_CFLAGS) -g main.c $(SOURCES) $(UBBD_FLAGS) -o ubbdadm
clean:
	rm -rf a.out ubbdadm
