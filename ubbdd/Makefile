include ../mk/config.mk

ifeq ("$(CONFIG_S3_BACKEND)", "y")
	LINKLIBS += -ls3-ubbd
endif

all:
	$(CC) $(EXTRA_CFLAGS) $(UBBD_FLAGS)  main.c -L../lib/ -lubbd-daemon $(LINKLIBS) -o ubbdd
clean:
	rm -rf ubbdd
