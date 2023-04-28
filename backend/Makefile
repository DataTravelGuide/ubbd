include ../mk/config.mk

ifeq ("$(CONFIG_S3_BACKEND)", "y")
	LINKLIBS += -ls3-ubbd
endif

all:
	$(CC) $(EXTRA_CFLAGS) main.c -L../lib/ -lubbd-daemon $(LINKLIBS) $(UBBD_FLAGS) -o ubbd-backend
clean:
	rm -rf ubbd-backend
