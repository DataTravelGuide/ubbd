EXTRA_CFLAGS += $(call cc-option,-Wno-tautological-compare) -Wall -Wmaybe-uninitialized -Werror

all:
	$(CC) $(EXTRA_CFLAGS) -g main.c ../lib/*.c ../lib/ubbd_devs/*.c -I /usr/include/libnl3/ -I ../include/  -lnl-3 -lnl-genl-3 -lrbd -lrados -lpthread -o ubbdd 
clean:
	rm -rf a.out ubbdd

# LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/data/ceph/build/lib/ ./a.out
