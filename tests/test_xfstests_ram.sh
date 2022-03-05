UBBD_DIR=`pwd`

# enable UBBD_FAULT_INJECT
sed -i "s/#undef UBBD_FAULT_INJECT/#define UBBD_FAULT_INJECT/" kmods/ubbd_internal.h

modprobe uio
make
sleep 1
insmod kmods/ubbd.ko
sleep 1
modprobe brd rd_nr=2 rd_size=2048000 max_part=0
sleep 1
./ubbdd/ubbdd &
sleep 2
./ubbdadm/ubbdadm --command map --type file --filepath /dev/ram0 --filesize $((1*1024*1024*1024))
sleep 1
./ubbdadm/ubbdadm --command map --type file --filepath /dev/ram1 --filesize $((1*1024*1024*1024))
sleep 1

# set the data-pages-reserve to 0
./ubbdadm/ubbdadm --command config --ubbdid 0 --data-pages-reserve 0
./ubbdadm/ubbdadm --command config --ubbdid 1 --data-pages-reserve 0


# mkfs for xfstests
mkfs.xfs -f /dev/ubbd0

cd $XFSTESTS_DIR
export SCRATCH_MNT=/media
export TEST_DIR=/mnt
export TEST_DEV=/dev/ubbd0
export SCRATCH_DEV=/dev/ubbd1
time ./check

# cleanup
umount /mnt
umount /media

cd $UBBD_DIR
./ubbdadm/ubbdadm --command unmap --ubbdid 0
./ubbdadm/ubbdadm --command unmap --ubbdid 1
sleep 3
pkill ubbdd
rmmod ubbd
rmmod brd
