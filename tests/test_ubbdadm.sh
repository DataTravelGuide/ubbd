#!/bin/sh

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
sh -x tests/start_ubbdd.sh 30 1 &
sleep 2



get_random()
{
	num=$(cat /dev/urandom | head -n 10 | cksum | awk -F ' ' '{print $1}')
	op=$((num % 3))
	num=$(cat /dev/urandom | head -n 10 | cksum | awk -F ' ' '{print $1}')
	id=$((num % 10))
}

do_ubbdadm_map()
{
	valgrind ./ubbdadm/ubbdadm --command map --type file --filepath /dev/ram0 --filesize $((1*1024*1024*1024))
}

do_ubbdadm_unmap()
{
	valgrind ./ubbdadm/ubbdadm --command unmap --ubbdid $id
}

do_ubbdadm_config()
{
	valgrind ./ubbdadm/ubbdadm --command config --ubbdid $id --data-pages-reserve 0
}

do_ubbdadm_action()
{
	if [ $op -eq 0 ]; then
		do_ubbdadm_map
	elif [ $op -eq 1 ]; then
		do_ubbdadm_unmap
	elif [ $op -eq 2 ]; then
		do_ubbdadm_config
	else
		exit
	fi

}

while true; do
	get_random
	echo $op $id
	do_ubbdadm_action
done

# cleanup
cd $UBBD_DIR
./ubbdadm/ubbdadm --command unmap --ubbdid 0
sleep 3
pkill ubbdd
rmmod ubbd
rmmod brd

