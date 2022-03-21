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


start_fio()
{
	DEV=$1
	fio --name test --rw randwrite --bs 4K --ioengine libaio --filename $DEV  --direct 1 --numjobs 1 --iodepth 128 --time_based --runtime 100 --eta-newline 1  --rate_iops 1000 &
}

get_random_op()
{
	num=$(cat /dev/urandom | head -n 10 | cksum | awk -F ' ' '{print $1}')
	op=$((num % 3))
}

get_random_id()
{
	num=$(cat /dev/urandom | head -n 10 | cksum | awk -F ' ' '{print $1}')
	id=$((num % 10))
}

do_ubbdadm_map()
{
	get_random_id
	dev=`valgrind ./ubbdadm/ubbdadm --command map --type file --filepath /dev/ram0 --filesize $((1*1024*1024*1024))`
	start_fio $dev
}

do_ubbdadm_unmap()
{
	get_random_id
	valgrind ./ubbdadm/ubbdadm --command unmap --ubbdid $id
	get_random_id
	valgrind ./ubbdadm/ubbdadm --command unmap --ubbdid $id --force
}

do_ubbdadm_config()
{
	get_random_id
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
	get_random_op
	do_ubbdadm_action
done

# cleanup
sleep 3
pkill ubbdd
rmmod ubbd
rmmod brd

