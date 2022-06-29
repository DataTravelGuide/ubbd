# 1. What is UBBD?

UBBD is **Userspace Backend Block Device**.

<img src="doc/ubbd.png" alt="ubbd arch" title="UBBD Arch">

# 2. Why we need UBBD?

a) block device driver upgrade online.

b) driver bug dont crash kernel.

c) Dont reinvent the wheel.

Some block storage especially cloud storage has a userspace library
but there is no linux kernel driver to use it. ubbd can make it very easy
to enable linux block device driver for it via library.

d) Decoupling the storage specified logical from a linux kernel block device logical.

# 3. Who:

Who should not use UBBD?  
  Very care about latency(~10us overhead), dont use UBBD driver.

# 4. build and use
<img src="doc/make_and_use_ubbd_file.gif" alt="use ubbd" title="use ubbd">

    a) install requirements  

    install requirement packages:  

	   [centos]  
	    yum install librbd-devel glibc-devel libnl3-devel  

	   [ubuntu]  
	    apt install -y librbd-dev libc-dev libnl-3-dev libnl-genl-3-dev  

    b) compile  
	   $ make install

    c) insert kernel module  
	   $ modprobe uio  
	   $ insmod kmods/ubbd.ko  

    d) start ubbdd daemon  
	   $ ubbdd &  

    e) setup a ramdisk and map ubbd device by ubbdadm  
	   $ modprobe brd rd_nr=1 rd_size=2048000 max_part=0  
	   $ ubbdadm --command map --type file --filepath /dev/ram0 --devsize $((1*1024*1024*1024))  

    f) use the /dev/ubbd0 device  
	   $ mkfs.xfs /dev/ubbd0  `

# 5. performance

We can get **15us** latency and **1.8 million** iops with null type ubbd device.

|  backend type|  latency |  iops |
|--------------|----------|-------|
|    null      |    15us  |  1.8M |
|   ramdisk    |    19us  |  1.2M |

<img src="doc/fio_ubbd_null_and_ram.gif" alt="fio" title="fio">

# 6. ubbd with rbd


|  solution| iops| latency| rbd journaling| linux block device|
|----------|-----|--------|---------------|-------------------|
|   librbd |10184|  1549us|       support |       No          |
|    krbd  |10724|  1385us|    Not support|       Yes         |
|    ubbd  |10830|  1652us|       support |       Yes         |
|          |     |        |               |                   |


	Note:
		a) ubbd + librbd is mapped by:
			$ ubbdadm/ubbdadm --command map --type rbd --pool rbd --image test --ceph-conf /etc/ceph/ceph.conf
		b) krbd is mapped by:
			$ rbd map test
		c) librbd is tested by fio with ioengine=rbd.
		d) iops is tested by fio with iodepth=128 and numjobs=1.
		e) latency is tested by fio with iodepth=1 and numjobs=1.

**ubbd with rbd-mirror**

<img src="doc/rbd_mirror_ubbd.png" alt="mirror" title="mirror">

We can use ubbd in primary ceph cluster with rbd backend, the all update in primary image
will be synced up to secondary ceph cluster by rbd-mirroring.

<img src="doc/ubbd_rbd_mirror.gif" alt="mirror" title="mirror">

# 7. upgrade driver online
As we decoupling the storage related logic with block device, then we can upgrade storage
driver out of kernel module. That means we can upgrade our driver with io inflight on the air.

![upgrad](doc/ubbd_upgrade.png)

When you are going to upgrade ubbd, you can upgrade it as below: 

(1) upgrade ubbdd, it is a deamon to do management for ubbd, there is no IO be handled in this process, 

then you can upgrade it with IO inflight. 

(2) restart backend one-by-one. we can restart each backend one time, that means it is smooth to restart 

all ubbd devices with ubbdadm --command dev-restart command. 

and you can choose the restart-mode in dev-restart command: 

**dev mode:** 
In this mode, ubbdd will stop backend and start a new backend for this device.

**queue mode** 

In this mode, ubbdd will start a new backend firstly, then stop queue in current backend, and start queue in new backend one-by-one
until all queues in this device are working in new backend. At last, stop the old backend and new backend become to current backend.

![dev-restart](doc/dev-restart.gif)

# 8. Testing:
![testing](doc/ubbd_tests.png)

# 8.1 unittests

![unittest](doc/unittest.gif)

unittests in ubbd are supportted in userspace and kernelspace, that means all code in ubbd can be unittested.

**userspace**
userspace unittests is in cmocka test framework. The coverage of cmocka is in unittests/result/index.html

![cmocka_coverage](doc/cmocka_coverage.PNG)

**kernelspace**
kernelspace unittests is in ktf test framework.



# 8.2 function tests

ubbd-tests is a test-suite runnnig via avocado which is a gread test framework.

[https://github.com/ubbd/ubbd-tests](https://github.com/ubbd/ubbd-tests)

![ubbd-tests](doc/ubbd_tests.gif)

result like that:

![test result](doc/ubbd_tests_result.PNG)


# 9 package build

rpm build:

	$ make dist
	$ cp ubbd-0.0.1.tar.gz ~/rpmbuild/SOURCES/
	$ cp rhel/ubbd.spec ~/rpmbuild/SPECS/
	$ rpmbuild -ba ~/rpmbuild/SPECS/ubbd.spec
