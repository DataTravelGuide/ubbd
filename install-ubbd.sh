#!/bin/bash
set -xe

[ -z "$UBBD_KERNEL_VERSION" ] && UBBD_KERNEL_VERSION="0.1.0"
[ -z "$UBBD_VERSION" ] && UBBD_VERSION="0.1.0"
[ -z "$INSTALL_UBBD_KERNEL" ] && INSTALL_UBBD_KERNEL=1
[ -z "$INSTALL_UBBD" ] && INSTALL_UBBD=1

UBBD_KERNEL_DOWNLOAD_URL="https://github.com/DataTravelGuide/ubbd-kernel/releases/download/v${UBBD_KERNEL_VERSION}/ubbd-kernel-${UBBD_KERNEL_VERSION}.tar.gz"
UBBD_DOWNLOAD_URL="https://github.com/DataTravelGuide/ubbd/releases/download/v${UBBD_VERSION}/ubbd-${UBBD_VERSION}.tar.gz"


source /etc/os-release

install_kernel_dev() {
	case "$ID" in
	debian|ubuntu|devuan|elementary|softiron)
		env DEBIAN_FRONTEND=noninteractive apt install -y linux-headers-$(uname -r)
		;;
	rocky|centos|fedora|rhel|ol|virtuozzo)
		yum install -y kernel-devel
		;;
	*)
		echo "$ID is unknown, kernel development package will have to be installed manually."
		exit 1
		;;
	esac
}

PKG_PATH=""

# clear ubbd cache dir
rm -rf /var/cache/ubbd
mkdir -p /var/cache/ubbd

if [ ${INSTALL_UBBD_KERNEL} -eq 1 ]; then
	# install kernel development package
	install_kernel_dev

	# install ubbd-kernel
	tarball_name="ubbd-kernel.tar.gz"

	# get the archive of ubbd-kernel
	curl -sL -o /var/cache/ubbd/${tarball_name} ${UBBD_KERNEL_DOWNLOAD_URL}
	cd /var/cache/ubbd
	tar xzvf ${tarball_name} > tar_output
	UBBD_KERNEK_DIR=`cat tar_output|head -n 1`
	cd ${UBBD_KERNEK_DIR}

	# build and install ubbd-kernel
	make mod
	make install

	# post install
	depmod -a
	modprobe ubbd
fi

# install ubbd and ubbd-dev from source
if [ ${INSTALL_UBBD} -eq 1 ]; then
	echo "install from source"
	# install ubbd-kernel
	tarball_name="ubbd.tar.gz"

	# get the archive of ubbd-kernel
	curl -sL -o /var/cache/ubbd/${tarball_name} ${UBBD_DOWNLOAD_URL}
	cd /var/cache/ubbd
	tar xzvf ${tarball_name} > tar_output
	UBBD_DIR=`cat tar_output|head -n 1`
	cd ${UBBD_DIR}

	# install dependency
	./install_dep.sh

	# build and install
	make
	make install

	# post install
	ldconfig
	systemctl daemon-reload
	systemctl restart ubbdd
fi
