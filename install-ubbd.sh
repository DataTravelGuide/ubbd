#!/bin/bash
set -xe

[ -z "$UBBD_KERNEL_VERSION" ] && UBBD_KERNEL_VERSION="latest"
[ -z "$UBBD_VERSION" ] && UBBD_VERSION="latest"
[ -z "$INSTALL_UBBD_KERNEL" ] && INSTALL_UBBD_KERNEL=1
[ -z "$INSTALL_UBBD" ] && INSTALL_UBBD=1

UBBD_DOWNLOAD_URL="124.223.60.68"

source /etc/os-release

install_kernel_dev() {
	case "$ID" in
	debian|ubuntu|devuan|elementary|softiron)
		apt install -qy linux-headers-$(uname -r)
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
	tarball_name="ubbd-kernel-${UBBD_KERNEL_VERSION}.tar.gz"

	# get the archive of ubbd-kernel
	curl -sL -o /var/cache/ubbd/${tarball_name} http://${UBBD_DOWNLOAD_URL}/ubbd-kernel/${UBBD_KERNEL_VERSION}/archive/ubbd-kernel.tar.gz
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

# install ubbd and ubbd-dev from packages
need_install_from_source=0

install_ubbd_pkg() {
	pkg_name=$1
	case "$ID" in
	debian|ubuntu|devuan|elementary|softiron)
		echo "deb [trusted=yes] http://${UBBD_DOWNLOAD_URL}/ubbd/${UBBD_VERSION}/debian/${VERSION_CODENAME}/ ./" > /etc/apt/sources.list.d/ubbd.list
		apt update
		apt install -qy ${pkg_name} ${pkg_name}-dev|| need_install_from_source=1
		rm -rf /etc/apt/sources.list.d/ubbd.list
		;;
	rocky|centos|fedora|rhel|ol|virtuozzo)
		echo "[ubbd]
name=UBBD
baseurl=https://${UBBD_DOWNLOAD_URL}/ubbd/${UBBD_VERSION}/rpm/\$releasever/\$basearch/
enabled=1
sslverify=0
gpgcheck=0" > /etc/yum.repos.d/ubbd.repo

		yum makecache
		yum install -y ${pkg_name} ${pkg_name}-devel || need_install_from_source=1
		rm -rf /etc/yum.repos.d/ubbd.repo
		;;
	*)
		echo "$ID is unknown, ${pkg_name} will have to be installed manually."
		exit 1
		;;
	esac
}

if [ ${INSTALL_UBBD} -eq 1 ]; then
	install_ubbd_pkg ubbd
fi

# install ubbd and ubbd-dev from source
if [ ${need_install_from_source} -eq 1 ]; then
	echo "install from source"
	# install ubbd-kernel
	tarball_name="ubbd-${UBBD_VERSION}.tar.gz"

	# get the archive of ubbd-kernel
	curl -sL -o /var/cache/ubbd/${tarball_name} http://${UBBD_DOWNLOAD_URL}/ubbd/${UBBD_VERSION}/archive/ubbd.tar.gz
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
