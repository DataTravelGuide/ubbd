import random
import os
import time

from avocado import Test
from avocado.utils import process, genio

class Ubbdadmtest(Test):

    proc = None
    ubbd_dev_list = []

    def setUp(self):
        self.ubbdd_timeout = self.params.get("ubbdd_timeout")
        self.ubbd_backend_file = self.params.get("ubbd_backend_file")
        self.ubbd_backend_file_size = self.params.get("ubbd_backend_file_size")
        self.ubbdadm_action_num = self.params.get("ubbdadm_action_num")
        self.ubbd_dev_timeout = self.params.get("ubbd_dev_timeout")
        self.ubbd_page_reserve = self.params.get("ubbd_page_reserve")
        self.fio_block_size = self.params.get("block_size")
        self.fio_iops_limit = self.params.get("iops_limit")
        self.fio_direct = self.params.get("fio_direct")
        self.ubbd_dir = self.params.get("UBBD_DIR")

        os.chdir(self.ubbd_dir)
        process.run("dmesg -C ", sudo=True)
        if self.ubbdd_timeout:
            self.start_ubbdd_killer()

    def start_ubbdd_killer(self):
        cmd = str("sh tests/function_test/utils/start_ubbdd_killer.sh %s" % (self.ubbdd_timeout))
        self.proc = process.get_sub_process_klass(cmd)(cmd)
        pid = self.proc.start()
        self.log.info("ubbdd killer started: pid: %s, %s", pid, self.proc)

    def stop_ubbdd_killer(self):
        if not self.proc:
            return

        process.kill_process_tree(self.proc.get_pid())
        self.log.info("ubbdd killer stopped")

    def start_fio(self, ubbd_dev):
        cmd = str("fio --name test --rw randrw --bs %s --ioengine libaio --filename %s --numjobs 16 --iodepth 128 --eta-newline 1 " % (self.fio_block_size, ubbd_dev))
        if (self.fio_iops_limit != 0):
            cmd = str("%s --rate_iops %s" % (cmd, self.fio_iops_limit))
        if (self.fio_direct):
            cmd = str("%s --direct 1" % (cmd))
        else:
            cmd = str("%s --direct 0" % (cmd))

        proc = process.get_sub_process_klass(cmd)(cmd)
        proc.start()
        time.sleep(1)

    def set_dev_timeout(self, ubbd_dev):
        cmd = str("echo %s > /sys/block/%s/queue/io_timeout" % (self.ubbd_dev_timeout, ubbd_dev.replace("/dev/", "")))
        process.run(cmd)

    def get_dev_id(self, ubbd_dev):
        return str(ubbd_dev.replace("/dev/ubbd", "")).strip()

    def do_map(self):
        result = process.run("./ubbdadm/ubbdadm --command map --type file --filepath %s --devsize %s" % (self.ubbd_backend_file, self.ubbd_backend_file_size), ignore_status=True)
        if result.exit_status:
            self.log.error("map error: %s" % (result))
            return False

        self.log.info("map result: %s" % (result))
        ubbd_dev = result.stdout_text.strip()
        self.set_dev_timeout(ubbd_dev)
        self.start_fio(ubbd_dev)
        self.ubbd_dev_list.append(ubbd_dev)
        return True

    def do_unmap(self, dev, force):
        cmd = str("./ubbdadm/ubbdadm --command unmap --ubbdid %s" % self.get_dev_id(dev))
        if force:
            cmd = str("%s --force" % cmd)
        result = process.run(cmd, ignore_status=True)
        self.log.info("unmap result: %s" % (result))
        return (result.exit_status == 0)

    def stop_dev(self, dev):
        while (os.path.exists(dev)):
            self.do_unmap(dev, True)

        self.ubbd_dev_list.remove(dev)

    def stop_devs(self):
        self.log.info(self.ubbd_dev_list)
        while (len(self.ubbd_dev_list) != 0):
            self.stop_dev(self.ubbd_dev_list[0])

    def do_config(self, dev):
        cmd = str("./ubbdadm/ubbdadm --command config --ubbdid %s --data-pages-reserve %s" % (self.get_dev_id(dev), self.ubbd_page_reserve))
        result = process.run(cmd, ignore_status=True)
        self.log.info("config result: %s" % (result))
        return (result.exit_status == 0)

    def do_ubbd_action(self):
        action = random.randint(1, 2)
        if action == 1:
            self.log.info("map")
            self.do_map()
        elif action == 2:
            self.log.info("unmap")
            if (len(self.ubbd_dev_list) > 0):
                self.stop_dev(self.ubbd_dev_list[0])
        elif action == 3:
            self.log.info("config")
            if (len(self.ubbd_dev_list) > 0):
                self.do_config(self.ubbd_dev_list[0])

    def test(self):
        for i in range(0, self.ubbdadm_action_num):
            self.do_ubbd_action()

    def tearDown(self):
        self.stop_devs()
        self.stop_ubbdd_killer()
        self.whiteboard = process.system_output("dmesg").decode()
