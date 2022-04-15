import random
import os
import time

from avocado import Test
from avocado.utils import process, dmesg

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
        self.ubbd_dir = self.params.get("UBBD_DIR")

        os.chdir(self.ubbd_dir)
        dmesg.clear_dmesg()
        self.start_ubbdd()

    def start_ubbdd(self):
        cmd = str("sh tests/start_ubbdd.sh %s 0" % (self.ubbdd_timeout))
        self.proc = process.get_sub_process_klass(cmd)(cmd)
        pid = self.proc.start()
        time.sleep(5)
        self.log.info("ubbdd started: pid: %s, %s", pid, self.proc)

    def stop_ubbdd(self):
        process.kill_process_tree(self.proc.get_pid())
        self.log.info("ubbdd stopped")

    def start_fio(self, ubbd_dev):
        cmd = str("fio --name test --rw randrw --bs %s --ioengine libaio --filename %s  --direct 1 --numjobs 1 --iodepth 128 --eta-newline 1 " % (self.fio_block_size, ubbd_dev))
        if (self.fio_iops_limit != 0):
            cmd = str("%s --rate_iops %s" % (cmd, self.fio_iops_limit))

        proc = process.get_sub_process_klass(cmd)(cmd)
        proc.start()
        time.sleep(3)

    def do_map(self):
        result = process.run("./ubbdadm/ubbdadm --command map --type file --filepath %s --filesize %s" % (self.ubbd_backend_file, self.ubbd_backend_file_size), ignore_status=True)
        if result.exit_status:
            self.log.error("map error: %s" % (result))
            return False

        self.log.info("map result: %s" % (result))
        ubbd_dev = result.stdout_text.strip()
        self.start_fio(ubbd_dev)
        self.ubbd_dev_list.append(ubbd_dev)
        return True

    def do_unmap(self, dev, force):
        cmd = str("./ubbdadm/ubbdadm --command unmap --ubbdid %s" % (str(dev.replace("/dev/ubbd", "")).strip()))
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

    def do_ubbd_action(self):
        action = random.randint(1, 2)
        if action == 1:
            self.log.info("map")
            self.do_map()
        elif action == 2:
            self.log.info("unmap")
            if (len(self.ubbd_dev_list) > 0):
                self.stop_dev(self.ubbd_dev_list[0])

    def test(self):
        for i in range(0, self.ubbdadm_action_num):
            self.do_ubbd_action()

    def tearDown(self):
        self.stop_devs()
        self.stop_ubbdd()
        dmesg.collect_dmesg()
