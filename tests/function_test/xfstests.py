#!/usr/bin/env python


import os
import glob
import re
import shutil

import avocado
from avocado import Test
from avocado.utils import process, build, git, distro, partition
from avocado.utils import disk, data_structures, pmem
from avocado.utils import genio


class Xfstests(Test):
    proc = None

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

    def do_config(self, dev):
        os.chdir(self.ubbd_dir)
        cmd = str("./ubbdadm/ubbdadm --command config --ubbdid %s --data-pages-reserve 0" % (dev))
        result = process.run(cmd, ignore_status=True)
        self.log.info("config result: %s" % (result))
        return (result.exit_status == 0)


    def setUp(self):
        self.xfstests_dir = self.params.get('xfstests_dir')
        self.ubbd_dir = self.params.get('ubbd_dir')
        self.scratch_mnt = self.params.get(
            'scratch_mnt', default='/mnt/scratch')
        self.test_mnt = self.params.get('test_mnt', default='/mnt/test')
        self.fs_to_test = self.params.get('fs', default='ext4')

        if process.system('which mkfs.%s' % self.fs_to_test,
                          ignore_status=True):
            self.cancel('Unknown filesystem %s' % self.fs_to_test)
        mount = True
        self.devices = []
        shutil.copyfile(self.get_data('local.config'),
                        os.path.join(self.xfstests_dir, 'local.config'))

        self.test_dev = self.params.get('disk_test', default=None)
        self.scratch_dev = self.params.get('disk_scratch', default=None)
        self.devices.extend([self.test_dev, self.scratch_dev])
        self.exclude = self.params.get('exclude', default=None)
        self.ubbdd_timeout = self.params.get('ubbdd_timeout', default=0)
        self.test_set = self.params.get('test_set', default="-g auto")

        process.run("dmesg -C ", sudo=True)
        # mkfs for devices
        if self.devices:
            cfg_file = os.path.join(self.xfstests_dir, 'local.config')
            self.mkfs_opt = self.params.get('mkfs_opt', default='')
            self.mount_opt = self.params.get('mount_opt', default='')
            with open(cfg_file, "r") as sources:
                lines = sources.readlines()
            with open(cfg_file, "w") as sources:
                for line in lines:
                    if line.startswith('export TEST_DEV'):
                        sources.write(
                            re.sub(r'export TEST_DEV=.*', 'export TEST_DEV=%s'
                                   % self.devices[0], line))
                    elif line.startswith('export TEST_DIR'):
                        sources.write(
                            re.sub(r'export TEST_DIR=.*', 'export TEST_DIR=%s'
                                   % self.test_mnt, line))
                    elif line.startswith('export SCRATCH_DEV'):
                        sources.write(re.sub(
                            r'export SCRATCH_DEV=.*', 'export SCRATCH_DEV=%s'
                                                      % self.devices[1], line))
                    elif line.startswith('export SCRATCH_MNT'):
                        sources.write(
                            re.sub(
                                r'export SCRATCH_MNT=.*',
                                'export SCRATCH_MNT=%s' %
                                self.scratch_mnt,
                                line))
                        break
            with open(cfg_file, "a") as sources:
                if self.mkfs_opt:
                    sources.write('MKFS_OPTIONS="%s"\n' % self.mkfs_opt)
                if self.mount_opt:
                    sources.write('MOUNT_OPTIONS="%s"\n' % self.mount_opt)

            for ite, dev in enumerate(self.devices):
                self.do_config(dev)
                dev_obj = partition.Partition(dev)
                dev_obj.mkfs(fstype=self.fs_to_test, args=self.mkfs_opt)

        if not os.path.exists(self.scratch_mnt):
            os.makedirs(self.scratch_mnt)
        if not os.path.exists(self.test_mnt):
            os.makedirs(self.test_mnt)

        if self.ubbdd_timeout:
            self.start_ubbdd_killer()

    def test(self):
        failures = False
        os.chdir(self.xfstests_dir)

        args = ''
        if self.exclude:
            args = ' -e \"%s\"' % self.exclude
        cmd = './check %s %s' % (args, self.test_set)
        result = process.run(cmd, ignore_status=True, verbose=True)
        if result.exit_status == 0:
            self.log.info('OK: All Tests passed.')
        else:
            msg = self._parse_error_message(result.stdout)
            self.log.info('ERR: Test(s) failed. Message: %s', msg)
            failures = True

        if failures:
            self.fail('One or more tests failed. Please check the logs.')

    def tearDown(self):
        self.stop_ubbdd_killer()
        # In case if any test has been interrupted
        process.system('umount %s %s' % (self.scratch_mnt, self.test_mnt),
                       sudo=True, ignore_status=True)

        process.system('wipefs -a %s' % (self.test_dev),
                       sudo=True, ignore_status=True)
        if os.path.exists(self.scratch_mnt):
            shutil.rmtree(self.scratch_mnt)
        if os.path.exists(self.test_mnt):
            shutil.rmtree(self.test_mnt)
        self.whiteboard = process.system_output("dmesg").decode()

    @staticmethod
    def _parse_error_message(output):
        na_re = re.compile(r'Passed all 0 tests')
        na_detail_re = re.compile(r'(\d{3})\s*(\[not run\])\s*(.*)')
        failed_re = re.compile(r'Failed \d+ of \d+ tests')

        lines = output.decode("utf-8").split('\n')
        result_line = lines[-3]

        error_msg = None
        if na_re.match(result_line):
            detail_line = lines[-3]
            match = na_detail_re.match(detail_line)
            if match is not None:
                error_msg = match.groups()[2]
            else:
                error_msg = 'Test dependency failed, test will not run.'
        elif failed_re.match(result_line):
            error_msg = 'Test error. %s.' % result_line
        else:
            error_msg = 'Could not verify test result. Please check the logs.'

        return error_msg
