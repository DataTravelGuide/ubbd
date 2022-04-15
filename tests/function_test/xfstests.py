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


    def setUp(self):
        self.xfstests_dir = self.params.get('xfstests_dir')
        self.skip_dangerous = self.params.get('skip_dangerous', default=True)
        self.test_range = self.params.get('test_range', default=None)
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
        shutil.copyfile(self.get_data('group'),
                        os.path.join(self.xfstests_dir, 'group'))

        self.test_dev = self.params.get('disk_test', default=None)
        self.scratch_dev = self.params.get('disk_scratch', default=None)
        self.devices.extend([self.test_dev, self.scratch_dev])
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
                dev_obj = partition.Partition(dev)
                dev_obj.mkfs(fstype=self.fs_to_test, args=self.mkfs_opt)

        self.available_tests = self._get_available_tests()

        self.test_list = self._create_test_list(self.test_range)
        self.log.info("Tests available in srcdir: %s",
                      ", ".join(self.available_tests))
        if not self.test_range:
            self.exclude = self.params.get('exclude', default=None)
            self.gen_exclude = self.params.get('gen_exclude', default=None)
            self.share_exclude = self.params.get('share_exclude', default=None)
            if self.exclude or self.gen_exclude or self.share_exclude:
                self.exclude_file = os.path.join(self.xfstests_dir, 'exclude')
                if self.exclude:
                    self._create_test_list(self.exclude, self.fs_to_test,
                                           dangerous=False)
                if self.gen_exclude:
                    self._create_test_list(self.gen_exclude, "generic",
                                           dangerous=False)
                if self.share_exclude:
                    self._create_test_list(self.share_exclude, "shared",
                                           dangerous=False)
        if not os.path.exists(self.scratch_mnt):
            os.makedirs(self.scratch_mnt)
        if not os.path.exists(self.test_mnt):
            os.makedirs(self.test_mnt)

    def test(self):
        failures = False
        os.chdir(self.xfstests_dir)
        if not self.test_list:
            self.log.info('Running all tests')
            args = ''
            if self.exclude or self.gen_exclude:
                args = ' -E %s' % self.exclude_file
            cmd = './check %s -g auto' % args
            result = process.run(cmd, ignore_status=True, verbose=True)
            if result.exit_status == 0:
                self.log.info('OK: All Tests passed.')
            else:
                msg = self._parse_error_message(result.stdout)
                self.log.info('ERR: Test(s) failed. Message: %s', msg)
                failures = True

        else:
            self.log.info('Running only specified tests')
            for test in self.test_list:
                test = '%s/%s' % (self.fs_to_test, test)
                cmd = './check %s' % test
                result = process.run(cmd, ignore_status=True, verbose=True)
                if result.exit_status == 0:
                    self.log.info('OK: Test %s passed.', test)
                else:
                    msg = self._parse_error_message(result.stdout)
                    self.log.info('ERR: %s failed. Message: %s', test, msg)
                    failures = True
        if failures:
            self.fail('One or more tests failed. Please check the logs.')

    def tearDown(self):
        # In case if any test has been interrupted
        process.system('umount %s %s' % (self.scratch_mnt, self.test_mnt),
                       sudo=True, ignore_status=True)
        if os.path.exists(self.scratch_mnt):
            shutil.rmtree(self.scratch_mnt)
        if os.path.exists(self.test_mnt):
            shutil.rmtree(self.test_mnt)

    def _create_test_list(self, test_range, test_type=None, dangerous=True):
        test_list = []
        dangerous_tests = []
        if self.skip_dangerous:
            dangerous_tests = self._get_tests_for_group('dangerous')
        if test_range:
            for test in data_structures.comma_separated_ranges_to_list(test_range):
                test = "%03d" % test
                if dangerous:
                    if test in dangerous_tests:
                        self.log.debug('Test %s is dangerous. Skipping.', test)
                        continue
                if not self._is_test_valid(test):
                    self.log.debug('Test %s invalid. Skipping.', test)
                    continue
                test_list.append(test)

        if test_type:
            with open(self.exclude_file, 'a') as fp:
                for test in test_list:
                    fp.write('%s/%s\n' % (test_type, test))
        return test_list

    def _get_tests_for_group(self, group):
        """
        Returns the list of tests that belong to a certain test group
        """
        group_test_line_re = re.compile(r'(\d{3})\s(.*)')
        group_path = os.path.join(self.xfstests_dir, 'group')
        with open(group_path, 'r') as group_file:
            content = group_file.readlines()

        tests = []
        for g_test in content:
            match = group_test_line_re.match(g_test)
            if match is not None:
                test = match.groups()[0]
                groups = match.groups()[1]
                if group in groups.split():
                    tests.append(test)
        return tests

    def _get_available_tests(self):
        os.chdir(self.xfstests_dir)
        tests_set = []
        tests = glob.glob(self.xfstests_dir + '/tests/*/???.out')
        tests += glob.glob(self.xfstests_dir + '/tests/*/???.out.linux')
        tests = [t.replace('.linux', '') for t in tests]

        tests_set = sorted([t[-7:-4] for t in tests if os.path.exists(t[:-4])])
        tests_set = set(tests_set)

        return tests_set

    def _is_test_valid(self, test_number):
        os.chdir(self.xfstests_dir)
        if test_number == '000':
            return False
        if test_number not in self.available_tests:
            return False
        return True

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
