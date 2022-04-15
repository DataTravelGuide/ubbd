#!/usr/bin/env python3

import sys

from avocado.core.job import Job
from avocado.core.suite import TestSuite

ubbdadmtest_config = {'resolver.references': ['ubbdadmtest.py:Ubbdadmtest.test'],
          'yaml_to_mux.files': ['ubbdadmtest.py.data/ubbdadmtest.yaml'],
          'nrunner.max_parallel_tasks': 1,
          'run.dry_run.enabled': False}

xfstests_config = {'resolver.references': ['xfstests.py:Xfstests.test'],
          'yaml_to_mux.files': ['xfstests.py.data/xfstests.yaml'],
          'nrunner.max_parallel_tasks': 1,
          'run.dry_run.enabled': False}

with Job(test_suites=[TestSuite.from_config(ubbdadmtest_config, name='ubbdadmtest'),
                      TestSuite.from_config(xfstests_config, name='xfstests')]) as j:
    sys.exit(j.run())
