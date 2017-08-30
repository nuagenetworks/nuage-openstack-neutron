# Copyright 2017 Nokia
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import testtools
import time

from nuage_neutron.plugins.common.time_tracker import TimeTracker

TimeTracker.enable_time_tracking()


class CoreCode(object):
    def core_method(self):
        time.sleep(1)

        # nested core method - shd not be counted twice
        self.other_core_method()

    def other_core_method(self):
        # double nested
        self.yet_other_core_method()

    def yet_other_core_method(self):
        time.sleep(1)


class NuageCoreWrapper(CoreCode):
    def __init__(self):
        super(NuageCoreWrapper, self).__init__()

    @TimeTracker.untracked
    def core_method(self):
        super(NuageCoreWrapper, self).core_method()

    @TimeTracker.untracked
    def other_core_method(self):
        super(NuageCoreWrapper, self).other_core_method()

    @TimeTracker.untracked
    def yet_other_core_method(self):
        super(NuageCoreWrapper, self).yet_other_core_method()


class NuageCode(NuageCoreWrapper):
    def __init__(self):
        super(NuageCode, self).__init__()

    @TimeTracker.tracked
    def do_something_cool(self):
        # nuage stuff
        time.sleep(1)  # taking 1 sec

        # core method
        self.core_method()  # taking 2 secs

        # nested nuage method - shd not be counted twice
        self.do_something_else_cool()  # taking 1 sec

    @TimeTracker.tracked
    def do_something_else_cool(self):
        # double nested
        self.yet_do_something_else_cool()

    @TimeTracker.tracked
    def yet_do_something_else_cool(self):
        time.sleep(1)


class TestTimeTracker(testtools.TestCase):

    def test_time_tracker(self):

        NuageCode().do_something_cool()

        self.assertEqual(2, int(TimeTracker.get_time_tracked()),
                         'time tracked')
        self.assertEqual(2, int(TimeTracker.get_time_not_tracked()),
                         'time not tracked')


# don't influence other tests
TimeTracker.enable_time_tracking(False)
