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

import six
import time


class TimeTracker(object):
    time_tracker = None

    def __init__(self):
        self.time_tracked = 0
        self.time_not_tracked = 0
        self.enable_tracking = False
        self.curr_pos_tracking = False
        self.curr_neg_tracking = False

    @staticmethod
    def start():
        TimeTracker.tracking_enabled(True)

    @staticmethod
    def stop():
        TimeTracker.tracking_enabled(False)

    @staticmethod
    def tracking_enabled(enable_tracking=None):
        if enable_tracking is not None:
            TimeTracker.tracker().enable_tracking = enable_tracking
        return TimeTracker.tracker().enable_tracking

    @staticmethod
    def currently_pos_tracking(curr_pos_tracking=None):
        if curr_pos_tracking is not None:
            TimeTracker.tracker().curr_pos_tracking = curr_pos_tracking
        return TimeTracker.tracker().curr_pos_tracking

    @staticmethod
    def currently_neg_tracking(curr_neg_tracking=None):
        if curr_neg_tracking is not None:
            TimeTracker.tracker().curr_neg_tracking = curr_neg_tracking
        return TimeTracker.tracker().curr_neg_tracking

    @staticmethod
    def get_time_tracked():
        return TimeTracker.tracker().time_tracked

    @staticmethod
    def get_time_not_tracked():
        return TimeTracker.tracker().time_not_tracked

    @classmethod
    def tracker(cls):
        if TimeTracker.time_tracker is None:
            TimeTracker.time_tracker = TimeTracker()
        return TimeTracker.time_tracker

    @staticmethod
    def track_time(t, positive=True):
        if positive:
            TimeTracker.tracker().time_tracked += t
        else:
            TimeTracker.tracker().time_tracked -= t
            TimeTracker.tracker().time_not_tracked += t

    @staticmethod
    def track(func, positive=True, *args, **kwargs):
        if not TimeTracker.tracking_enabled():
            return func(*args, **kwargs)
        # else :
        start = None
        negative = not positive
        nested_pos_tracking = positive and TimeTracker.currently_pos_tracking()
        nested_neg_tracking = negative and TimeTracker.currently_neg_tracking()
        if positive and not TimeTracker.currently_pos_tracking():
            TimeTracker.currently_pos_tracking(True)
            start = time.time()
        elif negative and not TimeTracker.currently_neg_tracking():
            TimeTracker.currently_neg_tracking(True)
            start = time.time()
        f = func(*args, **kwargs)
        if positive and not nested_pos_tracking:
            TimeTracker.track_time(time.time() - start, positive)
            TimeTracker.currently_pos_tracking(False)
        elif negative and not nested_neg_tracking:
            TimeTracker.track_time(time.time() - start, positive)
            TimeTracker.currently_neg_tracking(False)
        return f

    @staticmethod
    def tracked(func):
        @six.wraps(func)
        def func_wrapper(*args, **kwargs):
            return TimeTracker.track(func, True, *args, **kwargs)
        return func_wrapper

    @staticmethod
    def untracked(func):
        @six.wraps(func)
        def func_wrapper(*args, **kwargs):
            return TimeTracker.track(func, False, *args, **kwargs)
        return func_wrapper
