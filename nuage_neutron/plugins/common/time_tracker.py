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

from eventlet.semaphore import Semaphore
from greenlet import greenlet
import six
import time


class TimeTracker(object):
    time_tracker = None
    sem = Semaphore()

    def __init__(self):
        self.time_tracked = 0
        self.time_not_tracked = 0
        self.curr_pos_tracking = {}
        self.curr_neg_tracking = {}
        self.tracking_enabled = False

    @staticmethod
    def is_tracking_enabled():
        return TimeTracker.tracker().tracking_enabled

    @staticmethod
    def enable_time_tracking(flag=True):
        TimeTracker.tracker().tracking_enabled = flag

    @staticmethod
    def currently_pos_tracking(thread_id, curr_pos_tracking=None):
        if curr_pos_tracking is not None:
            TimeTracker.tracker().curr_pos_tracking[thread_id] = \
                curr_pos_tracking
        return TimeTracker.tracker().curr_pos_tracking.get(thread_id)

    @staticmethod
    def currently_neg_tracking(thread_id, curr_neg_tracking=None):
        if curr_neg_tracking is not None:
            TimeTracker.tracker().curr_neg_tracking[thread_id] = \
                curr_neg_tracking
        return TimeTracker.tracker().curr_neg_tracking.get(thread_id)

    @staticmethod
    def get_time_tracked():
        return TimeTracker.tracker().time_tracked

    @staticmethod
    def get_time_not_tracked():
        return TimeTracker.tracker().time_not_tracked

    @staticmethod
    def reset():
        TimeTracker.tracker().time_tracked = 0
        TimeTracker.tracker().time_not_tracked = 0

    @classmethod
    def tracker(cls):
        if TimeTracker.time_tracker is None:
            TimeTracker.time_tracker = TimeTracker()
        return TimeTracker.time_tracker

    @staticmethod
    def track_time(t, positive=True):
        with TimeTracker.sem:
            if positive:
                TimeTracker.tracker().time_tracked += t
            else:
                TimeTracker.tracker().time_tracked -= t
                TimeTracker.tracker().time_not_tracked += t

    @staticmethod
    def track(func, positive=True, *args, **kwargs):
        thread_id = id(greenlet.getcurrent())
        start = None
        negative = not positive
        nested_pos_tracking = positive and \
            TimeTracker.currently_pos_tracking(thread_id)
        nested_neg_tracking = negative and \
            TimeTracker.currently_neg_tracking(thread_id)
        if positive and not TimeTracker.currently_pos_tracking(thread_id):
            TimeTracker.currently_pos_tracking(thread_id, True)
            start = time.time()
        elif negative and not TimeTracker.currently_neg_tracking(thread_id):
            TimeTracker.currently_neg_tracking(thread_id, True)
            start = time.time()
        f = func(*args, **kwargs)
        if positive and not nested_pos_tracking:
            TimeTracker.track_time(time.time() - start, positive)
            TimeTracker.currently_pos_tracking(thread_id, False)
        elif negative and not nested_neg_tracking:
            TimeTracker.track_time(time.time() - start, positive)
            TimeTracker.currently_neg_tracking(thread_id, False)
        return f

    @staticmethod
    def tracked(func):
        if TimeTracker.is_tracking_enabled():
            @six.wraps(func)
            def func_wrapper(*args, **kwargs):
                return TimeTracker.track(func, True, *args, **kwargs)
            return func_wrapper
        else:
            return func

    @staticmethod
    def untracked(func):
        if TimeTracker.is_tracking_enabled():
            @six.wraps(func)
            def func_wrapper(*args, **kwargs):
                return TimeTracker.track(func, False, *args, **kwargs)
            return func_wrapper
        else:
            return func
