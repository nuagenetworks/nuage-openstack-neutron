# Copyright 2015 Alcatel-Lucent USA Inc.
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

from neutron_lib.api import validators

from nuage_neutron.plugins.common import exceptions
import six


def validate(name, dict, requirements):
    requirements_it = six.iteritems(requirements)
    for key, requirement in requirements_it:
        if not requirement.matches(dict.get(key)):
            raise exceptions.NuageBadRequest(msg=requirement.msg(key, name))


def require(result, resource, id):
    if result:
        return
    try:
        raise result.exception
    except Exception:
        raise exceptions.NuageBadRequest(msg="Can't find %s '%s'"
                                             % (resource, id))


class IsSet(object):

    def matches(self, value):
        return validators.is_attr_set(value)

    def msg(self, key, name):
        return "%s is required in %s" % (key, name)


class Not(object):

    def __init__(self, invalid):
        super(Not, self).__init__()
        self.invalid = invalid

    def matches(self, value):
        return validators.is_attr_set(value) and value != self.invalid

    def msg(self, key, name):
        return "%s in %s can't be %s or None" % (key, name, self.invalid)


class NotIn(object):

    def __init__(self, invalid):
        super(NotIn, self).__init__()
        self.invalid = invalid

    def matches(self, value):
        return not validators.is_attr_set(value) or value not in self.invalid

    def msg(self, key, name):
        return "%s in %s can't be one of %s" % (key, name, self.invalid)


class Is(object):

    def __init__(self, valid):
        super(Is, self).__init__()
        self.valid = valid

    def matches(self, value):
        return validators.is_attr_set(value) and value == self.valid

    def msg(self, key, name):
        return "%s in %s must be %s" % (key, name, self.valid)


class IsOrNone(object):

    def __init__(self, valid):
        super(IsOrNone, self).__init__()
        self.valid = valid

    def matches(self, value):
        return not validators.is_attr_set(value) or value == self.valid

    def msg(self, key, name):
        return "%s in %s must be %s or None" % (key, name, self.valid)


class IsIn(object):

    def __init__(self, valid):
        super(IsIn, self).__init__()
        self.valid = valid

    def matches(self, value):
        return validators.is_attr_set(value) and value in self.valid

    def msg(self, key, name):
        return "%s in %s must be one of %s" % (key, name, self.valid)
