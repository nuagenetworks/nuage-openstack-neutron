# Copyright 2016 Alcatel-Lucent USA Inc.
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

from oslo_log import log as logging

from neutron.callbacks import manager

LOG = logging.getLogger(__name__)

CALLBACK_MANAGER = None


def get_callback_manager():
    global CALLBACK_MANAGER
    if CALLBACK_MANAGER is None:
        CALLBACK_MANAGER = NuageCallbacksManager()
    return CALLBACK_MANAGER


class NuageCallbacksManager(manager.CallbacksManager):
    """Custom CallbacksManager which allows exceptions to be raised

    The default CallbacksManager will, when an exception occurs, log the
    exception but not interrupt the general flow. For Nuage we want exceptions
    raised by our service_plugins to be able to halt the neutron flow and bring
    exceptions to the user.
    """
    def _notify_loop(self, resource, event, trigger, **kwargs):
        LOG.debug("Notify callbacks for %(resource)s, %(event)s",
                  {'resource': resource, 'event': event})

        callbacks = self._callbacks[resource].get(event, {}).items()
        for callback_id, callback in callbacks:
            LOG.debug("Calling callback %s", callback_id)
            callback(resource, event, trigger, **kwargs)
