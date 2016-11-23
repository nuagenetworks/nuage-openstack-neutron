# Copyright 2016 NOKIA
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

from neutron._i18n import _
from neutron.db import api as n_db_api
from oslo_db import api as db_api
from oslo_db import exception as db_exc
from pecan import util as p_util
from sqlalchemy.orm import exc


class retry_if_session_inactive(db_api.wrap_db_retry):
    """A wrap_db_retry decorator that can be nested safely

    See also: https://github.com/openstack/neutron/commit/09c87425
    eg. create_floatingip calls create_port internally. If both are decorated
    with @wrap_db_retry, an exception in create_port will cause create_port
    decorator to retry. But the exception that occurred has marked the entire
    session as invalid.
    Because the session is started in the surrounding create_floatingip code,
    the create_port decorator can not work because it will keep on trying to
    reuse an invalidated session.
    """

    def __init__(self, context_var_name='context',
                 retry_interval=1, max_retries=20,
                 inc_retry_interval=True, max_retry_interval=10,
                 retry_on_disconnect=False, retry_on_deadlock=False,
                 retry_on_request=False, exception_checker=lambda exc: False):
        self.context_var_name = context_var_name
        super(retry_if_session_inactive, self).__init__(retry_interval,
                                                        max_retries,
                                                        inc_retry_interval,
                                                        max_retry_interval,
                                                        retry_on_disconnect,
                                                        retry_on_deadlock,
                                                        retry_on_request,
                                                        exception_checker)

    def __call__(self, f):
        f_with_retry = super(retry_if_session_inactive, self).__call__(f)

        @six.wraps(f)
        def wrapper(*args, **kwargs):
            try:
                ctx_arg_index = p_util.getargspec(f).args.index(
                    self.context_var_name)
            except ValueError:
                raise RuntimeError(_("Could not find position of var %s")
                                   % self.context_var_name)

            if self.context_var_name in kwargs:
                context = kwargs[self.context_var_name]
            else:
                context = args[ctx_arg_index]

            method = f if context.session.is_active else f_with_retry
            return method(*args, **kwargs)

        return wrapper


# https://review.openstack.org/#/c/326927 from Newton.
def is_retriable(e):
    if n_db_api._is_nested_instance(e, (db_exc.DBDeadlock,
                                        exc.StaleDataError,
                                        db_exc.DBConnectionError,
                                        db_exc.DBDuplicateEntry,
                                        db_exc.RetryRequest)):
        return True
    # looking savepoints mangled by deadlocks. see bug/1590298 for details.
    return n_db_api._is_nested_instance(e, db_exc.DBError) and '1305' in str(e)


retry_db_errors = retry_if_session_inactive(
    max_retries=n_db_api.MAX_RETRIES,
    retry_on_request=True,
    exception_checker=is_retriable)
