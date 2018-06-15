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

import base64
import calendar
import logging
import re
import time

from eventlet.green import threading
from neutron._i18n import _
from oslo_serialization import jsonutils as json
import requests

from nuage_neutron.plugins.common import config as nuage_config
from nuage_neutron.plugins.common import constants as plugin_constants


# Suppress urllib3 warnings
try:
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except AttributeError:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

LOG = logging.getLogger(__name__)

REST_SUCCESS_CODES = range(200, 300)
REST_UNAUTHORIZED = 401
REST_NOT_FOUND = 404
REST_CONFLICT = 409
REST_CONFLICT_ERR_CODE = REST_CONFLICT
REST_SERV_UNAVAILABLE_CODE = 503

REST_EXISTS_INTERNAL_ERR_CODE = '2510'
REST_NO_ATTR_CHANGES_TO_MODIFY_ERR_CODE = '2039'
REST_VM_UUID_IN_USE_ERR_CODE = '2748'
REST_VLAN_EXISTS_ERR_CODE = '3316'
REST_VLAN_IN_USE_ERR_CODE = '7053'
REST_IFACE_EXISTS_ERR_CODE = '7006'
REST_ENT_PERMS_EXISTS_ERR_CODE = '4504'
REST_PG_EXISTS_ERR_CODE = '9501'
REST_NW_MACRO_EXISTS_INTERNAL_ERR_CODE = '2504'
REST_DUPLICATE_ACL_PRIORITY = '2640'

# legacy - deprecated
CONFLICT_ERR_CODE = REST_CONFLICT
RES_NOT_FOUND = REST_NOT_FOUND
RES_CONFLICT = REST_CONFLICT
RES_EXISTS_INTERNAL_ERR_CODE = REST_EXISTS_INTERNAL_ERR_CODE
VSD_NO_ATTR_CHANGES_TO_MODIFY_ERR_CODE = \
    REST_NO_ATTR_CHANGES_TO_MODIFY_ERR_CODE

VSD_RESP_OBJ = 3

LIST_L2DOMAINS = re.compile('.*/l2domains(\?.*)?$')
LIST_SUBNETS = re.compile('.*/subnets(\?.*)?$')
GET_L2DOMAIN = re.compile('/l2domains/([0-9a-fA-F\-]+?)(\?.*)?$')
GET_SUBNET = re.compile('/subnets/([0-9a-fA-F\-]+?)(\?.*)?$')

NUAGE_AUTH = None
NUAGE_AUTH_RENEWING = True
NUAGE_AUTH_SEMAPHORE = threading.Semaphore()
THREAD_LOCAL_DATA = threading.local()


class RESTProxyBaseException(Exception):
    message = _("An unknown exception occurred.")

    def __init__(self, **kwargs):
        try:
            super(RESTProxyBaseException, self).__init__(self.message % kwargs)
            self.msg = self.message % kwargs
        except Exception:
            if self.use_fatal_exceptions():
                raise
            else:
                super(RESTProxyBaseException, self).__init__(self.message)

    def __unicode__(self):
        return str(self.msg)

    def use_fatal_exceptions(self):
        return False


class RESTProxyError(RESTProxyBaseException):
    def __init__(self, message, error_code=None, vsd_code=None):
        self.code = 0
        if error_code:
            self.code = error_code
        self.vsd_code = vsd_code

        if self.code == REST_CONFLICT_ERR_CODE:
            self.message = (_('%s') % message)
        else:
            self.message = (_('Error in REST call to VSD: %s') % message)
        super(RESTProxyError, self).__init__()


class ResourceExistsException(RESTProxyError):
    def __init__(self, message):
        super(ResourceExistsException, self).__init__(
            message,
            REST_CONFLICT_ERR_CODE,
            vsd_code=REST_EXISTS_INTERNAL_ERR_CODE)

        super(RESTProxyError, self).__init__()


class ResourceNotFoundException(RESTProxyError):
    def __init__(self, message):
        super(ResourceNotFoundException, self).__init__(
            message,
            REST_NOT_FOUND)


class RESTProxyServer(object):

    def __init__(self, server, base_uri, serverssl, verify_cert, serverauth,
                 auth_resource, organization, servertimeout=30, max_retries=5):
        self.scheme = "https" if serverssl else "http"
        self.server = server
        self.base_uri = base_uri
        if verify_cert.lower() == 'true':
            self.verify_cert = True
        elif verify_cert.lower() == 'false':
            self.verify_cert = False
        else:
            self.verify_cert = verify_cert
        self.serverauth = serverauth
        self.auth_resource = auth_resource
        self.organization = organization
        self.timeout = servertimeout
        self.max_retries = max_retries
        self.api_stats_enabled = nuage_config.is_enabled(
            plugin_constants.DEBUG_API_STATS)
        self.api_count = 0

    @staticmethod
    def raise_rest_error(msg, exc=None, log_as_error=True):
        if log_as_error:
            LOG.error(_('RESTProxy: %s'), msg)
        else:
            LOG.debug(_('RESTProxy: %s'), msg)
        if exc:
            raise exc
        else:
            raise Exception(msg)

    @staticmethod
    def raise_error_response(response):
        try:
            errors = json.loads(response[3])
            log_as_error = False
            if response[0] == REST_SERV_UNAVAILABLE_CODE:
                log_as_error = True
                msg = 'VSD temporarily unavailable, ' + str(errors['errors'])
            else:
                msg = str(
                    errors['errors'][0]['descriptions'][0]['description'])

            if response[0] == REST_NOT_FOUND:
                e = ResourceNotFoundException(msg)
            else:
                vsd_code = str(errors.get('internalErrorCode'))
                e = RESTProxyError(msg, error_code=response[0],
                                   vsd_code=vsd_code)
            RESTProxyServer.raise_rest_error(msg, e, log_as_error)
        except (TypeError, ValueError):
            if response[3]:
                LOG.error('REST response from VSD: %s', response[3])
            msg = ("Cannot communicate with SDN controller. Please do not "
                   "perform any further operations and contact the "
                   "administrator.")
            RESTProxyServer.raise_rest_error(msg)

    @staticmethod
    def _get_session():
        """Get the :class:`requests.Session` object for the current thread.

        Due to SSL connection issues arising when one session is shared between
        multiple threads (problem is in urllib3), we assign a new session to
        each thread. This is done using thread-local data. For more information
        see https://docs.python.org/2/library/threading.html#threading.local.

        :return: :class:`requests.Session`
        """
        global THREAD_LOCAL_DATA
        if not hasattr(THREAD_LOCAL_DATA, 'session'):
            THREAD_LOCAL_DATA.session = requests.Session()
        return THREAD_LOCAL_DATA.session

    def _rest_call(self, action, resource, data, extra_headers=None,
                   ignore_marked_for_deletion=False, auth_renewal=False):
        global NUAGE_AUTH
        if not auth_renewal and self.api_stats_enabled:
            self.api_count += 1
        uri = self.base_uri + resource
        url = "{}://{}{}".format(self.scheme, self.server, uri)
        body = json.dumps(data)
        headers = {
            'Content-type': 'application/json',
            'X-Nuage-Organization': self.organization,
        }
        if NUAGE_AUTH:
            headers['Authorization'] = NUAGE_AUTH
        if extra_headers:
            headers.update(extra_headers)

        if "X-Nuage-Filter" in headers:
            hdr = '[' + headers['X-Nuage-Filter'] + ']'
            LOG.debug('VSD_API REQ %s %s %s %s', action, uri, hdr, body)
        else:
            LOG.debug('VSD_API REQ %s %s %s', action, uri, body)

        ret = None
        for attempt in range(self.max_retries):
            try:
                response = self._create_request(action, url, body, headers)
                resp_data = response.text
                resp_nuage_count = (response.headers.get('X-Nuage-Count')
                                    if response.headers else None)
                if resp_nuage_count is not None:
                    LOG.debug('VSD_API RSP [Count:%s] %s %s %s',
                              resp_nuage_count,
                              response.status_code,
                              response.reason,
                              response.text)
                else:
                    LOG.debug('VSD_API RSP %s %s %s',
                              response.status_code,
                              response.reason,
                              response.text)
                if response.status_code in REST_SUCCESS_CODES:
                    try:
                        resp_data = json.loads(response.text)
                    except ValueError:
                        # response was not JSON, ignore the exception
                        pass
                    if (action.upper() == 'GET' and
                            not ignore_marked_for_deletion):
                        if (LIST_L2DOMAINS.match(resource) is not None or
                                LIST_SUBNETS.match(resource) is not None):
                            resp_data = [
                                d for d in resp_data if not self.is_marked(d)]
                        else:
                            match = GET_L2DOMAIN.match(resource)
                            if match is not None and resp_data and \
                                    self.is_marked(resp_data[0]):
                                return self._l2domain_not_found(match.group(1))
                            match = GET_SUBNET.match(resource)
                            if match is not None and resp_data and \
                                    self.is_marked(resp_data[0]):
                                return self._subnet_not_found(match.group(1))
                ret = (response.status_code, response.reason, response.text,
                       resp_data, response.headers, headers['Authorization'])
            except requests.exceptions.RequestException as e:
                LOG.error(_('ServerProxy: %(action)s failure, %(e)r'),
                          locals())
            else:
                if response.status_code != REST_SERV_UNAVAILABLE_CODE:
                    return ret
            time.sleep(1)
            LOG.debug("Attempt %s of %s", attempt + 1, self.max_retries)
        LOG.debug('After %d retries VSD did not respond properly.',
                  self.max_retries)
        return ret or 0, None, None, None, None, headers['Authorization']

    def _create_request(self, method, url, data, headers):
        """Create a HTTP(S) connection to the server and return the response.

        :param method: The HTTP method used for the request.
        :param url: The URL for the request.
        :param data: Any type of data to be sent along with the request.
        :param headers: Dictionary of HTTP headers.
        :return: :class:`requests.Response`
        """
        kwargs = {
            'data': data,
            'headers': headers,
            'timeout': self.timeout,
            'verify': self.verify_cert,
        }
        return self._get_session().request(method, url, **kwargs)

    def compute_sleep_time(self, api_key_info):
        # Assuming it's always going be in GMT
        response_headers = api_key_info[4] if api_key_info else None
        api_key_data = api_key_info[3][0] if api_key_info else None
        if response_headers and api_key_data:
            current_time_on_vsd = int(calendar.timegm(time.strptime(
                response_headers['date'].rstrip(' GMT'),
                "%a, %d %b %Y %H:%M:%S")))
            # Convert from milli seconds to seconds
            api_expiry_time = api_key_data['APIKeyExpiry'] / 1000
            response = self.get('/systemconfigs', required=True)
            if response[0]:
                renewal_before = response[0]['APIKeyRenewalInterval']
                time_to_sleep = (
                    api_expiry_time - current_time_on_vsd - renewal_before)
                time_to_sleep = time_to_sleep if time_to_sleep > 0 else 1
                return time_to_sleep

        # Sleep for 1 second and compute value for time to sleep.
        return 1

    def generate_nuage_auth(self):
        """Generate the Nuage authentication key.

        The first thread to execute this method acquires `NUAGE_AUTH_SEMAPHORE`
        and is thus able to generate the key. All subsequent threads which
        execute this method while the first thread is busy generating the key,
        will wait in the elif-block until the semaphore has been released by
        the first thread. If the first thread has finished generating the key,
        these threads will acquire the semaphore, release it and thus exit
        the method. However, if the first thread fails to generate the key,
        all other threads will again execute this method.
        """
        global NUAGE_AUTH, NUAGE_AUTH_RENEWING, NUAGE_AUTH_SEMAPHORE
        if NUAGE_AUTH_SEMAPHORE.acquire(blocking=False):
            NUAGE_AUTH_RENEWING = True
            try:
                encoded_auth = base64.b64encode(
                    self.serverauth.encode()).decode()
                # use a temporary auth key instead of the expired auth key
                extra_headers = {'Authorization': 'Basic ' + encoded_auth}
                resp = self._rest_call('GET', self.auth_resource, '',
                                       extra_headers=extra_headers,
                                       auth_renewal=True)

                if not resp or resp[0] == 0:
                    self.raise_rest_error("Could not establish a connection "
                                          "with the VSD. Please check VSD URI "
                                          "path in plugin config and verify "
                                          "IP connectivity.")
                elif resp[0] not in REST_SUCCESS_CODES \
                        or not resp[3][0].get('APIKey'):
                    self.raise_rest_error("Could not authenticate with the "
                                          "VSD. Please check the credentials "
                                          "in the plugin config")
                else:
                    uname = self.serverauth.split(':')[0]
                    new_uname_pass = uname + ':' + resp[3][0]['APIKey']
                    encoded_auth = base64.b64encode(
                        new_uname_pass.encode()).decode()
                    NUAGE_AUTH = 'Basic ' + encoded_auth
                    NUAGE_AUTH_RENEWING = False
                    LOG.debug("[RESTProxy] New auth-token received %s",
                              NUAGE_AUTH)
                    return resp
            finally:
                NUAGE_AUTH_SEMAPHORE.release()
        # some other thread is renewing the auth key
        elif NUAGE_AUTH_RENEWING:
            # make this thread wait until the other thread completes renewal
            NUAGE_AUTH_SEMAPHORE.acquire(blocking=True)
            NUAGE_AUTH_SEMAPHORE.release()
            if NUAGE_AUTH_RENEWING:  # but not successful
                self.generate_nuage_auth()

    def rest_call(self, action, resource, data, extra_headers=None,
                  ignore_marked_for_deletion=False):
        global NUAGE_AUTH
        response = self._rest_call(
            action, resource, data, extra_headers=extra_headers,
            ignore_marked_for_deletion=ignore_marked_for_deletion)

        # If at all authentication expires with VSD, re-authenticate.
        if response[0] == REST_UNAUTHORIZED and response[1] == 'Unauthorized':
            # only renew the auth key if it hasn't been renewed yet
            if response[5] == NUAGE_AUTH:
                self.generate_nuage_auth()
                # When VSD license expires and if user will spin a VM
                # in this state then a proper error should be raised
                # eventually instead of going in to infinite loop.
                response = self._rest_call(
                    action, resource, data, extra_headers=extra_headers,
                    ignore_marked_for_deletion=ignore_marked_for_deletion)
            else:
                response = self.rest_call(
                    action, resource, data, extra_headers=extra_headers,
                    ignore_marked_for_deletion=ignore_marked_for_deletion)
        return response

    def get(self, resource, data='', extra_headers=None, required=False):
        response = self.rest_call('GET', resource, data,
                                  extra_headers=extra_headers)
        if response[0] in REST_SUCCESS_CODES:
            headers = response[4]
            data = response[3]
            page_size = len(data)
            response_size = int(headers.get('X-Nuage-Count', 0))
            if page_size and response_size > page_size:
                # handle pagination
                num_pages = response_size // page_size + 1
                for page in range(1, num_pages):
                    headers = extra_headers or dict()
                    headers['X-Nuage-Page'] = str(page)
                    headers['X-Nuage-PageSize'] = str(page_size)
                    response = self.rest_call('GET', resource, data,
                                              extra_headers=headers)
                    if response[0] in REST_SUCCESS_CODES:
                        data.extend(response[3])
                    else:
                        self.raise_error_response(response)
            return data
        elif response[0] == REST_NOT_FOUND and not required:
            return ''
        else:
            self.raise_error_response(response)

    def _get_ignore_marked_for_deletion(self, resource, data='',
                                        extra_headers=None, required=False):
        response = self.rest_call(
            'GET', resource, data, extra_headers=extra_headers,
            ignore_marked_for_deletion=True)
        if response[0] in REST_SUCCESS_CODES:
            return response[3]
        elif response[0] == REST_NOT_FOUND and not required:
            return ''
        else:
            self.raise_error_response(response)

    @staticmethod
    def retrieve_by_external_id(restproxy, resource, data):
        if not data.get('externalID'):
            return None
        headers = {
            'X-NUAGE-FilterType': "predicate",
            'X-Nuage-Filter': "externalID IS '%s'" % data.get('externalID'),
        }
        return restproxy.get(resource, extra_headers=headers)

    @staticmethod
    def retrieve_by_name(restproxy, resource, data):
        if not data.get('name'):
            return None
        headers = {
            'X-NUAGE-FilterType': "predicate",
            'X-Nuage-Filter': "name IS '%s'" % data.get('name'),
        }
        return restproxy.get(resource, extra_headers=headers)

    @staticmethod
    def acltmpl_retrieve_by_priority(restproxy, resource, data):
        if not data.get('priority'):
            return None
        headers = {
            'X-NUAGE-FilterType': "predicate",
            'X-Nuage-Filter': "priority IS %d and externalID CONTAINS '%s'" % (
                data.get('priority'),
                data.get('externalID').split('@')[1]),
        }
        return restproxy.get(resource, extra_headers=headers)

    def post(self, resource, data, extra_headers=None,
             on_res_exists=retrieve_by_external_id.__func__,
             ignore_err_codes=None):
        """Post request to VSD

        :param resource: eg. vports
        :param data: json data to post
        :param extra_headers: extra headers to add to request, eg.
            {'X-Nuage-ProxyUser' : 'csp@enterprise'}
        :param on_res_exists: Method to execute when VSD returns 409 (CONFLICT)
            default: Retrieve based on external id
            on None: Do nothing
        :param ignore_err_codes: VSD error codes to ignore and eg. execute
                on_res_exists on. eg. 2551
            default: REST_EXISTS_INTERNAL_ERR_CODE
        :return:
            resource: when created or found on_res_exists
            None: When resource not created and on_res_exists=None
        :raises:
            RestProxyError: when internal VSD error code not in
                ignore_err_codes or resource not found after on_res_exists
       """
        if ignore_err_codes is None:
            ignore_err_codes = [REST_EXISTS_INTERNAL_ERR_CODE]
        response = self.rest_call('POST', resource, data,
                                  extra_headers=extra_headers)
        if response[0] in REST_SUCCESS_CODES:
            return response[3]
        elif response[0] == REST_UNAUTHORIZED:
            # probably this is a POST of VM but user is not in CMS group
            self.raise_rest_error(
                'Unauthorized to this VSD API. '
                'Please check the user credentials in plugin config belong '
                'to CMS group in VSD.')
        elif response[0] == REST_CONFLICT_ERR_CODE:
            # Under heavy load, vsd responses may get lost. We must try find
            # the resource else it's stuck in VSD.
            errors = json.loads(response[3])
            if str(errors.get('internalErrorCode')) in ignore_err_codes:
                if on_res_exists:
                    get_response = on_res_exists(self, resource, data)
                    if not get_response:
                        msg = str(errors['errors'][0]['descriptions'][0]
                                  ['description'])
                        self.raise_rest_error(msg,
                                              ResourceExistsException(msg))
                    return get_response
                else:
                    # when on_res_exists is set to None, it means do not
                    # expect object to exist; this anticipates for a real
                    # conflict error returned by VSD
                    return None

        self.raise_error_response(response)

    def put(self, resource, data, extra_headers=None):
        response = self.rest_call('PUT', resource, data,
                                  extra_headers=extra_headers)
        if response[0] in REST_SUCCESS_CODES:
            return
        else:
            errors = json.loads(response[3])
            vsd_code = str(errors.get('internalErrorCode'))
            if vsd_code == REST_NO_ATTR_CHANGES_TO_MODIFY_ERR_CODE:
                return
            self.raise_error_response(response)

    def delete(self, resource, data='', extra_headers=None, required=False):
        response = self.rest_call('DELETE', resource, data,
                                  extra_headers=extra_headers)
        if response[0] in REST_SUCCESS_CODES:
            return response[3]
        elif response[0] == REST_NOT_FOUND and not required:
            return None
        else:
            self.raise_error_response(response)

    def _l2domain_not_found(self, id):
        return self._resource_not_found('l2domain', id)

    def _subnet_not_found(self, id):
        return self._resource_not_found('subnet', id)

    def _resource_not_found(self, resource, id):
        """Replicate VSD 404 response"""
        vsd_response = (
            '{"title": "%(resource)s not found",'
            '"errors": [{"property": "","'
            'descriptions": [{"title": "%(resource)s not found",'
            '"description": "Cannot find %(resource)s with ID %(id)s"}]}],'
            '"description": "Cannot find %(resource)s with ID %(id)s"}'
            % {'resource': resource,
               'id': id})
        return REST_NOT_FOUND, 'Not Found', vsd_response, vsd_response

    @staticmethod
    def is_marked(vsd_object):
        return vsd_object.get('name', '').endswith('_MARKED_FOR_DELETION')
